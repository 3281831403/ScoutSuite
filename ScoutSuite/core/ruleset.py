import json
import os
import re
import tempfile

from ScoutSuite.core.console import print_debug, print_error, prompt_yes_no, print_exception
from ScoutSuite.core.ruleset_exceptions import RulesetValidationError

from ScoutSuite.core.rule import Rule
from ScoutSuite.core.rule_definition import RuleDefinition

aws_ip_ranges_filename = 'ip-ranges.json'
ip_ranges_from_args = 'ip-ranges-from-args'

# Rule entries may only set one of these levels
VALID_RULE_LEVELS = ['danger', 'warning']
# Accepted textual representations of boolean values, mapped to actual booleans
BOOLEAN_STRINGS = {'true': True, 'false': False, 'yes': True, 'no': False,
                   '1': True, '0': False, 'on': True, 'off': False}
# Rule names may be written with or without this prefix / the ".json" suffix
RULE_TYPE_PREFIXES = ('findings/', 'filters/')
re_arg_placeholder = re.compile(r'_ARG_(\d+)_')


class Ruleset:
    """
    TODO

    :ivar rules:                        List of rules defined in the ruleset
    :ivar rule_definitions:             Definition of all rules found
    :ivar ??
    """

    def __init__(self,
                 cloud_provider,
                 environment_name='default',
                 filename=None,
                 name=None,
                 rules_dir=None,
                 rule_type='findings',
                 ip_ranges=None,
                 account_id=None,
                 ruleset_generator=False,
                 strict_validation=False):
        rules_dir = [] if rules_dir is None else rules_dir
        ip_ranges = [] if ip_ranges is None else ip_ranges

        self.rules_data_path = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))) + '/providers/%s/rules' % cloud_provider

        self.environment_name = environment_name
        self.rule_type = rule_type
        # When True, malformed rulesets raise RulesetValidationError instead of
        # logging errors and continuing. Always off for the HTML ruleset
        # generator, which intentionally lists rules regardless of validity.
        self.strict_validation = strict_validation and not ruleset_generator
        # Every validation problem encountered while loading, whether or not
        # strict mode turns it into an exception. Callers can inspect this list
        # to detect rules that were normalized or rejected.
        self.validation_errors = []
        # Custom directories holding user-defined rule definition files
        self._custom_rule_dirs = list(rules_dir)
        # Remember whether generator-specific behavior is needed
        self._ruleset_generator_mode = ruleset_generator
        # Ruleset filename
        self.filename = self.find_file(filename)
        if not self.filename:
            self.search_ruleset(environment_name)
        print_debug('Loading ruleset %s' % self.filename)
        self.name = os.path.basename(self.filename).replace('.json', '') if not name else name
        self.load(self.rule_type)
        self.shared_init(ruleset_generator, rules_dir, account_id, ip_ranges)

    def to_string(self):
        return str(vars(self))

    def shared_init(self, ruleset_generator, rule_dirs, account_id, ip_ranges):

        # Load rule definitions
        if not hasattr(self, 'rule_definitions'):
            self.load_rule_definitions(ruleset_generator, rule_dirs)

        # Prepare the rules
        params = {'account_id': account_id}
        if ruleset_generator:
            self.prepare_rules(attributes=['description', 'key', 'rationale'], params=params)
        else:
            self.prepare_rules(ip_ranges=ip_ranges, params=params)

        # Finding keys are only known once definitions have been loaded; reject
        # ruleset entries that would produce the same finding more than once.
        if not ruleset_generator:
            self._check_duplicate_finding_keys()

    def load(self, rule_type, quiet=False):
        """
        Open a JSON file defining a ruleset and load it into a Ruleset object

        :param rule_type:           TODO
        :param quiet:               TODO
        :return:
        """
        if self.filename and os.path.exists(self.filename):
            try:
                with open(self.filename) as f:
                    ruleset = json.load(f)
                self._load_ruleset_dict(ruleset, rule_type)
            except RulesetValidationError:
                raise
            except Exception as e:
                print_exception(f'Ruleset file {self.filename} contains malformed JSON: {e}')
                self.rules = []
                self.about = ''
        else:
            self.rules = []
            if not quiet:
                print_error('Error: the file %s does not exist.' % self.filename)

    def load_rules(self, file, rule_type):
        file.seek(0)
        ruleset = json.load(file)
        self._load_ruleset_dict(ruleset, rule_type)

    def _load_ruleset_dict(self, ruleset, rule_type):
        """
        Validate, normalize and load a ruleset dictionary.

        Rule file names are accepted in three equivalent forms::

            my-rule.json
            my-rule
            findings/my-rule.json   (or filters/...)

        All three are normalized to the canonical ``my-rule.json`` key.
        """
        self.about = ruleset['about'] if 'about' in ruleset else ''
        self.rules = {}
        self.validation_errors = []
        if type(ruleset.get('rules')) != dict:
            self._fail('Ruleset file %s does not contain a "rules" dictionary' % self.filename)
            return
        for raw_filename in ruleset['rules']:
            filename = self._normalize_rule_filename(raw_filename)
            if filename is None:
                self._fail('Invalid rule name %r in ruleset %s' % (raw_filename, self.filename))
                continue
            entries = ruleset['rules'][raw_filename]
            if type(entries) != list or not entries:
                self._fail('Rule %s must be associated with a non-empty list of rule entries' % raw_filename)
                continue
            if filename in self.rules:
                # Same canonical rule referenced through two equivalent name
                # forms (e.g. "name" and "name.json") is a duplicate.
                self._fail('Rule %s is declared more than once in the ruleset' % filename)
                continue
            # Unknown rule names are reported up front rather than failing
            # later, deep in definition loading, with a confusing message.
            if self._resolve_rule_path(filename) is None:
                self._fail('Rule %s does not exist and cannot be loaded' % filename)
                continue
            self.rules[filename] = []
            for rule in entries:
                if type(rule) != dict:
                    self._fail('Rule entry for %s must be a dictionary' % filename)
                    continue
                if not self._validate_rule_entry(filename, rule):
                    # Keep the entry in the ruleset for inspection but disable
                    # it so the processing engine skips a rule that could not be
                    # validated, instead of running it with broken parameters.
                    rule = dict(rule)
                    rule['enabled'] = False
                self.handle_rule_versions(filename, rule_type, rule)

    @staticmethod
    def _normalize_rule_filename(raw_filename):
        """
        Convert any supported rule-name form to the canonical ``name.json`` form.
        """
        if type(raw_filename) != str or not raw_filename:
            return None
        filename = raw_filename
        for prefix in RULE_TYPE_PREFIXES:
            if filename.startswith(prefix):
                filename = filename[len(prefix):]
                break
        if not filename.endswith('.json'):
            filename = '%s.json' % filename
        return filename

    def _resolve_rule_path(self, filename):
        """
        Resolve a canonical rule file name against the custom rule directories
        and the built-in findings/filters directories. Returns the file path
        or None when the rule does not exist.
        """
        # Locally-defined rules take precedence over built-in ones
        for rule_dir in getattr(self, '_custom_rule_dirs', []):
            candidate = os.path.join(rule_dir, filename) if rule_dir else filename
            if os.path.isfile(candidate):
                return candidate
        # Built-in rules, honoring an explicit findings/filters prefix if any
        for rule_type in (self.rule_type,) + tuple(t for t in ('findings', 'filters') if t != self.rule_type):
            candidate = os.path.join(self.rules_data_path, rule_type, filename)
            if os.path.isfile(candidate):
                return candidate
        return None

    def _definition_required_args(self, filename):
        """
        Return the number of _ARG_N_ placeholders referenced by a rule
        definition (highest index + 1), or 0 when the rule takes no argument.
        """
        path = self._resolve_rule_path(filename)
        if not path:
            return None
        with open(path) as f:
            content = f.read()
        indices = [int(index) for index in re_arg_placeholder.findall(content)]
        return (max(indices) + 1) if indices else 0

    def _validate_rule_entry(self, filename, rule, parent_args=None):
        """
        Validate a single rule entry (or a ``versions`` sub-entry).

        Normalizes accepted textual forms in place and returns True when the
        entry is valid, False otherwise (the error is recorded and, in strict
        mode, raised).
        """
        parent_args = [] if parent_args is None else parent_args
        valid = True
        # enabled must be a real boolean. In lenient mode common textual
        # booleans ("true"/"false"/...) are normalized; in strict mode any
        # non-boolean is rejected so that a quoted "false" cannot silently
        # enable a rule.
        if 'enabled' in rule:
            enabled = rule['enabled']
            if type(enabled) == bool:
                pass
            elif not self.strict_validation and type(enabled) == str and enabled.lower() in BOOLEAN_STRINGS:
                rule['enabled'] = BOOLEAN_STRINGS[enabled.lower()]
            else:
                self._fail('Rule %s has an invalid "enabled" value %r: expected a boolean'
                           % (filename, enabled))
                valid = False
        # level, when present, must be a known level
        if 'level' in rule and rule['level'] not in VALID_RULE_LEVELS:
            self._fail('Rule %s has an invalid "level" value %r: expected one of %s'
                       % (filename, rule['level'], ', '.join(VALID_RULE_LEVELS)))
            valid = False
        # args must be a list
        if 'args' in rule and type(rule['args']) != list:
            self._fail('Rule %s has an invalid "args" value %r: expected a list'
                       % (filename, rule['args']))
            valid = False
        # Every _ARG_N_ placeholder must have a corresponding value. Version
        # sub-entries inherit the args declared on their parent entry.
        required_args = self._definition_required_args(filename)
        if required_args:
            args = rule['args'] if 'args' in rule and type(rule['args']) == list else parent_args
            if len(args) < required_args:
                self._fail('Rule %s requires %d argument(s) but only %d were provided'
                           % (filename, required_args, len(args)))
                valid = False
        return valid

    def _fail(self, message):
        """
        Record a validation error and, in strict mode, abort ruleset loading.

        :return: True when loading must stop, False when the entry is skipped
                 but loading can continue.
        """
        print_error('Error: %s' % message)
        self.validation_errors.append(message)
        if self.strict_validation:
            raise RulesetValidationError(message)
        return False

    def handle_rule_versions(self, filename, rule_type, rule):
        """
        For each version of a rule found in the ruleset, append a new Rule object
        """
        if 'versions' in rule:
            versions = rule.pop('versions')
            if type(versions) != dict or not versions:
                self._fail('Rule %s has an invalid "versions" value: expected a non-empty dictionary'
                           % filename)
                return
            for version_key_suffix in versions:
                version = versions[version_key_suffix]
                if type(version) != dict:
                    self._fail('Version %s of rule %s must be a dictionary'
                               % (version_key_suffix, filename))
                    continue
                if not self._validate_rule_entry(filename, version, parent_args=rule.get('args', [])):
                    continue
                version['key_suffix'] = version_key_suffix
                tmp_rule = dict(rule, **version)
                self.rules[filename].append(Rule(self.rules_data_path, filename, rule_type, tmp_rule))
        else:
            self.rules[filename].append(Rule(self.rules_data_path, filename, rule_type, rule))

    def prepare_rules(self, attributes=None, ip_ranges=None, params=None):
        """
        Update the ruleset's rules by duplicating fields as required by the HTML ruleset generator

        :return:
        """
        attributes = [] if attributes is None else attributes
        ip_ranges = [] if ip_ranges is None else ip_ranges
        params = {} if params is None else params
        for filename in self.rule_definitions:
            if filename in self.rules:
                for rule in self.rules[filename]:
                    # Disabled rules that failed argument validation are never
                    # run, so skip definition loading rather than substituting
                    # empty strings for their missing arguments.
                    if not rule.enabled and self._is_missing_arguments(filename, rule):
                        continue
                    rule.set_definition(self.rule_definitions, attributes, ip_ranges, params)
            elif self._ruleset_generator_mode:
                # The ruleset generator lists every built-in rule, including
                # rules absent from the ruleset; represent them as disabled.
                self.rules[filename] = []
                new_rule = Rule(self.rules_data_path, filename, self.rule_type, {'enabled': False, 'level': 'danger'})
                if not self._is_missing_arguments(filename, new_rule):
                    new_rule.set_definition(self.rule_definitions, attributes, ip_ranges, params)
                self.rules[filename].append(new_rule)

    def _is_missing_arguments(self, filename, rule):
        """
        True when the rule definition references _ARG_N_ placeholders for
        which the rule entry provides no value.
        """
        required_args = self._definition_required_args(filename)
        return bool(required_args) and len(rule.args) < required_args

    def _check_duplicate_finding_keys(self):
        """
        Ensure enabled rules produce unique finding keys. Two entries resolving
        to the same key would run twice and overwrite each other's findings.

        In strict mode the collision raises; otherwise the later rule is
        disabled so each finding key is evaluated exactly once.
        """
        seen_keys = {}
        for filename in self.rules:
            for rule in self.rules[filename]:
                if not rule.enabled or not hasattr(rule, 'key'):
                    continue
                if rule.key in seen_keys:
                    message = ('Ruleset produces duplicate finding key "%s" from rules %s and %s'
                               % (rule.key, seen_keys[rule.key][0], filename))
                    if self.strict_validation:
                        self._fail(message)
                    else:
                        print_error('Error: %s; keeping the first occurrence and disabling the duplicate'
                                    % message)
                        self.validation_errors.append(message)
                        rule.enabled = False
                else:
                    seen_keys[rule.key] = (filename, rule)

    def load_rule_definitions(self, ruleset_generator=False, rule_dirs=None):
        """
        Load definition of rules declared in the ruleset

        :param ruleset_generator:
        :param rule_dirs:
        :return:
        """
        rule_dirs = [] if rule_dirs is None else rule_dirs
        self._ruleset_generator_mode = ruleset_generator

        # Load rules from JSON files. Rule names are normalized to their
        # canonical "name.json" form at load time, which is also how built-in
        # definition files are named, so both dictionaries share the same key.
        self.rule_definitions = {}
        for rule_filename in self.rules:
            self.rule_definitions[rule_filename] = RuleDefinition(self.rules_data_path,
                                                                   rule_filename,
                                                                   rule_dirs=rule_dirs)
        # In case of the ruleset generator, list all available built-in rules
        if ruleset_generator:
            rule_dirs.append(self.rules_data_path + '/findings')
            rule_filenames = []
            for rule_dir in rule_dirs:
                rule_filenames += [f for f in os.listdir(rule_dir) if os.path.isfile(os.path.join(rule_dir, f))]
            for rule_filename in rule_filenames:
                if rule_filename not in self.rule_definitions:
                    self.rule_definitions[rule_filename] = RuleDefinition(self.rules_data_path,
                                                                           rule_filename)

    def search_ruleset(self, environment_name, no_prompt=False):
        """

        :param environment_name:
        :param no_prompt:
        :return:
        """
        ruleset_found = False
        if environment_name != 'default':
            ruleset_file_name = 'ruleset-%s.json' % environment_name
            ruleset_file_path = os.path.join(self.rules_data_path, 'rulesets/%s' % ruleset_file_name)
            if os.path.exists(ruleset_file_path):
                if no_prompt or prompt_yes_no(
                        "A ruleset whose name matches your environment name was found in %s. "
                        "Would you like to use it instead of the default one" % ruleset_file_name):
                    ruleset_found = True
                    self.filename = ruleset_file_path
        if not ruleset_found:
            self.filename = os.path.join(self.rules_data_path, 'rulesets/default.json')

    def find_file(self, filename, filetype='rulesets'):
        """

        :param filename:
        :param filetype:
        :return:
        """
        if filename and not os.path.isfile(filename):
            # Not a valid relative / absolute path, check Scout's data under findings/ or filters/
            if not filename.startswith('findings/') and not filename.startswith('filters/'):
                filename = f'{filetype}/{filename}'
            if not os.path.isfile(filename):
                filename = os.path.join(self.rules_data_path, filename)
            if not os.path.isfile(filename) and not filename.endswith('.json'):
                filename = self.find_file('%s.json' % filename, filetype)
        return filename


class TmpRuleset(Ruleset):

    def __init__(self, cloud_provider, rule_dirs=None, rule_filename=None, rule_args=None, rule_level='danger'):
        # Temporary rulesets are assembled programmatically; validation of
        # user-authored files does not apply to them.
        super().__init__(cloud_provider, strict_validation=False)
        rule_dirs = [] if rule_dirs is None else rule_dirs
        rule_args = [] if rule_args is None else rule_args
        self.rule_type = 'findings'
        tmp_ruleset = {'rules': {}, 'about': 'Temporary, single-rule ruleset.'}
        tmp_ruleset['rules'][rule_filename] = []
        rule = {'enabled': True, 'level': rule_level}
        if len(rule_args):
            rule['args'] = rule_args
        tmp_ruleset['rules'][rule_filename].append(rule)
        tmp_ruleset_file = tempfile.TemporaryFile('w+t')
        tmp_ruleset_file.write(json.dumps(tmp_ruleset))

        self.rules_data_path = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))) + '/providers/%s/rules' % cloud_provider

        self.load_rules(file=tmp_ruleset_file, rule_type='findings')

        self.shared_init(False, rule_dirs, '', [])
