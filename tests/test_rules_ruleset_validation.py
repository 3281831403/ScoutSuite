import json
import os
import tempfile
import unittest

from ScoutSuite.core.console import set_logger_configuration
from ScoutSuite.core.rule import Rule, coerce_boolean
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.ruleset_exceptions import RulesetValidationError


class TestScoutRulesetValidation(unittest.TestCase):
    """
    Strict validation and normalization of user-authored rulesets.
    """

    def setUp(self):
        set_logger_configuration(is_debug=True)
        self.test_dir = os.path.dirname(os.path.realpath(__file__))

    def _write_ruleset(self, rules):
        with tempfile.NamedTemporaryFile('wt', suffix='.json', delete=False) as f:
            json.dump({'about': 'validation test', 'rules': rules}, f)
            return f.name

    def _load(self, rules, provider='gcp', strict=True):
        return Ruleset(cloud_provider=provider,
                       filename=self._write_ruleset(rules),
                       strict_validation=strict)

    # --- Rule name normalization -------------------------------------------

    def test_rule_name_three_forms_normalize(self):
        rules = {
            'dns-zones-dnssec-not-enabled.json': [{'enabled': True, 'level': 'danger'}],
            'dns-zones-key-signing-key-using-rsasha1': [{'enabled': True, 'level': 'danger'}],
            'findings/dns-zones-zone-signing-key-using-rsasha1.json': [
                {'enabled': True, 'level': 'danger'}],
        }
        ruleset = self._load(rules)
        self.assertEqual(sorted(ruleset.rules.keys()), [
            'dns-zones-dnssec-not-enabled.json',
            'dns-zones-key-signing-key-using-rsasha1.json',
            'dns-zones-zone-signing-key-using-rsasha1.json'])
        for entries in ruleset.rules.values():
            for rule in entries:
                self.assertTrue(hasattr(rule, 'path'))

    def test_equivalent_names_are_duplicates(self):
        rules = {
            'dns-zones-dnssec-not-enabled.json': [{'enabled': True, 'level': 'danger'}],
            'dns-zones-dnssec-not-enabled': [{'enabled': True, 'level': 'warning'}],
        }
        with self.assertRaises(RulesetValidationError):
            self._load(rules)

    # --- Unknown rules ------------------------------------------------------

    def test_unknown_rule_rejected_strict(self):
        rules = {'no-such-rule-whatsoever.json': [{'enabled': True, 'level': 'danger'}]}
        with self.assertRaises(RulesetValidationError) as ctx:
            self._load(rules)
        self.assertIn('does not exist', str(ctx.exception))

    def test_unknown_rule_skipped_lenient(self):
        rules = {'no-such-rule-whatsoever.json': [{'enabled': True, 'level': 'danger'}]}
        ruleset = self._load(rules, strict=False)
        self.assertNotIn('no-such-rule-whatsoever.json', ruleset.rules)
        self.assertTrue(any('does not exist' in e for e in ruleset.validation_errors))

    # --- Duplicate finding keys --------------------------------------------

    def test_duplicate_finding_key_rejected_strict(self):
        rules = {'dns-zones-dnssec-not-enabled.json': [
            {'enabled': True, 'level': 'warning'},
            {'enabled': True, 'level': 'danger'}]}
        with self.assertRaises(RulesetValidationError) as ctx:
            self._load(rules)
        self.assertIn('duplicate finding key', str(ctx.exception))

    def test_duplicate_finding_key_runs_once_lenient(self):
        rules = {'dns-zones-dnssec-not-enabled.json': [
            {'enabled': True, 'level': 'warning'},
            {'enabled': True, 'level': 'danger'}]}
        ruleset = self._load(rules, strict=False)
        entries = ruleset.rules['dns-zones-dnssec-not-enabled.json']
        self.assertTrue(entries[0].enabled)
        self.assertFalse(entries[1].enabled)
        # The first entry, and its level, is the one kept
        self.assertEqual(entries[0].level, 'warning')

    # --- enabled validation -------------------------------------------------

    def test_string_enabled_rejected_strict(self):
        for bad in ['false', 'true', 0, 1]:
            with self.assertRaises(RulesetValidationError):
                self._load({'dns-zones-dnssec-not-enabled.json': [
                    {'enabled': bad, 'level': 'danger'}]})

    def test_string_enabled_normalized_lenient(self):
        ruleset = self._load({'dns-zones-dnssec-not-enabled.json': [
            {'enabled': 'false', 'level': 'danger'}]}, strict=False)
        self.assertIs(ruleset.rules['dns-zones-dnssec-not-enabled.json'][0].enabled, False)

    def test_coerce_boolean_helper(self):
        self.assertIs(coerce_boolean(True), True)
        self.assertIs(coerce_boolean(False), False)
        self.assertIs(coerce_boolean('false'), False)
        self.assertIs(coerce_boolean('TRUE'), True)
        with self.assertRaises(ValueError):
            coerce_boolean('maybe')

    # --- level / args validation -------------------------------------------

    def test_invalid_level_rejected(self):
        with self.assertRaises(RulesetValidationError) as ctx:
            self._load({'dns-zones-dnssec-not-enabled.json': [
                {'enabled': True, 'level': 'critical'}]})
        self.assertIn('invalid "level"', str(ctx.exception))

    def test_missing_args_rejected_strict(self):
        with self.assertRaises(RulesetValidationError) as ctx:
            self._load(
                {'iam-password-policy-expiration-threshold.json': [
                    {'enabled': True, 'level': 'danger'}]},
                provider='aws')
        self.assertIn('requires 1 argument', str(ctx.exception))

    def test_args_must_be_list(self):
        with self.assertRaises(RulesetValidationError):
            self._load(
                {'iam-password-policy-expiration-threshold.json': [
                    {'enabled': True, 'level': 'danger', 'args': '90'}]},
                provider='aws')

    def test_valid_args_accepted(self):
        ruleset = self._load(
            {'iam-password-policy-expiration-threshold.json': [
                {'enabled': True, 'level': 'danger', 'args': ['90']}]},
            provider='aws')
        self.assertEqual(ruleset.validation_errors, [])
        rule = ruleset.rules['iam-password-policy-expiration-threshold.json'][0]
        self.assertTrue(hasattr(rule, 'path'))

    # --- Shipped GCP CIS 1.1.0 ruleset -------------------------------------

    def test_gcp_cis_110_loads_all_rules(self):
        path = os.path.join(self.test_dir,
                            '../ScoutSuite/providers/gcp/rules/rulesets/cis-1.1.0.json')
        ruleset = Ruleset(cloud_provider='gcp', filename=os.path.abspath(path),
                          strict_validation=True)
        self.assertEqual(ruleset.validation_errors, [])
        self.assertEqual(sum(len(v) for v in ruleset.rules.values()), 46)
        dns = [r.filename for entries in ruleset.rules.values() for r in entries
               if 'dns' in r.filename]
        self.assertEqual(len(dns), 3)

    def test_rule_constructor_never_makes_string_false_truthy(self):
        # The Rule class itself must never coerce "false" to True; the string
        # is interpreted as the boolean False rather than by truthiness.
        rule = Rule('/tmp', 'x.json', 'findings', {'enabled': 'false'})
        self.assertIs(rule.enabled, False)
        rule = Rule('/tmp', 'x.json', 'findings', {'enabled': 'true'})
        self.assertIs(rule.enabled, True)
        with self.assertRaises(ValueError):
            Rule('/tmp', 'x.json', 'findings', {'enabled': 'maybe'})
