"""
Single-service rule processing functions
"""

import copy

from ScoutSuite.core.console import print_exception
from ScoutSuite.core.conditions import pass_conditions, fix_path_string


# Keys that identify an object as an IAM policy statement. A policy's Statement
# element may legally be either an array of statements or a single statement
# object; the keys below are the ones shared by every kind of statement.
STATEMENT_KEYS = ('Action', 'NotAction', 'Principal', 'NotPrincipal',
                  'Resource', 'NotResource', 'Condition', 'Sid')

# Name of the path segment that holds a policy's statements.
STATEMENT_SEGMENT = 'Statement'


def _is_single_statement(current_info, container):
    """
    Return True when the object reached at a wildcard (`id`) path is a single
    IAM policy statement rather than a resource container whose keys should be
    iterated over.

    A policy's `Statement` element is either an array of statement objects or a
    single statement object; the latter must be traversed as a one-element
    list. The path segment that reaches the wildcard names the container, which
    is the reliable signal; statement keys are a fallback. `Effect` alone is not
    enough -- it is also an ordinary key of some resource dictionaries.
    """
    if type(current_info) != dict:
        return False
    if container and container.endswith(STATEMENT_SEGMENT):
        return True
    if 'Effect' in current_info:
        return any(key in current_info for key in STATEMENT_KEYS)
    return False


def recurse(all_info, current_info, target_path, current_path, config, add_suffix=False):
    """
    Recursively test conditions for a path.
    In order to do this, needs to evaluate all the `id` possibilities.

    When the value in the path is `id`, this represents either a key for a dict or an index for a list.

    When the is `id`:
    - For a dict return value at key
    - For a list, return the list
    When the value ends in `id.`:
    - For a dict, return a list of keys
    - For a list, return value at the index indicated by id
    `
    :param all_info:        All of the services' data
    :param current_info:    ?
    :param target_path:     The path that is being tested
    :param current_path:
    :param config:          The Rule object that is being tested
    :param add_suffix:      ?
    :return:
    """
    results = []
    if len(target_path) == 0:
        # Dashboard: count the number of processed resources here
        setattr(config, 'checked_items', getattr(config, 'checked_items') + 1)
        # Test for conditions...
        if pass_conditions(all_info, current_path, copy.deepcopy(config.conditions)):
            # id_suffix
            if add_suffix and hasattr(config, 'id_suffix'):
                suffix = fix_path_string(all_info, current_path, config.id_suffix)
                current_path.append(suffix)
            # class_suffix
            if add_suffix and hasattr(config, 'class_suffix'):
                suffix = fix_path_string(all_info, current_path, config.class_suffix)
                current_path.append(suffix)
            results.append('.'.join(current_path))
        # Return the flagged items...
        return results
    target_path = copy.deepcopy(target_path)
    dbg_target_path = copy.deepcopy(target_path)
    current_path = copy.deepcopy(current_path)
    attribute = target_path.pop(0)
    if type(current_info) == dict:
        if attribute in current_info:
            split_path = copy.deepcopy(current_path)
            split_path.append(attribute)
            results = results + recurse(all_info, current_info[attribute], target_path, split_path, config, add_suffix)
        elif attribute == 'id':
            # A single policy statement is legally serialized as an object
            # instead of a one-element array. Treat such an object as a
            # single implicit statement so that both serializations lead to
            # the same boolean result, the same items and the same number
            # of checked items.
            if _is_single_statement(current_info, current_path[-1] if current_path else None):
                # Evaluate the single statement object in place, mirroring
                # the behavior of a one-element array.  The resource path
                # ends at the Statement container, while the equivalent array
                # carries an extra element index; the path resolver maps the
                # statement-level wildcard onto the container itself, so
                # conditions that read attributes below `Statement.id` keep
                # working for both serializations.
                split_path = copy.deepcopy(current_path)
                results = results + recurse(all_info, current_info, copy.deepcopy(target_path),
                                            split_path, config, add_suffix)
            else:
                for key in current_info:
                    split_target_path = copy.deepcopy(target_path)
                    split_current_path = copy.deepcopy(current_path)
                    split_current_path.append(key)
                    split_current_info = current_info[key]
                    results = results + recurse(all_info, split_current_info, split_target_path, split_current_path,
                                                config, add_suffix)
    # To handle lists properly, I would have to make sure the list is properly ordered and I can use the index to
    # consistently access an object... Investigate (or do not use lists)
    elif type(current_info) == list:
        for index, split_current_info in enumerate(current_info):
            split_current_path = copy.deepcopy(current_path)
            split_current_path.append(str(index))
            results = results + recurse(all_info, split_current_info, copy.deepcopy(target_path), split_current_path,
                                        config, add_suffix)
    # Python 2-3 compatible way to check for string type
    elif isinstance(current_info, str):
        split_current_path = copy.deepcopy(current_path)
        results = results + recurse(all_info, current_info, [], split_current_path,
                                    config, add_suffix)
    else:
        print_exception('Unable to recursively test condition for path {}: '
                        'unhandled case for \"{}\" type'.format(current_path,
                                                                type(current_info)),
                        additional_details={'current_path': current_path,
                                            'current_info': current_info,
                                            'dbg_target_path': dbg_target_path})
    return results
