import copy

from ScoutSuite.core.console import print_exception


########################################
# Functions
########################################

def combine_paths(path1, path2):
    path = path1
    for p in path2:
        if p == '..':
            del (path[-1])
        else:
            path.append(p)
    return path


def get_object_at(object, path, attribute_name=None):
    """
    Get arbitrary object given a dictionary and path (list of keys).

    :param object:
    :param path:
    :param attribute_name:
    :return:
    """
    o = object
    for p in path:
        if type(o) is dict:
            o = o[p]
        else:
            o = getattr(o, p)

    if attribute_name:
        if type(o) is dict:
            return o[attribute_name]
        else:
            return getattr(o, attribute_name)
    else:
        return o


# Tokens with a special meaning inside a get_value_at path.
RELATIVE_ANCHOR = 'this'
PARENT_SEGMENT = '..'
WILDCARD_SEGMENT = 'id'

# Condition tests that inspect the selected resource as a whole (its keys or
# its value) rather than comparing the name of the key that selects it.
OBJECT_TESTS = frozenset((
    'withKey', 'withoutKey',
    'withKeyCaseInsensitive', 'withoutKeyCaseInsensitive',
    'null', 'notNull', 'empty', 'notEmpty',
    'true', 'false', 'notTrue',
))

# Containers whose `id` wildcard selects a resource object even when the
# condition does not carry a test that says so. Used as a fallback when
# get_value_at is called outside of condition evaluation (for instance when
# expanding `_GET_VALUE_AT_` inside a path).
OBJECT_CONTAINERS = frozenset((
    'certificates',   # ACM certificates, tested with withKey
    'instances',      # Cloud SQL instances, tested with withKey
    'containers',     # Kubernetes pod containers (list of objects)
    'iam_role',       # CloudFormation stack role, addressed via `this`
))


def _id_selects_object(container, test_name):
    """
    Decide the meaning of a final `id` segment applied to a dictionary.

    The three `.id` semantics are decidable from the container being walked:

    - over a list, `id` selects the element at the matching position;
    - over a dictionary, `id` selects either a resource object or a key name.

    For the dictionary case the deciding signal is what the condition does with
    the value: tests that inspect an object as a whole (its keys or its value)
    select the resource object, while value comparisons select the key name.
    This keeps `rules.id equal "ingress"` reading the key while
    `certificates.id withKey "NotAfter"` reads the certificate.  When there is
    no condition (e.g. expanding `_GET_VALUE_AT_` inside a path), the resource
    containers that are addressed as objects are recognised by name; every
    other dictionary keeps the historical key-name semantics.
    """
    if test_name is not None:
        return test_name in OBJECT_TESTS
    return container in OBJECT_CONTAINERS


def _resolve_path(current_path, keys):
    """
    Turn the dotted path requested by a condition into a list of
    (segment, is_wildcard, container) tuples that can be walked from the root
    of all_info.

    Paths starting with `this` are relative to current_path: `this` is the
    current object, `..` moves one level up, and every other segment (an `id`
    included) is interpreted from that anchor as a literal attribute name.
    Absolute paths keep their positional alignment with current_path.
    """
    if keys and keys[0] == RELATIVE_ANCHOR:
        resolved = [(segment, False, None)
                    for segment in copy.deepcopy(current_path)]
        for segment in keys[1:]:
            if segment == PARENT_SEGMENT:
                if resolved:
                    resolved.pop()
            else:
                # Inside a `this`-relative path every segment is a literal
                # attribute name, including a segment named `id`.
                resolved.append((segment, False, None))
        return resolved

    if len(keys) == 1:
        # A single bare attribute name is read on the current object.
        resolved = [(segment, False, None) for segment in copy.deepcopy(current_path)]
        resolved.append((keys[0], False, None))
        return resolved

    resolved = []
    for i, key in enumerate(keys):
        if key == WILDCARD_SEGMENT:
            if i < len(current_path):
                segment = current_path[i]
            elif i == len(current_path):
                # The wildcard can land one position past current_path: a
                # single-statement object is evaluated at its container path,
                # whereas the equivalent array carries an extra element index.
                # Keep an empty marker and let the walker stay on the object.
                segment = ''
            else:
                print_exception(f'Unable to get index "{i}" from path "{current_path}": list index out of range',
                                additional_details={'current_path': current_path,
                                                    'key': key,
                                                    'i': i})
                return None
            container = keys[i - 1] if i > 0 else None
            resolved.append((segment, True, container))
        # If empty key and value is an index, keep the index
        elif key == '' and i < len(current_path) and current_path[i].isdigit():
            resolved.append((int(current_path[i]), False, None))
        else:
            resolved.append((key, False, None))
    # Path longer than current_path: keep the remaining literal segments
    if len(keys) > len(current_path):
        for extra_index, key in enumerate(keys[len(resolved):], start=len(resolved)):
            if key == WILDCARD_SEGMENT:
                container = keys[extra_index - 1] if extra_index > 0 else None
                resolved.append((key, True, container))
            else:
                resolved.append((key, False, None))
    return resolved


def _walk_path(all_info, resolved, current_path, original_key, test_name=None):
    """
    Walk a resolved path from all_info, applying the three `id` semantics.
    """
    target_obj = all_info
    for index, (p, is_wildcard, container) in enumerate(resolved):
        is_last = index == len(resolved) - 1
        try:
            if type(target_obj) == list:
                if p == '':
                    # Trailing dot: stay on the current object.
                    pass
                elif is_wildcard:
                    # `id` over a list selects one of the list's elements,
                    # addressed by its positional index.
                    target_obj = target_obj[int(p)]
                elif type(p) == int or (type(p) == str and p.isdigit()):
                    target_obj = target_obj[int(p)]
                else:
                    # Historical behavior: a non-numeric segment on a list
                    # yields the segment itself.
                    target_obj = p
            elif type(target_obj) == dict:
                if p == '':
                    # Trailing dot: stay on the current object.
                    pass
                elif is_wildcard and is_last:
                    # A final `id` segment either selects the resource object
                    # or yields the key name, depending on the container and
                    # on what the condition does with the value.
                    if _id_selects_object(container, test_name):
                        target_obj = target_obj.get(p)
                    else:
                        target_obj = p
                else:
                    candidate = target_obj.get(p)
                    if candidate is None and p not in target_obj and not is_last:
                        # The segment is not a key of this dict but more
                        # segments remain: keep traversing so a later object
                        # can resolve the attribute (historical pass-through).
                        pass
                    else:
                        target_obj = candidate
            elif p == '':
                pass
            elif target_obj is None:
                pass
            else:
                target_obj = getattr(target_obj, p)
        except Exception as e:
            print_exception(f'Unable to get "{p}" from target object "{target_obj}" in path "{original_key}": {e}',
                            additional_details={'current_path': current_path,
                                                'target_obj': target_obj,
                                                'p': p})
            return None
    return target_obj


def get_value_at(all_info, current_path, key, to_string=False, test_name=None):
    """
    Get value located at a given path.

    :param all_info:        All of the services' data
    :param current_path:    The value of the `path` variable defined in the finding file
    :param key:             The key that is being requested
    :param to_string:       Whether or not the returned value should be casted as a string
    :param test_name:       Name of the condition test that will consume the value, if any
    :return:                The value in `all_info` indicated by the `key` in `current_path`
    """
    keys = key.split('.')

    # Bare "this" references the object located at current_path directly.
    if key == RELATIVE_ANCHOR:
        resolved = [(segment, False, None) for segment in copy.deepcopy(current_path)]
    else:
        resolved = _resolve_path(current_path, keys)
        if resolved is None:
            return None
    target_obj = _walk_path(all_info, resolved, current_path, key, test_name)

    if to_string:
        return str(target_obj)
    else:
        return target_obj
