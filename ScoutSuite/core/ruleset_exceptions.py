class RulesetValidationError(Exception):
    """
    Raised when a ruleset cannot be loaded because its content is invalid:
    unknown rule names, malformed entries, duplicate finding keys, invalid
    ``enabled`` values or insufficient rule arguments.
    """
    pass
