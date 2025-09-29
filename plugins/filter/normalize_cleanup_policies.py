def normalize_cleanup_policies(policy):
    """
    Normalize mixed-format cleanup policies to be passed to the API
    """
    normalized = {}

    # Copy all top-level keys except 'criteria'
    for key, value in policy.items():
        if key != 'criteria':  # Skip 'criteria' for now
            normalized[key] = value

    # Process 'criteria' if present
    if 'criteria' in policy:
        criteria = policy['criteria']
        for crit_key, crit_value in criteria.items():
            # Map nexus_oss format to config_api format
            if crit_key == "regexKey":
                new_key = "criteriaAssetRegex"
            elif crit_key == "isPrerelease":
                new_key = "criteriaReleaseType"
            else:
                new_key = f"criteria{crit_key[0].upper()}{crit_key[1:]}"
            normalized[new_key] = crit_value

    # Include any existing criteria keys directly
    for key, value in policy.items():
        if key.startswith('criteria') and key not in normalized:
            normalized[key] = value

    # Handle special mappings for old keys in the main body
    if 'regexKey' in policy:
        normalized['criteriaAssetRegex'] = policy['regexKey']
    if 'isPrerelease' in policy:
        normalized['criteriaReleaseType'] = policy['isPrerelease']

    # Remove leftover 'criteria', 'regexKey', and 'isPrerelease' keys
    normalized.pop('criteria', None)
    normalized.pop('regexKey', None)
    normalized.pop('isPrerelease', None)

    return normalized


class FilterModule:
    def filters(self):
        return {
            'normalize_cleanup_policies': normalize_cleanup_policies
        }
