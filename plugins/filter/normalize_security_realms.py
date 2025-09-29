def normalize_security_realms(value, realm_mappings):
    """
    Normalize security realms configuration from nexus_oss variables
    or return as-is for API.
    """
    # If already in API format (list), return as-is
    if isinstance(value, list):
        return value

    # Default realm
    realms = ["NexusAuthenticatingRealm"]

    # Add realms based on nexus_oss variables
    for key, realm_name in realm_mappings.items():
        if value.get(key, False):  # Only add if the variable is True
            realms.append(realm_name)

    return realms


class FilterModule:
    def filters(self):
        return {
            "normalize_security_realms": normalize_security_realms
        }
