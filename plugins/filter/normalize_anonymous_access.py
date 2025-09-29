def normalize_anonymous_access(value):
    """
    Normalize the nexus_anonymous_access configuration to API compatible format
    """
    # If the value is already in API compatible format, return it as-is
    if isinstance(value, dict):
        return value

    # If the value is in nexus_oss role format (boolean), convert it to API format with sensible defaults
    if isinstance(value, bool):
        return {
            "enabled": value,
            "userId": "anonymous",
            "realmName": "NexusAuthorizingRealm"
        }

    # If the value is unrecognized, raise an error
    raise ValueError("Unsupported format for nexus_anonymous_access")


class FilterModule:
    def filters(self):
        return {
            'normalize_anonymous_access': normalize_anonymous_access
        }
