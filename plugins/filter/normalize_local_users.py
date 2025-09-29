def normalize_local_users(users):
    """
    Normalize nexus_local_users to ensure format for API
    Identifies items for normalization while preserving items already in API format
    """
    normalized_users = []

    def clean_empty(data):
        """
        Remove attributes with None or empty values from a dictionary.
        """
        return {k: v for k, v in data.items() if v not in (None, "", [], {})}

    for user in users:
        # Check if already in API format
        if all(key in user for key in ["userId", "firstName", "lastName", "emailAddress"]):
            normalized_users.append(user)
            continue

        # Normalize items to API format
        normalized = {
            "userId": user.get("username", ""),
            "firstName": user.get("first_name", ""),
            "lastName": user.get("last_name", ""),
            "emailAddress": user.get("email", ""),
            "source": "default",
            "status": "active",
            "readOnly": False,
            "roles": user.get("roles", []),
            "externalRoles": [],
        }

        # Remove empty attributes
        normalized_users.append(clean_empty(normalized))

    return normalized_users


class FilterModule:
    def filters(self):
        return {
            "normalize_local_users": normalize_local_users
        }
