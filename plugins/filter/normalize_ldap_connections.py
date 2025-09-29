def normalize_ldap_connections(connections):
    """
    Normalize LDAP connections to API format.
    Handles mixed formats for legacy and API configurations.
    """
    normalized_connections = []

    def clean_empty(data):
        """
        Remove attributes with None or empty values from a dictionary.
        """
        return {k: v for k, v in data.items() if v not in (None, "", [], {})}

    for conn in connections:
        # Normalize to API format
        normalized = {}

        # Map legacy format to API format
        if "ldap_name" in conn:
            normalized = {
                "name": conn.get("ldap_name", "Default LDAP Connection"),
                "protocol": conn.get("ldap_protocol", "LDAP"),
                "host": conn.get("ldap_hostname", "localhost"),
                "port": conn.get("ldap_port", 389),
                "searchBase": conn.get("ldap_search_base", "dc=example,dc=com"),
                "authScheme": conn.get("ldap_auth", "NONE").upper(),
                "connectionTimeoutSeconds": 30,
                "connectionRetryDelaySeconds": 300,
                "maxIncidentsCount": 3,
                "useTrustStore": conn.get("ldap_use_trust_store", False),
                "userBaseDn": conn.get("ldap_user_base_dn", ""),
                "userLdapFilter": conn.get("ldap_user_filter", ""),
                "userIdAttribute": conn.get("ldap_user_id_attribute", ""),
                "userRealNameAttribute": conn.get("ldap_user_real_name_attribute", ""),
                "userEmailAddressAttribute": conn.get("ldap_user_email_attribute", ""),
                "userPasswordAttribute": conn.get("ldap_user_password_attribute", ""),
                "authUsername": conn.get("ldap_auth_username", ""),
                "authPassword": conn.get("ldap_auth_password", ""),
                "userObjectClass": conn.get("ldap_user_object_class", ""),
                "ldapGroupsAsRoles": True,
                "groupBaseDn": conn.get("ldap_group_base_dn", ""),
                "groupSubtree": conn.get("ldap_group_subtree", False),
                "userSubtree": conn.get("ldap_user_subtree", False),
            }

            # Determine group type
            if "ldap_group_object_class" in conn:
                normalized.update({
                    "groupType": "STATIC",
                    "groupObjectClass": conn.get("ldap_group_object_class", ""),
                    "groupIdAttribute": conn.get("ldap_group_id_attribute", ""),
                    "groupMemberAttribute": conn.get("ldap_group_member_attribute", ""),
                    "groupMemberFormat": conn.get("ldap_group_member_format", ""),
                })
            elif "userMemberOfAttribute" in conn:
                normalized.update({
                    "groupType": "DYNAMIC",
                    "userMemberOfAttribute": conn.get("userMemberOfAttribute", "memberOf"),
                })

        # API format: Keep as-is but clean empty attributes
        elif all(key in conn for key in ["name", "protocol", "host", "searchBase"]):
            normalized = conn

        # Remove attributes with empty or null values
        normalized_connections.append(clean_empty(normalized))

    return normalized_connections


class FilterModule:
    def filters(self):
        return {
            "normalize_ldap_connections": normalize_ldap_connections
        }
