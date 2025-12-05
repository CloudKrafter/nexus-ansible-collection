import copy

UPPERCASE_FIELDS = [
    "storage.writePolicy",
    "yum.deployPolicy",
    "maven.contentDisposition",
    "raw.contentDisposition",
    "maven.layoutPolicy",
    "maven.versionPolicy"
]


def convert_specified_fields_to_uppercase(data, fields_to_uppercase):
    """
    Convert specified keys' values to uppercase in the given dictionary.
    Handles both top-level and nested dotted key paths.
    """
    for key_path in fields_to_uppercase:
        value = get_nested_value(data, key_path)
        if isinstance(value, str):
            set_nested_value(data, key_path, value.upper())


def get_nested_value(data, key_path, default=None):
    """
    Retrieve a nested value from a dictionary using a dotted key path.
    Returns the default value if any key in the path is missing.
    """
    keys = key_path.split('.')
    for key in keys:
        if isinstance(data, dict) and key in data:
            data = data[key]
        else:
            return default
    return data


def set_nested_value(data, key_path, value):
    """
    Set a nested value in a dictionary using a dotted key path.
    Creates intermediate dictionaries as needed.
    """
    keys = key_path.split('.')
    for key in keys[:-1]:
        data = data.setdefault(key, {})
    data[keys[-1]] = value


def merge_dict(source, destination):
    """
    Recursively merge `source` dictionary into `destination`.
    """
    for key, value in source.items():
        if isinstance(value, dict) and key in destination and isinstance(destination[key], dict):
            merge_dict(value, destination[key])
        else:
            destination[key] = value
    return destination


def merge_defaults(repo, global_defaults, type_defaults, format_defaults, repo_type, repo_format, legacy_field_map):
    """
    Merge hierarchical defaults and normalize a repository configuration.
    """
    try:
        # Step 1: Start with global defaults
        normalized = copy.deepcopy(global_defaults)

        # Step 2: Add type-specific defaults
        type_defaults_applied = type_defaults.get(repo_type, {})
        normalized = merge_dict(copy.deepcopy(
            type_defaults_applied), normalized)

        # Step 3: Add format-specific defaults
        format_defaults_applied = format_defaults.get(repo_format, {})
        normalized = merge_dict(copy.deepcopy(
            format_defaults_applied), normalized)

        # **Fix: Gracefully handle authentication=None in defaults**
        if repo_type == "proxy" and "httpClient" in normalized:
            if normalized["httpClient"].get("authentication") is None:
                # Replace None with a dictionary for processing
                normalized["httpClient"]["authentication"] = {}

        # Step 4: Normalize legacy attributes
        for legacy_key, normalized_key in legacy_field_map.items():
            # Handle dynamic mappings for fields like `content_disposition` and `remove_quarantined`
            if legacy_key in ["content_disposition", "remove_quarantined", "passphrase", "keypair"] and isinstance(normalized_key, dict):
                # Check if the format and type exist in the mapping
                if repo_format in normalized_key and repo_type in normalized_key[repo_format]:
                    target_field = normalized_key[repo_format][repo_type]
                else:
                    continue  # Skip if no valid mapping exists for this repo
            else:
                target_field = normalized_key

            value = get_nested_value(repo, legacy_key)
            if value is not None:
                set_nested_value(normalized, target_field, value)

        # Step 5: Add repository-specific attributes
        normalized = merge_dict(repo, normalized)

        # Step 6: Convert specific fields to uppercase
        convert_specified_fields_to_uppercase(normalized, UPPERCASE_FIELDS)

        # Step 6: Set httpClient.authentication.type (only for proxy repositories)
        if repo_type == "proxy":
            auth_block = normalized.get(
                "httpClient", {}).get("authentication", {})
            if auth_block:
                # Use the existing 'type' if defined
                if "type" not in auth_block:
                    username = auth_block.get("username")
                    password = auth_block.get("password")
                    ntlm_host = auth_block.get("ntlmHost")
                    ntlm_domain = auth_block.get("ntlmDomain")

                    if ntlm_host or ntlm_domain:
                        # NTLM authentication requires all related fields
                        if not (username and password and ntlm_host and ntlm_domain):
                            raise ValueError(
                                f"Repository '{repo.get('name', 'unknown')}' is missing required fields "
                                "for NTLM authentication (username, password, ntlmHost, ntlmDomain)."
                            )
                        auth_block["type"] = "ntlm"
                    elif username or password:
                        # Username-based authentication
                        if not (username and password):
                            raise ValueError(
                                f"Repository '{repo.get('name', 'unknown')}' is missing required fields "
                                "for username authentication (username and password)."
                            )
                        auth_block["type"] = "username"

                # Update the normalized structure with the modified auth_block
                normalized["httpClient"]["authentication"] = auth_block

        # Step 7: Revert authentication to None if originally None (only for proxy repositories)
        if repo_type == "proxy":
            original_auth = get_nested_value(
                type_defaults_applied, "httpClient.authentication", None)
            if original_auth is None:
                auth_block = get_nested_value(
                    normalized, "httpClient.authentication", {})
                # If no authentication attributes exist, set to None
                if not any(key in auth_block for key in ["username", "password", "ntlmHost", "ntlmDomain", "type"]):
                    normalized["httpClient"]["authentication"] = None

        return normalized
    except Exception as e:
        raise RuntimeError(f"Error processing repository '{repo.get('name', 'unknown')}': {e}")


def enhanced_cleanup_legacy_attributes(repo, legacy_field_map):
    """
    Explicitly remove legacy attributes from the repository data after normalization.
    """
    cleaned_repo = repo.copy()  # Work on a copy to avoid mutating the input directly
    for legacy_key in legacy_field_map.keys():
        if '.' in legacy_key:
            # Remove nested keys
            parent, child = legacy_key.rsplit('.', 1)
            nested_parent = get_nested_value(cleaned_repo, parent, {})
            if isinstance(nested_parent, dict) and child in nested_parent:
                nested_parent.pop(child, None)
        elif legacy_key in cleaned_repo:
            # Remove top-level keys
            cleaned_repo.pop(legacy_key, None)
    return cleaned_repo


def normalize_and_clean_repositories_with_explicit_cleanup(
    repo_data, global_defaults, type_defaults, format_defaults, repo_type, repo_format, legacy_field_map
):
    """
    Normalize repositories and ensure explicit removal of all legacy attributes.
    """
    normalized_repos = []
    for repo in repo_data:
        # Normalize the repository
        normalized = merge_defaults(
            repo, global_defaults, type_defaults, format_defaults, repo_type, repo_format, legacy_field_map
        )

        # Explicitly clean up all legacy attributes from the normalized repository
        normalized = enhanced_cleanup_legacy_attributes(
            normalized, legacy_field_map)

        # Append the cleaned, normalized repository to the list
        normalized_repos.append(normalized)

    return normalized_repos


class FilterModule:
    def filters(self):
        """
        Ansible filter module definition.
        Registers the 'normalize_repositories' filter for use in playbooks.
        """
        return {
            "normalize_repositories": normalize_and_clean_repositories_with_explicit_cleanup
        }
