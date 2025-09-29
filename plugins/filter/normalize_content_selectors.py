def normalize_content_selectors(selectors):
    """
    Normalize nexus_content_selectors to API format.
    Ensures compatibility with both formats, adds missing fields, and removes empty attributes.
    """
    normalized_selectors = []

    def clean_empty(data):
        """
        Remove attributes with None or empty values from a dictionary.
        """
        return {k: v for k, v in data.items() if v not in (None, "", [], {})}

    for selector in selectors:
        # Check if already in API format
        if all(key in selector for key in ["name", "type", "description", "expression"]):
            normalized_selectors.append(selector)
            continue

        # Normalize nexus_oss format to API format
        normalized = {
            "name": selector.get("name", ""),
            "type": "csel",  # Default value for API format
            "description": selector.get("description", ""),
            "expression": selector.get("search_expression", ""),
        }

        # Clean empty attributes
        normalized_selectors.append(clean_empty(normalized))

    return normalized_selectors


class FilterModule:
    def filters(self):
        return {
            "normalize_content_selectors": normalize_content_selectors
        }
