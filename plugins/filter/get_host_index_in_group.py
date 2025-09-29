#!/usr/bin/env python

def get_host_index_in_group(host, group):
    """Get the index of a host within its sorted group list"""
    if not group or host not in group:
        return 0
    return sorted(group).index(host)

def get_direct_parent(host, groups):
    """
    Find the smallest group containing the host.
    
    Args:
        host (str): Hostname to find
        groups (dict): Ansible inventory groups dictionary
        
    Returns:
        str: Name of the smallest group containing the host
        
    Raises:
        ValueError: If multiple groups of the same size contain the host
    """
    # Skip special groups
    SPECIAL_GROUPS = {'all', 'ungrouped'}
    
    # Find all groups containing the host
    containing_groups = {
        name: members
        for name, members in groups.items()
        if name not in SPECIAL_GROUPS and host in members
    }
    
    if not containing_groups:
        return ''
    
    # Group by member count
    groups_by_size = {}
    for name, members in containing_groups.items():
        size = len(members)
        if size not in groups_by_size:
            groups_by_size[size] = []
        groups_by_size[size].append(name)
    
    # Get smallest size and its groups
    smallest_size = min(groups_by_size.keys())
    smallest_groups = groups_by_size[smallest_size]
    
    # Error if multiple groups have the same smallest size
    if len(smallest_groups) > 1:
        raise ValueError(
            f"Host {host} belongs to multiple groups of size {smallest_size}: "
            f"{', '.join(smallest_groups)}. Cannot determine primary group."
        )
    
    return smallest_groups[0]

class FilterModule(object):
    def filters(self):
        return {
            'host_index_in_group': get_host_index_in_group,
            'direct_parent': get_direct_parent
        }
