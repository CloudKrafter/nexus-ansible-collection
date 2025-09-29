---
title: Roles
weight: 12
---

Only roles within the `default` source will be managed by this role.
Nexus roles that are created initially by Nexus will not be updated or deleted. These roles have a `readOnly: true` attribute.

This role does not support mixed configs since the definition is already in a supported format for the API.

```yaml {filename="group_vars/all.yml"}
nexus_roles:
  - name: role-team1
    id: role-team1
    description: team1
    privileges:
      - docker-private-team1-rw

  - name: role-team2
    id: role-team2
    description: team2
    privileges:
      - docker-private-team2-rw

  - name: role-no-priviliges
    id: role-no-privs
    description: role without privileges assigned
```

{{< callout emoji="💡" >}}
set `nexus_config_dry_run: true` to see what will be changed, without making any changes to your Nexus instance.
{{< /callout >}}

This config can be applied with the {{< badge content="roles" type="warning">}} tag. Just keep in mind the privileges assigned to your roles need to be present!
