---
title: Security Realms
weight: 3
---

Each realm will be activated and configured in the same order as you listed.
Available security realms are `NexusAuthenticatingRealm`, `User-Token-Realm`, `NuGetApiKey`, `ConanToken`, `Crowd`, `DefaultRole`, `DockerToken`, `LdapRealm`, `NpmToken`, `rutauth-realm` and `SamlRealm`.

```yaml {filename="group_vars/all.yml"}
nexus_security_realms:
  - NexusAuthenticatingRealm # default realm
```

```yaml {filename="group_vars/all.yml"}
nexus_security_realms:
  - NexusAuthenticatingRealm # default realm
  - DockerToken
```

If you're using the `nexus_oss` role, you do not have to add the `nexus_security_realms:` variable.
This role will map and transform the realm variables from the `nexus_oss` role for compatibility.
However, if you define the `nexus_security_realms` with any realm other than `NexusAuthenticatingRealm`, the realms variables defined in the `nexus_oss` role will be ignored.

Our recommendation is to configure security realms using this role and not using the `nexus_oss` role.
