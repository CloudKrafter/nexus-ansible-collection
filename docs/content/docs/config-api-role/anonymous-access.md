---
title: Anonymous Access
weight: 4
---

This variable is compatible with the `nexus_anonymous_access` variable used in the `nexus_oss` role. Meaning you don't have to change this value to make it work. However, when enabling anonymous access through the API, Nexus expects an username and realm to be provided as well. By default this will be the **anonymous** user and the **NexusAuthorizingRealm**.
If you want to change this, provide these options as following:

```yaml {filename="group_vars/all.yml"}
nexus_anonymous_access:
  enabled: true
  userId: anonymous
  realmName: NexusAuthorizingRealm
```

Once you have defined `nexus_anonymous_access` with an userId and realmName, the `nexus_oss` role will not configure anonymous access anymore since it expects a boolean and not an object.

Anonymous Docker pulls are handled by the `DockerToken` realm. You need to enable this and then ensure the `forceBasicAuth` attribute is set to `false`. See [Docker repositories](/docs/config-api-role/repositories/#docker)
