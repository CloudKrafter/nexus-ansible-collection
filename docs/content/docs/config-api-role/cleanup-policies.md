---
title: Cleanup Policies
weight: 8
---

{{< callout type="warning" >}}
The cleanup policies API endpoint is a Pro feature!
{{< /callout >}}

```yaml {filename="Role Default"}
nexus_repos_cleanup_policies: []
```

{{< tabs items="config_api,nexus_oss, mixed format" >}}
  {{< tab >}}

  ```yaml {filename="group_vars/all.yml"}
  nexus_repos_cleanup_policies:
  - name: maven_releases
    format: maven2
    notes: "maven RELEASES"
    criteriaLastBlobUpdated: 60
    criteriaLastDownloaded: 120
    criteriaReleaseType: RELEASES
    criteriaAssetRegex: "your-regex*"
  ```
  {{< /tab >}}
  {{< tab >}}
  ```yaml {filename="group_vars/all.yml"}
  nexus_repos_cleanup_policies:
  - name: maven_releases
    format: maven2
    notes: "maven SNAPSHOTS"
    criteria:
      lastBlobUpdated: 60
      lastDownloaded: 120
      preRelease: RELEASES
      regexKey: "your-regex*"
  ```
  {{< /tab >}}
  {{< tab >}}
  ```yaml {filename="group_vars/all.yml"}
  nexus_repos_cleanup_policies:
  # You can use both formats

  # nexus_oss format
  - name: maven_releases
    format: maven2
    notes: "maven SNAPSHOTS"
    criteria:
      lastBlobUpdated: 60
      lastDownloaded: 120
      preRelease: RELEASES
      regexKey: "your-regex*"

  # config_api format
  - name: maven_snapshots
    format: maven2
    notes: "maven SNAPSHOTS"
    criteriaLastBlobUpdated: 60
    criteriaLastDownloaded: 120
    criteriaReleaseType: SNAPSHOTS
    criteriaAssetRegex: "your-regex*"
  ```
  {{< /tab >}}
{{< /tabs >}}

Cleanup policies definitions. Can be added to repo definitions with either the `cleanup_policies` or `cleanup.policyNames` attribute. See [repositories](/docs/config-api-role/repositories/) for examples.
