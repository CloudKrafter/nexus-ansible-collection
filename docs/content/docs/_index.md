---
linkTitle: "Documentation"
title: Introduction
comments: false
---

Hi!

Before you start please take note of the following;

## A note on renaming repositories

When using the `config_api` role, renaming repositories is not supported. This has to do with the fact when you rename a repository, it will be considered a new repo and the old one will be deleted since its not in the list of 'desired repos' anymore.

Unfortunatly repos do not have an unique identifier that's returned by the Nexus API, therefore we can not use that to update the name of a repo.

## FAQ

{{% details title="Q: After enabling the Pro eatures, my playbook fails when configuring User Tokens or Cleanup Policies" closed="true" %}}

After enabling the pro features by uploading or installing the license, you have to reboot your Nexus instance first before the additional API endpoints become available.

{{% /details %}}

{{% details title="Q: BlobStore is in use and cannot be deleted" closed="true" %}}

Make sure you have removed the blobstore from the all blobstore groups first
The order of the `group_vars` is important since the dictionaries will be passed through `as-is` to the Nexus API.

{{% /details %}}

{{% details title="Q: Cleanup Policy format '*' or ALL can't be created" closed="true" %}}

The Nexus cleanup-policy API does not support `format: '*'` or `format: ALL`. This is a known issue at Sonatype.
You can create the same cleanup policy for every format explicitly as a workaround.

{{% /details %}}

## Missing support on Nexus API

Some attributes can't be fetched or updated using the Nexus API.
This result in some features not to work as expected, or may seem broken.

Here's an overview of attributes that are not fully supported on the Nexus API, either to set those attributes, or to update them.

- `httpclient.authentication.password` cant be fetched through API (and therefore can not be updated through this role) However you can set it for new repos
- Create `cleanup policy` for `format 'all'` (and therefore can not be created through this role) https://sonatype.atlassian.net/issues/NEXUS-43742
- `useTrustStoreForIndexAccess` for `docker proxy` (and therefore can not be set through this role)
- `yumsigning` cant be fetched through the API (and therefore not updated through this role) However you can set it for new repos
- `raw.contentdisposition` for `raw groups` cant be fetched through api (and therefore not updated through this role) but it can be set for new repos https://sonatype.atlassian.net/issues/NEXUS-45431
- `aptSigning` cant be fetched through api (and therefore not updated through this role) but it can be set for new repos
- `conanProxy.conanVersion` cant be fetched through API (and therefore not updated through this role) but it can be set for new repos
- `preemptive beartoken` can not be set for `cargo proxy` and `npm proxy` https://ideas.sonatype.com/ideas/IDEAS-I-2449 and https://sonatype.atlassian.net/issues/NEXUS-30725

## Questions or Feedback?

  The CloudKrafter.Nexus collection is in active development.
  Have a question or feedback? Feel free to [open an issue](https://github.com/CloudKrafter/nexus-ansible-collection/issues) or [start a discussion](https://github.com/orgs/CloudKrafter/discussions/new?category=general)

## Next

Now you know the limitations and known issues, it's time to get started:

{{< cards >}}
  {{< card link="getting-started" title="Getting Started" icon="play" subtitle="Install the collection and add the roles to your plays" >}}
  {{< card link="contributing" title="Contributing" icon="light-bulb" subtitle="Share your knowlegde, skills and thoughts with us" >}}
{{< /cards >}}
