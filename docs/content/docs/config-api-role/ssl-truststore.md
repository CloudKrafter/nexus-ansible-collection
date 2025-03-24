---
title: SSL Truststore
weight: 5
---

```yaml {filename="group_vars/all.yml"}
nexus_ssl_truststore:
  certificates:
    - name: ssl.example.com
      pem: |
        -----BEGIN CERTIFICATE-----
        Cert data
        -----END CERTIFICATE-----
  hostnames:
    - host: example.com
      port: 443
```
