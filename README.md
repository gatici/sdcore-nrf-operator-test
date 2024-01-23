# SD-Core NRF Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-nrf-k8s/badge.svg)](https://charmhub.io/sdcore-nrf-k8s)

Charmed Operator for the SD-Core Network Repository Function (NRF) for K8s.

# Usage

```bash
juju deploy sdcore-nrf-k8s --channel=edge
juju deploy mongodb-k8s --trust --channel=6/beta
juju deploy self-signed-certificates --channel=beta

juju integrate sdcore-nrf-k8s:database mongodb-k8s
juju integrate self-signed-certificates:certificates sdcore-nrf-k8s:certificates
```

# Image

- **nrf**: `ghcr.io/canonical/sdcore-nrf:1.3`

