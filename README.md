# k8sss

Issue Kubernetes client certificates via smallstep.

## Installation

See [the latest release](https://github.com/andsens/k8sss/releases/latest) for instructions.

## Deployment

The smallstep deployment is quite rough around the edges and configured for
authenticating via SSH keys. It mounts `/home/admin/.ssh/authorized_keys`
converts each pubkey to a JWK and then adds it to `ca.json`.
