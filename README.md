# Rampart Helm Chart Repository

Official Helm Chart repository for **Rampart** - Cloud-Native Application Security Posture Management (ASPM) Platform.

## Installation

### Standard Helm Repository
```bash
helm repo add rampart https://taha2samy-3.github.io/Rampart
helm repo update
helm install rampart rampart/rampart
```

### OCI Registry
```bash
helm install rampart oci://ghcr.io/taha2samy-3/rampart/charts/rampart --version 0.1.0
```

For documentation and configuration options, see the [Rampart Repository](https://github.com/taha2samy-3/Rampart).
