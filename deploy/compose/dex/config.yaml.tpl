# Development identity provider for the Compose quick start. `./init.sh` renders this template into
# dex/config.yaml, with bcrypt hashes of random demo passwords (it is git-ignored).
#
# Two demo users are created by hand here, the way you would in a small installation. Dex is a
# supported identity provider (docs/14); replace it with yours by setting RAMPART_AUTH_OIDC_*.
# Note: Dex's password database returns no `groups`, so Rampart roles are bound by e-mail
# (RAMPART_AUTH_OIDC_BINDINGS in docker-compose.yml), never read straight from the provider.
issuer: http://localhost:5556/dex

# Memory storage loses the signing keys and every session on restart: fine for a laptop, never for
# production (use the kubernetes or postgres storage there).
storage:
  type: memory

web:
  http: 0.0.0.0:5556

oauth2:
  skipApprovalScreen: true

enablePasswordDB: true

staticClients:
  - id: rampart
    name: Rampart
    secretEnv: RAMPART_OIDC_CLIENT_SECRET
    redirectURIs:
      - http://localhost:8080/auth/oidc/default/callback

staticPasswords:
  - email: ada@example.com
    username: ada
    userID: 3c0f2c3e-6a56-4b6a-9b0e-5d0d8f6f6a01
    hash: "@DEMO_ADMIN_HASH@"
  - email: grace@example.com
    username: grace
    userID: 8b1d5a2f-0c2e-4f0e-8a77-2b6c1e9d4b02
    hash: "@DEMO_VIEWER_HASH@"
