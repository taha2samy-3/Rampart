# Docker Compose quick start

A single-machine installation for trying Rampart: PostgreSQL, an S3-compatible object store (SeaweedFS), Dex as the identity provider, and Rampart itself with the web UI embedded. Everything listens on `127.0.0.1` only.

## Start

```bash
./init.sh
docker compose up -d --build
```

`init.sh` needs Docker (it hashes the demo passwords in a throwaway container). It is safe to run again: it never overwrites `.env` or `dex/config.yaml` (use `--force` to start over). It writes:

- `.env` (mode 0600): a random value for every secret, the first administrator's password, and the two demo users' passwords. Never commit it (it is git-ignored).
- `dex/config.yaml`: Dex's configuration with bcrypt hashes of the demo passwords (git-ignored, rendered from `dex/config.yaml.tpl`).

Then open http://localhost:8080. `init.sh` prints the accounts; they are also in `.env`.

## Signing in

| Who | How | Role |
|---|---|---|
| `ada@example.com` | **Continue with Single sign-on**, then Dex's form | admin (a binding on her e-mail) |
| `grace@example.com` | the same | viewer (the default role) |
| `admin` | the **username and password** form under the SSO button | admin. This is the first administrator, created inside Rampart at first start |

This is the model of a real installation: people sign in through an identity provider, and one local administrator exists so that you can get in before the provider is set up, or when it is down. In a real installation that account switches itself off once single sign-on is configured; the quick start keeps it on (`RAMPART_AUTH_BOOTSTRAP_ADMIN_KEEP_ENABLED`) so you can try both. See [docs/14](../../docs/14-sso-and-identity.md) section 11.

Roles are granted by `RAMPART_AUTH_OIDC_BINDINGS` in `docker-compose.yml`, never read straight from Dex (its password database returns no groups).

## Change the administrator's password

```bash
printf '%s\n' 'a-new-long-password' | docker compose exec -T rampart /app/rampart admin set-password
```

The new password is read from standard input (never from the command line). It clears a lock and ends the account's sessions. Minimum length 12 characters.

## Add or change Dex users

Edit `dex/config.yaml` (`staticPasswords`: `email`, `username`, `userID`, and a bcrypt `hash`, for example from `htpasswd -nbBC 10 "" 'the-password'`), then `docker compose restart dex`. Grant a role in `RAMPART_AUTH_OIDC_BINDINGS` (`user:alice@example.com=triager,group:...=admin`). Dex's storage here is `memory`: restarting it forgets its signing keys and everyone is signed out. Use the `kubernetes` or `postgres` storage in production, or your own identity provider (`RAMPART_AUTH_OIDC_*`).

## How it is wired, and why

- **Roles per service**: the application runs as `rampart_app` (row-level security enforced), migrations as `rampart_owner`, tenant and configuration bootstrap as `rampart_system` ([docs/16](../../docs/16-implementation-decisions.md) D4).
- **One issuer URL for the browser and the server**: the Rampart container shares Dex's network namespace (`network_mode: "service:dex"`), so `http://localhost:5556/dex` reaches Dex from both. That is why the ports of Rampart (8080, 9090) are published on the `dex` service.
- **Secrets** reach Rampart as Docker secrets (`/run/secrets/...`), not environment variables.
- **The first administrator's password** is a Docker secret read at first start; it is never logged.

## Reset everything

```bash
docker compose down -v && ./init.sh --force
```
