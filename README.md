# Obliance

**Self-hosted, multi-tenant RMM: monitor, patch, automate and remotely manage your Windows, macOS, Linux and FreeBSD fleet.**

Obliance is a remote monitoring and management platform for MSPs and IT teams. A web panel (Node.js server + React client, PostgreSQL) manages lightweight Go agents. It brings inventory, patching, scripting, event-driven automation, compliance, remote access and strict tenant isolation together in one Docker deployment.

Website: [ance.obli.tools](https://ance.obli.tools)

## Key features

- **Multi-tenant by design**: isolated tenants, teams with read-only or read-write access per group or device, and an overview tenant for the whole platform.
- **Cross-platform agents**: Windows (MSI, including builds for older Windows versions), macOS, Linux and FreeBSD. New devices wait for approval; Windows agents update themselves.
- **Inventory and patching**: hardware and software inventory, disk health, Windows Update, winget and Chocolatey scanning, update policies.
- **Scripts**: script library, schedules, run history, encrypted secret parameters.
- **Scenarios**: visual, event-driven automation (machine boot, user login, agent approval, group join, schedule failure, manual), built-in templates, portable JSON import/export.
- **Compliance**: policies with built-in presets (CIS Windows L1, NIST SP 800-171, ISO 27001, PCI DSS v4, HIPAA, SOC 2, Windows/Linux/macOS baselines) and CVE tracking.
- **Remote access**: in-browser screen streaming with [Oblireach](https://github.com/obli-tools/Oblireach), RDP / SSH / CMD / PowerShell tunnels through the agent (no inbound port on the machines), file explorer, process manager, Hyper-V VM console.
- **SSH bastion (optional)**: reach Linux machines with your native `ssh` client or `ssh -J` through the agent tunnel, with IP allow-lists, bans and TOTP step-up.
- **Privacy and isolation**: an end-user privacy mode from the tray icon, and an emergency network isolation mode that keeps only the link to Obliance (with automatic rollback if the server becomes unreachable).
- **Security and operations**: TOTP two-factor authentication, approval workflow for sensitive actions, live alerts, notifications, reports, audit log, 18 UI languages.

## Quick install

```sh
curl -fsSL https://raw.githubusercontent.com/obli-tools/Obliance/main/install.sh | sh
```

The installer runs on Linux, or on macOS with Docker Desktop. It:

- checks Docker and Docker Compose; on Linux it offers to install them with Docker's official script, only after you confirm;
- downloads `docker-compose.yml` and `.env.example` into `./obliance`;
- creates `.env` with unique random secrets (`DB_PASSWORD`, `SESSION_SECRET`, initial admin password);
- pulls the images, starts the stack and prints the panel URL and the initial admin password (shown only once).

Running it again upgrades an existing install; `.env` is never modified.

Options (pass them after `sh -s --`):

| Option | Description |
|--------|-------------|
| `-y`, `--yes` | Non-interactive: accept the defaults and install Docker if it is missing |
| `--dir PATH` | Install directory (default `./obliance`) |
| `--port PORT` | Host port of the web interface (default `3003`, first install only) |
| `--url URL` | Public URL of the panel, e.g. `https://obliance.example.com` (first install only) |

```sh
curl -fsSL https://raw.githubusercontent.com/obli-tools/Obliance/main/install.sh | sh -s -- -y --dir /opt/obliance --url https://obliance.example.com
```

`--help` lists every option.

## Manual install (Docker Compose)

```sh
mkdir obliance && cd obliance
curl -fsSLO https://raw.githubusercontent.com/obli-tools/Obliance/main/docker-compose.yml
curl -fsSLO https://raw.githubusercontent.com/obli-tools/Obliance/main/.env.example
cp .env.example .env
mkdir -p custom/scripts custom/.ssh
# Edit .env: set DB_PASSWORD, SESSION_SECRET (32+ characters), DEFAULT_ADMIN_PASSWORD
# and CLIENT_ORIGIN (the public URL of the panel).
docker compose up -d
```

The panel answers on port `3003` (`LISTEN_PORT`). The stack runs PostgreSQL 16, the server (`meejay/obliance-server`) and the web client (`meejay/obliance-client`). To use an existing PostgreSQL server instead, see `docker-compose.external-db.yml`.

## Update

```sh
docker compose pull && docker compose up -d
```

Or run the installer again from the same directory.

## Installing agents

Agents are installed from the panel: **Add agent** generates the install command for each platform (PowerShell + MSI on Windows, a shell one-liner on Linux, macOS and FreeBSD) with the enrollment key of your choice. New devices appear for approval.

## Requirements

- A Linux host (or macOS with Docker Desktop) with Docker Engine and Docker Compose v2.
- A public URL reachable by the agents.
- HTTPS through a reverse proxy for production use: set `CLIENT_ORIGIN` in `.env` to the public `https://` address and `TRUSTED_PROXY_HOPS=2`, then run `docker compose up -d` again.
- Optional features (SSH bastion, Obligate SSO, phone validation) are documented in `.env.example`. The SSH bastion port must be published directly, not through a TCP proxy.

## Single sign-on

Obliance supports single sign-on with [Obligate](https://github.com/obli-tools/Obligate): register Obliance as an app in Obligate, then enter the Obligate URL and API key in the Obliance settings. Local accounts keep working alongside SSO.

## Part of the Obli suite

| Tool | Purpose |
|------|---------|
| **[Obliance](https://ance.obli.tools)** | Remote monitoring and management (RMM) |
| [Oblireach](https://reach.obli.tools) | Remote screen access and remote support |
| [Obliview](https://view.obli.tools) | Uptime and infrastructure monitoring |
| [Oblimap](https://map.obli.tools) | IPAM and network discovery |
| [Obliguard](https://guard.obli.tools) | Agent-based intrusion prevention |
| [Obligate](https://gate.obli.tools) | Single sign-on and access management for the suite |
| [Oblihub](https://hub.obli.tools) | Docker control panel |
| [Obliwan](https://github.com/obli-tools/Obliwan) | WAN router fleet management |
| [ObliDesk](https://github.com/obli-tools/ObliDesk) | Ticketing and service desk |
| [Obliplan](https://github.com/obli-tools/Obliplan) | Workforce scheduling and working-time tracking |
| [Oblifield](https://field.obli.tools) | Field intervention management |

Suite home: [obli.tools](https://obli.tools)

## License

Obliance is source-available under the [Elastic License 2.0](LICENSE) (ELv2). You may use, modify and self-host it, including for commercial use inside your organization; you may not provide it to others as a hosted or managed service. See [LICENSE](LICENSE) for the full terms, the obli.tools clarifications and third-party notices.
