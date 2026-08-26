# ShipDeck | Central Docker Deployment Dashboard

ShipDeck is a lightweight, secure web dashboard configured to manage multi-container Docker compose projects across local and remote (SSH) host systems from a single application console.

---

## Key Features

- **Centralized Panel**: Dynamic status monitoring, git pulls, container rebuilds (`docker compose up -d --build`), and logs stream output.
- **WebSocket Streaming terminal**: Powered by `xterm.js` for real-time console outputs.
- **Connection Context Swapping**: Seamless local sub-process execution and remote client channels (`ssh2`).
- **Role-Based Access Control (RBAC)**: Support for `admin` (full management) and `user` (restricted deploy permissions) privileges.
- **Docker-Ready**: Self-contained runner mapping target server’s `/var/run/docker.sock` directly.
- **Reverse Proxy Authentication Support**: Plug-and-play header checks suitable for **Authelia**, **Keycloak**, or **OAuth2-Proxy**.

---

## Project Structure

```
├── server.js               # Node.js/Express & WebSocket Backend
├── index.html              # Responsive dark-mode SPA Dashboard Console
├── package.json            # Base package configuration and dependencies
├── Dockerfile              # Docker Container build instruction
├── docker-compose.yml      # Service mapping and volumes mount setup
├── auth_instructions.md    # Integration guidelines for Authelia & Keycloak
└── hosts.json              # Persistent host configuration storage
```

---

## Quickstart Guide

### Option A: Running inside Docker (Recommended)
By running ShipDeck in Docker and mounting the local Docker socket, the dashboard can command host containers directly.

1. **Verify settings** or customize variables in `docker-compose.yml`.
2. **Start the container**:
   ```bash
   docker compose up -d
   ```
3. Open `http://localhost:3000` in your web browser.

### Option B: Running Natively (Node.js)
Ensure you have **Node.js v18+** installed:

1. **Install dependencies**:
   ```bash
   npm install
   ```
2. **Start the application in Development Mode** (bypass header auth checks):
   - **Linux/macOS**:
     ```bash
     PORT=3000 AUTH_TYPE=none npm start
     ```
   - **Windows (PowerShell)**:
     ```powershell
     $env:PORT="3000"; $env:AUTH_TYPE="none"; npm start
     ```
3. Open `http://localhost:3000` in your web browser.

---

## Role-Based Access Control (RBAC)

ShipDeck classifies traffic into two permission levels:
- **`admin`**: Full control to view, add, configure, or delete any environment host.
- **`user`**: Read/Write execution (redploy, view logs) only on hosts explicitly allowed (where `Required Access Role` is set to "User Role"). Adding/modifying hosts is disabled.

*Note: In local Development Mode (`AUTH_TYPE=none`), a Developer Role Simulator select-box is rendered in the header toolbar to easily swap simulated identities for layout testing.*

---

## Reverse Proxy Authentication Setup
For production deployments, change `AUTH_TYPE=header` and place ShipDeck behind a reverse proxy (e.g. Nginx, Traefik). The proxy should append credentials to inbound requests:
- `Remote-User`: Authenticated username.
- `Remote-Groups`: Comma-separated groups mapping (matching `admins` or `users`).

For comprehensive proxy definitions, see the [Authentication Integration Guide (auth_instructions.md)](./auth_instructions.md).
