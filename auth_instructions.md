# ShipDeck Authentication Integration Guide

ShipDeck is designed to be highly secure yet lightweight. Rather than reinventing authentication, it integrates seamlessly with enterprise-grade Open-Source Authentication systems like **Authelia** or **Keycloak** using **Trusted Header-Based Authentication (Reverse Proxy Auth)**.

In this setup, your reverse proxy (e.g., Nginx, Traefik, Caddy) handles the authentication flow. Once a user successfully authenticates, the proxy forwards the request to ShipDeck, appending HTTP headers containing details of the logged-in user.

---

## 1. How ShipDeck Receives Auth Data

When ShipDeck runs with the environment variable `AUTH_TYPE=header`, it enforces that inbound requests contain the `Remote-User` (or `X-Forwarded-User`) header. 

Here are the headers ShipDeck listens for:
- `Remote-User` (or `X-Forwarded-User`): The unique username (Mandatory under header authentication mode).
- `Remote-Name` (or `x-forwarded-preferred-username`): The user's display name.
- `Remote-Email` (or `X-Forwarded-Email`): The user's email address.
- `Remote-Groups` (or `X-Forwarded-Groups`): A comma-separated list of groups the user belongs to (e.g., `admins, developers`).

---

## 2. Integrating with Authelia & Nginx

Here is a deployment configuration using **Nginx** as your reverse proxy and **Authelia** for single sign-on.

### Step A: Configure Authelia Access Rules
In your Authelia `configuration.yml`, define access controls for the ShipDeck domain (e.g., `shipdeck.example.com`):

```yaml
access_control:
  default_policy: deny
  rules:
    - domain: shipdeck.example.com
      policy: one_factor # or two_factor for high security admins
      subject:
        - ["group:admins"] # Only allow users in the 'admins' group
```

### Step B: Configure Nginx Reverse Proxy
In your Nginx site configuration, set up Nginx to use Authelia's authentication verification endpoint and forward the auth headers to ShipDeck:

```nginx
# Outlines the auth request location
location = /api/verify {
    proxy_pass http://authelia.example.com/api/verify;
    proxy_set_header Host $http_host;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

server {
    listen 443 ssl;
    server_name shipdeck.example.com;

    # SSL Certs here...

    location / {
        # Check authentication against Authelia verify endpoint
        auth_request /api/verify;
        
        # If verify succeeds, Authelia responds with headers.
        # Nginx captures these and forwards them down to ShipDeck.
        auth_request_set $user $upstream_http_remote_user;
        auth_request_set $groups $upstream_http_remote_groups;
        auth_request_set $name $upstream_http_remote_name;
        auth_request_set $email $upstream_http_remote_email;

        proxy_set_header Remote-User $user;
        proxy_set_header Remote-Groups $groups;
        proxy_set_header Remote-Name $name;
        proxy_set_header Remote-Email $email;

        # Standard proxy settings
        proxy_pass http://127.0.0.1:3000; # ShipDeck backend address
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (Crucial for xterm.js real-time streams!)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## 3. Integrating with Keycloak & Traefik

If you are using **Keycloak**, you can use **OAuth2-Proxy** (or Traefik ForwardAuth) to interface between Traefik and Keycloak, which handles OIDC authentication and sends headers down to ShipDeck.

### Traefik ForwardAuth / OAuth2-Proxy Configuration
Configure OAuth2-Proxy to point to your Keycloak client:

```bash
--provider=oidc
--client-id=shipdeck-dashboard
--client-secret=your_keycloak_client_secret
--oidc-issuer-url=https://keycloak.example.com/realms/master
--upstream=http://127.0.0.1:3000
--email-domains=*
--set-xauthrequest=true # Tells oauth2-proxy to pass headers
```

OAuth2-Proxy will forward headers automatically:
- `X-Auth-Request-User` (maps to username)
- `X-Auth-Request-Email` (maps to email)
- `X-Auth-Request-Groups` (maps to roles/groups)

On the **ShipDeck** backend, these are checked by the Express middleware:
```javascript
const user = req.headers['remote-user'] || req.headers['x-forwarded-user'] || req.headers['x-auth-request-user'] || '';
```
*(This header format is already supported by default in ShipDeck's `server.js`!)*

---

## 4. Running ShipDeck

### Option A: Running inside Docker (Recommended)

Run ShipDeck seamlessly inside a lightweight Docker container. By mounting the host's Docker socket, the dashboard can command the host's local containers and compose files directly.

1. **Verify your local settings** in `docker-compose.yml` (e.g., verifying port `3000` mapping, and setting `AUTH_TYPE` variable accordingly).
2. **Start the ShipDeck application container**:
   ```bash
   docker compose up -d
   ```
3. **Persisted configurations**:
   The dashboard automatically reads and writes to `hosts.json` in the current folder, which is mounted live into the container.
4. **Deploying local projects**:
   If running dashboard CLI commands (like `git pull`) inside local directories on your host system:
   - Mount your codebase directories into the container using a compose volume (e.g. `- /var/www:/projects`).
   - Setup the target host in the dashboard with an absolute path referring to the container's path (e.g., `/projects/my-node-app`).

---

### Option B: Running natively with Node.js

You control the security mode using the `AUTH_TYPE` environment variable.

1. **Development/Testing (Bypass Mode):**
   Run without custom headers (ideal for initial local setup validation).
   ```bash
   # Linux/macOS
   PORT=3000 AUTH_TYPE=none npm start
   
   # Windows (PowerShell)
   $env:PORT="3000"; $env:AUTH_TYPE="none"; npm start
   ```

2. **Production Mode (Enforce Auth):**
   Decline queries that do not supply headers confirmed from the safe proxy networks.
   ```bash
   # Linux/macOS
   PORT=3000 AUTH_TYPE=header npm start
   
   # Windows (PowerShell)
   $env:PORT="3000"; $env:AUTH_TYPE="header"; npm start
   ```
