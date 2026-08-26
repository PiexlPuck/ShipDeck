const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const { Client } = require('ssh2');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

const PORT = process.env.PORT || 3000;
const HOSTS_FILE = path.join(__dirname, 'hosts.json');

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Load hosts config
function getHosts() {
  try {
    if (!fs.existsSync(HOSTS_FILE)) {
      fs.writeFileSync(HOSTS_FILE, JSON.stringify([], null, 2));
      return [];
    }
    const data = fs.readFileSync(HOSTS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error('Error reading hosts file:', err);
    return [];
  }
}

// Save hosts config
function saveHosts(hosts) {
  try {
    fs.writeFileSync(HOSTS_FILE, JSON.stringify(hosts, null, 2));
  } catch (err) {
    console.error('Error saving hosts file:', err);
  }
}

// Extract User Identity & Role from headers
function extractUserFromHeaders(headers, isHeaderAuthEnforced) {
  // Support standard Authelia/Keycloak headers
  let user = headers['remote-user'] || headers['x-forwarded-user'] || headers['x-auth-request-user'] || '';
  let email = headers['remote-email'] || headers['x-forwarded-email'] || headers['x-auth-request-email'] || '';
  let name = headers['remote-name'] || headers['x-forwarded-preferred-username'] || headers['x-auth-request-name'] || '';
  let groupsStr = headers['remote-groups'] || headers['x-forwarded-groups'] || headers['x-auth-request-groups'] || '';

  // If header auth NOT strictly enforced (development mode/local status),
  // we let the client mock their identity for role testing convenience
  if (!isHeaderAuthEnforced) {
    if (headers['x-dev-user']) user = headers['x-dev-user'];
    if (headers['x-dev-groups']) groupsStr = headers['x-dev-groups'];
    if (headers['x-dev-name']) name = headers['x-dev-name'];
    if (headers['x-dev-email']) email = headers['x-dev-email'];
  }

  const username = user ? String(user).trim() : null;
  const groups = groupsStr ? String(groupsStr).split(',').map(g => g.trim().toLowerCase()) : [];

  // Decide role: if group contains 'admin', 'admins', or 'administrator', role is admin.
  // In dev simulation, we also support passing role in x-dev-role header directly
  let role = 'user';
  const isAdminGroup = groups.some(g => g.includes('admin') || g === 'administrator');
  const isDevAdminRole = !isHeaderAuthEnforced && headers['x-dev-role'] === 'admin';

  if (isAdminGroup || isDevAdminRole) {
    role = 'admin';
  } else if (username) {
    role = 'user'; // default role for authenticated users
  }

  return {
    username,
    email: email ? String(email).trim() : null,
    name: name ? String(name).trim() : (username ? username : null),
    groups,
    role
  };
}

// Authentication & Role Middleware
function authMiddleware(req, res, next) {
  const authType = process.env.AUTH_TYPE || 'none'; // 'header' or 'none'
  const isHeaderAuthEnforced = (authType === 'header');

  req.user = extractUserFromHeaders(req.headers, isHeaderAuthEnforced);

  if (isHeaderAuthEnforced) {
    if (!req.user.username) {
      return res.status(401).json({
        error: 'Unauthorized. Authenticate via secure reverse proxy (Authelia/Keycloak).'
      });
    }
  } else {
    // Local dev mode fallback if user is simulation empty
    if (!req.user.username) {
      req.user.username = 'dev-admin';
      req.user.name = 'Local Administrator (Dev)';
      req.user.role = 'admin';
      req.user.groups = ['admins'];
    }
  }

  next();
}

// Restrict to admins only
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Action forbidden. Only administrators can perform host operations.' });
  }
  next();
}

// Global Auth status API endpoint
app.get('/api/auth-status', authMiddleware, (req, res) => {
  res.json({
    authEnabled: (process.env.AUTH_TYPE === 'header'),
    user: req.user.username ? req.user : null
  });
});

// Manage Hosts API Endpoints
app.get('/api/hosts', authMiddleware, (req, res) => {
  const hosts = getHosts();
  // Admins get everything. Users get only hosts configured as allowedRole === 'user'
  if (req.user.role === 'admin') {
    res.json(hosts);
  } else {
    const userHosts = hosts.filter(h => h.allowedRole === 'user');
    res.json(userHosts);
  }
});

app.post('/api/hosts', authMiddleware, requireAdmin, (req, res) => {
  const { name, type, ip, port, user, sshKeyPath, projectDir, allowedRole } = req.body;

  if (!name || !type || !projectDir) {
    return res.status(400).json({ error: 'Missing name, type, or project directory path.' });
  }

  if (type === 'remote' && (!ip || !user)) {
    return res.status(400).json({ error: 'Remote connection requires IP address and user name.' });
  }

  const hosts = getHosts();
  const newHost = {
    id: Date.now().toString(),
    name,
    type,
    ip: type === 'remote' ? ip : '',
    port: type === 'remote' ? parseInt(port) || 22 : 22,
    user: type === 'remote' ? user : '',
    sshKeyPath: type === 'remote' ? sshKeyPath : '',
    projectDir,
    allowedRole: allowedRole === 'user' ? 'user' : 'admin' // default is admin
  };

  hosts.push(newHost);
  saveHosts(hosts);
  res.status(201).json(newHost);
});

app.put('/api/hosts/:id', authMiddleware, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, type, ip, port, user, sshKeyPath, projectDir, allowedRole } = req.body;

  let hosts = getHosts();
  const index = hosts.findIndex(h => h.id === id);
  if (index === -1) {
    return res.status(404).json({ error: 'Host not found' });
  }

  if (!name || !type || !projectDir) {
    return res.status(400).json({ error: 'Missing name, type, or project directory.' });
  }

  if (type === 'remote' && (!ip || !user)) {
    return res.status(400).json({ error: 'Remote connection requires IP address and user name.' });
  }

  hosts[index] = {
    id,
    name,
    type,
    ip: type === 'remote' ? ip : '',
    port: type === 'remote' ? parseInt(port) || 22 : 22,
    user: type === 'remote' ? user : '',
    sshKeyPath: type === 'remote' ? sshKeyPath : '',
    projectDir,
    allowedRole: allowedRole === 'user' ? 'user' : 'admin'
  };

  saveHosts(hosts);
  res.json(hosts[index]);
});

app.delete('/api/hosts/:id', authMiddleware, requireAdmin, (req, res) => {
  const { id } = req.params;
  let hosts = getHosts();
  const filtered = hosts.filter(h => h.id !== id);

  if (hosts.length === filtered.length) {
    return res.status(404).json({ error: 'Host not found' });
  }

  saveHosts(filtered);
  res.json({ message: 'Host successfully deleted.' });
});

// Ping Host endpoint to verify connection
app.get('/api/hosts/:id/ping', authMiddleware, (req, res) => {
  const { id } = req.params;
  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) {
    return res.status(404).json({ error: 'Host not found' });
  }

  // Security Check: Users can only ping hosts they are allowed to access
  const hostRole = host.allowedRole || 'admin';
  if (hostRole === 'admin' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden. Access restricted to administrator roles.' });
  }

  if (host.type === 'local') {
    if (fs.existsSync(host.projectDir)) {
      return res.json({ status: 'Online', message: 'Local directory exists.' });
    } else {
      return res.json({ status: 'Error', message: 'Local directory path does not exist on dashboard server.' });
    }
  } else {
    // Attempt SSH connection check (short timeout)
    const conn = new Client();
    let connError = null;

    conn.on('ready', () => {
      conn.exec(`test -d "${host.projectDir}" && echo "exists" || echo "missing"`, (err, stream) => {
        if (err) {
          conn.end();
          return res.json({ status: 'Error', message: `SSH Connection OK, command failed: ${err.message}` });
        }
        let output = '';
        stream.on('data', (data) => {
          output += data;
        }).on('close', (code) => {
          conn.end();
          if (output.trim() === 'exists') {
            res.json({ status: 'Online', message: 'SSH Connection OK. Remote project directory exists.' });
          } else {
            res.json({ status: 'Error', message: 'SSH Connection OK. Project directory DOES NOT exist on remote server.' });
          }
        });
      });
    }).on('error', (err) => {
      connError = err.message;
      res.json({ status: 'Offline', message: `SSH Connection failed: ${connError}` });
    }).connect({
      host: host.ip,
      port: host.port,
      username: host.user,
      privateKey: fs.existsSync(host.sshKeyPath)
        ? fs.readFileSync(host.sshKeyPath)
        : host.sshKeyPath,
      readyTimeout: 5000
    });
  }
});

// Upgrade HTTP Server to handle WebSockets
server.on('upgrade', (request, socket, head) => {
  const pathname = new URL(request.url, `http://${request.headers.host}`).pathname;

  if (pathname === '/api/stream') {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});

// WebSocket Connection Logic with permissions check
wss.on('connection', (ws, request) => {
  const urlObj = new URL(request.url, `http://${request.headers.host}`);
  const action = urlObj.searchParams.get('action');
  const hostId = urlObj.searchParams.get('hostId');

  if (!action || !hostId) {
    ws.send('\r\n\x1b[31mError: Missing parameters action or hostId.\x1b[0m\r\n');
    ws.close();
    return;
  }

  // Parse credentials from upgrade headers
  const authType = process.env.AUTH_TYPE || 'none';
  const isHeaderAuthEnforced = (authType === 'header');
  const userContext = extractUserFromHeaders(request.headers, isHeaderAuthEnforced);

  // If in dev mode, also allow parameters in URL query for WebSockets (since browser WS API doesn't support custom headers)
  if (!isHeaderAuthEnforced) {
    const simUserUrl = urlObj.searchParams.get('simUser');
    const simRoleUrl = urlObj.searchParams.get('simRole');
    if (simUserUrl) userContext.username = simUserUrl;
    if (simRoleUrl) userContext.role = simRoleUrl;
  }

  if (isHeaderAuthEnforced && !userContext.username) {
    ws.send('\r\n\x1b[31mError: Connection rejected. Unauthorized WebSocket handshake.\x1b[0m\r\n');
    ws.close();
    return;
  }

  const hosts = getHosts();
  const host = hosts.find(h => h.id === hostId);

  if (!host) {
    ws.send(`\r\n\x1b[31mError: Host configuraton '${hostId}' not found.\x1b[0m\r\n`);
    ws.close();
    return;
  }

  // Enforce Host Access Security checks on standard users
  const hostRole = host.allowedRole || 'admin';
  if (hostRole === 'admin' && userContext.role !== 'admin') {
    ws.send(`\r\n\x1b[31mError: Unauthorized access. Command execution on host '${host.name}' is restricted to administrators.\x1b[0m\r\n`);
    ws.close();
    return;
  }

  // Format terminal logs
  const emitLog = (data) => {
    const formatted = data.toString()
      .replace(/\r?\n/g, '\r\n')
      .replace(/\r\r\n/g, '\r\n');
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(formatted);
    }
  };

  // Determine commands to execute based on host action
  let commandStr = '';
  if (action === 'pull') {
    commandStr = 'git pull';
  } else if (action === 'redeploy') {
    commandStr = 'docker compose up -d --build';
  } else if (action === 'logs') {
    commandStr = 'docker compose logs --tail=100 -f';
  } else {
    ws.send(`\r\n\x1b[31mError: Invalid action '${action}' requested.\x1b[0m\r\n`);
    ws.close();
    return;
  }

  emitLog(`\x1b[34m=== Connection Target: ${host.name} (${host.type}) ===\x1b[0m\r\n`);
  emitLog(`\x1b[34m=== User: ${userContext.username} (${userContext.role}) ===\x1b[0m\r\n`);
  emitLog(`\x1b[34m=== Directory: ${host.projectDir} ===\x1b[0m\r\n`);
  emitLog(`\x1b[34m=== Executing command: ${commandStr} ===\x1b[0m\r\n\r\n`);

  if (host.type === 'local') {
    const options = {
      cwd: host.projectDir,
      shell: true
    };

    let p = spawn(commandStr, [], options);

    p.stdout.on('data', (data) => emitLog(data));
    p.stderr.on('data', (data) => emitLog(data));

    p.on('error', (err) => {
      emitLog(`\r\n\x1b[31mProcess error: ${err.message}\x1b[0m\r\n`);
    });

    p.on('close', (code) => {
      emitLog(`\r\n\x1b[32m=== Command completed with exit code ${code} ===\x1b[0m\r\n`);
      ws.close();
    });

    ws.on('close', () => {
      if (p && !p.killed) {
        p.kill();
      }
    });

  } else {
    const conn = new Client();

    ws.on('close', () => {
      conn.end();
    });

    conn.on('ready', () => {
      emitLog(`\x1b[32mSSH Connection established. Spawning session...\x1b[0m\r\n`);
      const fullRemoteCommand = `cd "${host.projectDir}" && ${commandStr}`;

      conn.exec(fullRemoteCommand, (err, stream) => {
        if (err) {
          emitLog(`\r\n\x1b[31mSSH execution error: ${err.message}\x1b[0m\r\n`);
          conn.end();
          ws.close();
          return;
        }

        stream.on('data', (data) => emitLog(data));
        stream.stderr.on('data', (data) => emitLog(data));

        stream.on('close', (code, signal) => {
          emitLog(`\r\n\x1b[32m=== Command completed. Code: ${code}, Signal: ${signal || 'none'} ===\x1b[0m\r\n`);
          conn.end();
          ws.close();
        });
      });
    });

    conn.on('error', (err) => {
      emitLog(`\r\n\x1b[31mSSH connection lost or failed: ${err.message}\x1b[0m\r\n`);
      ws.close();
    });

    conn.on('end', () => {
      emitLog(`\r\n\x1b[33mSSH session closed.\x1b[0m\r\n`);
    });

    try {
      if (!fs.existsSync(host.sshKeyPath) && !host.sshKeyPath.includes('-----BEGIN')) {
        emitLog(`\r\n\x1b[31mError: SSH Private key file path not found: ${host.sshKeyPath}\x1b[0m\r\n`);
        ws.close();
        return;
      }

      const privateKey = fs.existsSync(host.sshKeyPath)
        ? fs.readFileSync(host.sshKeyPath)
        : host.sshKeyPath;

      conn.connect({
        host: host.ip,
        port: host.port,
        username: host.user,
        privateKey: privateKey,
        readyTimeout: 15000
      });
    } catch (err) {
      emitLog(`\r\n\x1b[31mError starting SSH client: ${err.message}\x1b[0m\r\n`);
      ws.close();
    }
  }
});

// Start Express Server
server.listen(PORT, () => {
  console.log(`===============================================`);
  console.log(`   Docker Deployment Dashboard Server Online   `);
  console.log(`   Port: ${PORT}                               `);
  console.log(`   Authentication Type: ${process.env.AUTH_TYPE || 'none'} `);
  console.log(`===============================================`);
});
