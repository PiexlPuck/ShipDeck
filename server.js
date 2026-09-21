const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');
const { spawn, exec } = require('child_process');
const { Client } = require('ssh2');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

const PORT = process.env.PORT || 8765;

// Load optional local dashboard .env configs natively from root or mounted data subdirectories
const rootEnv = path.join(__dirname, '.env');
const persistentEnv = path.join(__dirname, 'data', '.env');

// Restore .env from persistent storage if root .env was lost on rebuild
try {
  const isRootMissing = !fs.existsSync(rootEnv) || (fs.existsSync(rootEnv) && fs.statSync(rootEnv).isDirectory());
  if (isRootMissing && fs.existsSync(persistentEnv) && fs.statSync(persistentEnv).isFile()) {
    if (!fs.existsSync(rootEnv)) {
      fs.copyFileSync(persistentEnv, rootEnv);
      console.log('Restored .env from data/.env after container rebuild.');
    }
  }
} catch (e) { }

const envPaths = [
  rootEnv,
  persistentEnv,
  path.join(process.cwd(), '.env')
];
for (const p of envPaths) {
  if (fs.existsSync(p)) {
    try {
      if (fs.statSync(p).isFile()) {
        const envContent = fs.readFileSync(p, 'utf8');
        envContent.split(/\r?\n/).forEach(line => {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) return;
          const index = trimmed.indexOf('=');
          if (index > 0) {
            const key = trimmed.slice(0, index).trim();
            const value = trimmed.slice(index + 1).trim().replace(/^['"]|['"]$/g, '');
            if (!process.env[key]) {
              process.env[key] = value;
            }
          }
        });
      }
    } catch (err) {
      console.error(`Error loading env from ${p}:`, err);
    }
  }
}

// Format Git repository HTTPS clone URL with GitHub Token credentials if configured
function formatGitUrl(url) {
  if (!url) return url;
  const token = process.env.GITHUB_TOKEN;
  const username = process.env.GITHUB_USERNAME || '';
  if (!token) return url;

  if (url.includes('github.com') && url.startsWith('http')) {
    try {
      const cleanUrl = url.replace(/https?:\/\//, '');
      const auth = username ? `${username}:${token}` : token;
      return `https://${auth}@${cleanUrl}`;
    } catch (e) {
      return url;
    }
  }
  return url;
}

// Mask secret GITHUB_TOKEN or credentials when writing outputs to logs/dashboards
function maskSecrets(str) {
  if (!str) return str;
  // Match HTTPS auth segment: https://token@github.com or https://user:token@github.com
  let masked = str.replace(/(https?:\/\/)([^:]+):([^@]+)(@github\.com)/gi, '$1$2:********$4');
  masked = masked.replace(/(https?:\/\/)([^@]+)(@github\.com)/gi, (match, proto, auth, domain) => {
    if (auth.trim().toLowerCase() === 'git') {
      return match; // git@github.com type triggers are keys, ignore 
    }
    if (auth.includes(':')) {
      const parts = auth.split(':');
      return `${proto}${parts[0]}:********${domain}`;
    }
    return `${proto}********${domain}`;
  });

  // Also replace any raw occurrences of GITHUB_TOKEN if present
  const token = process.env.GITHUB_TOKEN;
  if (token && token.length > 5) {
    masked = masked.split(token).join('********');
  }

  return masked;
}
const HOSTS_FILE = (() => {
  const DATA_DIR = path.join(__dirname, 'data');
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  const target = path.join(DATA_DIR, 'hosts.json');
  const oldHostsFile = path.join(__dirname, 'hosts.json');
  if (fs.existsSync(oldHostsFile) && !fs.existsSync(target)) {
    try {
      fs.copyFileSync(oldHostsFile, target);
      console.log('Migrated hosts.json directory location safely to data/hosts.json');
    } catch (e) {
      console.error('Migration failed:', e);
    }
  }
  return target;
})();

// Serve SVG favicon directly with proper MIME type
app.get('/favicon.svg', (req, res) => {
  const svgPath = path.join(__dirname, 'favicon.svg');
  if (fs.existsSync(svgPath)) {
    res.setHeader('Content-Type', 'image/svg+xml');
    return res.sendFile(svgPath);
  }
  const defaultSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64"><rect width="64" height="64" rx="16" fill="#0b1329"/><path d="M14 20 L32 10 L50 20 L32 30 Z" fill="#3b82f6"/><path d="M14 20 L32 30 L32 50 L14 40 Z" fill="#2563eb"/><path d="M32 30 L50 20 L50 40 L32 50 Z" fill="#06b6d4"/></svg>`;
  res.setHeader('Content-Type', 'image/svg+xml');
  res.send(defaultSvg);
});

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname)));

function getDefaultHost() {
  const defaultDir = fs.existsSync('/app') ? '/app' : process.cwd();
  return {
    id: 'local-docker',
    name: 'Local Docker Engine',
    type: 'local',
    ip: '',
    port: 22,
    user: '',
    sshKeyPath: '',
    projectDir: defaultDir,
    allowedRole: 'user',
    autoPrune: { enabled: false, mode: 'after-redeploy', lastRun: null }
  };
}

// Load hosts config
function getHosts() {
  try {
    if (!fs.existsSync(HOSTS_FILE)) {
      const initial = [getDefaultHost()];
      fs.writeFileSync(HOSTS_FILE, JSON.stringify(initial, null, 2));
      return initial;
    }
    const data = fs.readFileSync(HOSTS_FILE, 'utf8');
    const parsed = JSON.parse(data);
    if (!Array.isArray(parsed) || parsed.length === 0) {
      const initial = [getDefaultHost()];
      saveHosts(initial);
      return initial;
    }
    return parsed;
  } catch (err) {
    console.error('Error reading hosts file:', err);
    return [getDefaultHost()];
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

// Check if a docker container belongs to a specific host environment
function isContainerForHost(item, host) {
  if (!host) return false;

  const hostName = (host.name || '').trim().toLowerCase();
  const rawDir = (host.projectDir || '').trim();
  const dirBase = rawDir ? path.basename(rawDir.replace(/[\\/]+$/, '')).toLowerCase() : '';

  // Only global engine hosts that explicitly indicate they manage the full engine should see all containers
  const isGlobalEngine = (hostName.includes('engine') || hostName.includes('all containers') || hostName.includes('global')) &&
    (!rawDir || rawDir === '/app' || rawDir === '/' || rawDir === '.');

  if (isGlobalEngine) {
    return true;
  }

  // Collect identification tokens for this host
  const candidateKeys = new Set();
  if (dirBase && !['app', 'root', 'home', 'var', 'tmp', '.', ''].includes(dirBase)) {
    candidateKeys.add(dirBase);
    candidateKeys.add(dirBase.replace(/[^a-z0-9]/g, ''));
  }
  if (hostName && !['local', 'server', 'docker', 'host', ''].includes(hostName)) {
    candidateKeys.add(hostName);
    candidateKeys.add(hostName.replace(/[^a-z0-9]/g, ''));
  }

  // Remove empty keys
  candidateKeys.delete('');

  if (candidateKeys.size === 0) {
    return false;
  }

  // Check compose labels
  let composeProject = '';
  let composeWorkDir = '';
  if (item.Labels) {
    if (typeof item.Labels === 'string') {
      const projMatch = item.Labels.match(/com\.docker\.compose\.project=([^,]+)/);
      if (projMatch) composeProject = projMatch[1].toLowerCase().trim();
      const dirMatch = item.Labels.match(/com\.docker\.compose\.project\.working_dir=([^,]+)/);
      if (dirMatch) composeWorkDir = dirMatch[1].toLowerCase().trim();
    } else if (typeof item.Labels === 'object') {
      composeProject = (item.Labels['com.docker.compose.project'] || '').toLowerCase().trim();
      composeWorkDir = (item.Labels['com.docker.compose.project.working_dir'] || '').toLowerCase().trim();
    }
  }

  // 1. Check working directory exact match
  if (composeWorkDir && rawDir) {
    const normHostDir = rawDir.toLowerCase().replace(/\\/g, '/').replace(/\/+$/, '');
    const normComposeDir = composeWorkDir.replace(/\\/g, '/').replace(/\/+$/, '');
    if (normHostDir === normComposeDir) {
      return true;
    }
  }

  const rawNames = (item.Names || item.Name || '').split(',').map(n => n.replace(/^\//, '').toLowerCase().trim());

  // 2. Check candidate keys against compose project or container name
  for (const key of candidateKeys) {
    if (!key) continue;

    if (composeProject) {
      const cleanProj = composeProject.replace(/[^a-z0-9]/g, '');
      if (composeProject === key || cleanProj === key) {
        return true;
      }
    }

    for (const name of rawNames) {
      if (!name) continue;
      if (name === key) return true;
      if (name.startsWith(key + '-') || name.startsWith(key + '_') || name.startsWith(key + '.')) {
        return true;
      }
    }
  }

  return false;
}

// Parse docker ps -a --format "{{json .}}" output, filtered by host if provided
function parseDockerPsOutput(stdout, host = null) {
  const lines = (stdout || '').trim().split('\n').map(l => l.trim()).filter(Boolean);
  const results = [];
  for (const line of lines) {
    try {
      const item = JSON.parse(line);
      if (host && !isContainerForHost(item, host)) {
        continue;
      }
      let service = item.Names || item.ID || 'container';
      if (item.Labels) {
        if (typeof item.Labels === 'string') {
          const match = item.Labels.match(/com\.docker\.compose\.service=([^,]+)/);
          if (match && match[1]) {
            service = match[1];
          }
        } else if (typeof item.Labels === 'object' && item.Labels['com.docker.compose.service']) {
          service = item.Labels['com.docker.compose.service'];
        }
      }
      const rawName = (item.Names || item.Name || item.ID || 'container').split(',')[0].replace(/^\//, '').trim();
      results.push({
        Name: rawName,
        Service: service,
        State: item.State || item.Status || '',
        Status: item.Status || item.State || '',
        Ports: item.Ports || ''
      });
    } catch (e) { }
  }
  return results;
}


// Extract User Identity & Role from headers
function extractUserFromHeaders(headers, isHeaderAuthEnforced) {
  // Support standard Authelia/Keycloak headers
  let user = headers['remote-user'] || headers['x-forwarded-user'] || headers['x-auth-request-user'] || headers['x-authentik-username'] || '';
  let email = headers['remote-email'] || headers['x-forwarded-email'] || headers['x-auth-request-email'] || headers['x-authentik-email'] || '';
  let name = headers['remote-name'] || headers['x-forwarded-preferred-username'] || headers['x-auth-request-name'] || headers['x-authentik-name'] || '';
  let groupsStr = headers['remote-groups'] || headers['x-forwarded-groups'] || headers['x-auth-request-groups'] || headers['x-authentik-groups'] || '';

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
  const { name, type, ip, port, user, sshKeyPath, projectDir, allowedRole, envPermissions, gitUrl, branch } = req.body;

  if (!name || !type || !projectDir) {
    return res.status(400).json({ error: 'Missing name, type, or project directory path.' });
  }

  if (type === 'remote' && (!ip || !user)) {
    return res.status(400).json({ error: 'Remote connection requires IP address and user name.' });
  }

  const hosts = getHosts();
  const resolvedDir = type === 'local' ? path.resolve(projectDir || '.') : projectDir;
  const newHost = {
    id: Date.now().toString(),
    name,
    type,
    ip: type === 'remote' ? ip : '',
    port: type === 'remote' ? parseInt(port) || 22 : 22,
    user: type === 'remote' ? user : '',
    sshKeyPath: type === 'remote' ? sshKeyPath : '',
    projectDir: resolvedDir,
    allowedRole: allowedRole === 'user' ? 'user' : 'admin', // default is admin
    envPermissions: envPermissions || { default: 'none', users: {}, groups: {} },
    gitUrl: gitUrl || '',
    branch: branch || 'main',
    autoPrune: req.body.autoPrune || { enabled: false, mode: 'after-redeploy', lastRun: null }
  };

  hosts.push(newHost);
  saveHosts(hosts);
  res.status(201).json(newHost);
});

app.put('/api/hosts/:id', authMiddleware, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, type, ip, port, user, sshKeyPath, projectDir, allowedRole, envPermissions, gitUrl, branch, autoPrune } = req.body;

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

  const resolvedDir = type === 'local' ? path.resolve(projectDir || '.') : projectDir;
  hosts[index] = {
    ...hosts[index],
    id,
    name,
    type,
    ip: type === 'remote' ? ip : '',
    port: type === 'remote' ? parseInt(port) || 22 : 22,
    user: type === 'remote' ? user : '',
    sshKeyPath: type === 'remote' ? sshKeyPath : '',
    projectDir: resolvedDir,
    allowedRole: allowedRole === 'user' ? 'user' : 'admin',
    envPermissions: envPermissions || hosts[index].envPermissions || { default: 'none', users: {}, groups: {} },
    gitUrl: gitUrl || '',
    branch: branch || 'main',
    autoPrune: autoPrune !== undefined ? autoPrune : (hosts[index].autoPrune || { enabled: false, mode: 'after-redeploy', lastRun: null })
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

// Ping Host endpoint to verify connection and Docker container status
app.get('/api/hosts/:id/ping', authMiddleware, (req, res) => {
  const { id } = req.params;
  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) {
    return res.status(404).json({ error: 'Host not found' });
  }

  const hostRole = host.allowedRole || 'admin';
  if (hostRole === 'admin' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden. Access restricted to administrator roles.' });
  }

  const evaluateContainers = (stdout, cb) => {
    let running = 0;
    let total = 0;
    const lines = (stdout || '').trim().split('\n').map(l => l.trim()).filter(Boolean);

    if (lines.length > 0) {
      lines.forEach(line => {
        if (line.startsWith('{')) {
          try {
            const parsed = JSON.parse(line);
            total++;
            const state = (parsed.State || parsed.Status || '').toLowerCase();
            if (state.includes('running') || state.includes('up')) running++;
          } catch (e) { }
        } else if (line.startsWith('[')) {
          try {
            const arr = JSON.parse(line);
            total = arr.length;
            running = arr.filter(c => ((c.State || c.Status || '').toLowerCase().includes('running') || (c.State || c.Status || '').toLowerCase().includes('up'))).length;
          } catch (e) { }
        } else if (!line.toLowerCase().startsWith('name') && !line.toLowerCase().startsWith('container')) {
          const lower = line.toLowerCase();
          if (lower.startsWith('warn') || lower.startsWith('error') || lower.includes('no configuration file') || lower.includes('not found') || lower.includes('failed')) {
            return;
          }
          total++;
          if (lower.includes('up') || lower.includes('running')) {
            running++;
          }
        }
      });
    }

    let status = 'Online';
    if (total === 0) {
      status = 'Online';
    } else if (running === 0) {
      status = 'Offline';
    } else if (running < total) {
      status = 'Degraded';
    } else {
      status = 'Online';
    }
    cb({ status, running, total });
  };

  if (host.type === 'local') {
    if (!fs.existsSync(host.projectDir)) {
      return res.json({
        status: 'Offline',
        message: 'Project directory does not exist. Click Git Pull to deploy.',
        version: 'Directory Missing',
        containersCount: 0,
        containersRunning: 0
      });
    }

    const gitDir = path.join(host.projectDir || '.', '.git');
    const finishPing = (finalResult) => {
      if (fs.existsSync(gitDir)) {
        exec('git log -1 --format="%h - %s (%cr)"', { cwd: host.projectDir }, (gitErr, stdout) => {
          const version = gitErr ? 'No Version Data' : stdout.trim();
          res.json({
            status: finalResult.status,
            message: `${host.name} (${finalResult.running}/${finalResult.total} containers running)`,
            version,
            containersCount: finalResult.total,
            containersRunning: finalResult.running
          });
        });
      } else {
        res.json({
          status: finalResult.status,
          message: `${host.name} (${finalResult.running}/${finalResult.total} containers running)`,
          version: 'No Git Repository',
          containersCount: finalResult.total,
          containersRunning: finalResult.running
        });
      }
    };

    exec('docker compose ps --format json 2>/dev/null || docker compose ps 2>/dev/null', { cwd: host.projectDir }, (dockErr, dockStdout) => {
      evaluateContainers(dockStdout, (cResult) => {
        if (cResult.total > 0) {
          return finishPing(cResult);
        }
        // If compose has 0, check if any containers match this specific host
        exec('docker ps -a --format "{{json .}}" 2>/dev/null', (psErr, psStdout) => {
          if (!psErr && psStdout && psStdout.trim()) {
            const matching = parseDockerPsOutput(psStdout, host);
            const rCount = matching.filter(c => (c.State || c.Status || '').toLowerCase().includes('running') || (c.State || c.Status || '').toLowerCase().includes('up')).length;
            const tCount = matching.length;
            const status = tCount === 0 ? 'Online' : (rCount === tCount ? 'Online' : (rCount === 0 ? 'Offline' : 'Degraded'));
            finishPing({ status, running: rCount, total: tCount });
          } else {
            finishPing(cResult);
          }
        });
      });
    });
  } else {
    const conn = new Client();
    let connError = null;

    conn.on('ready', () => {
      const cmd = `if [ -d "${host.projectDir}" ]; then cd "${host.projectDir}" && docker compose ps 2>/dev/null; if [ -d ".git" ]; then git log -1 --format="%h - %s (%cr)"; else echo "nogit"; fi; else echo "missing"; fi`;
      conn.exec(cmd, (err, stream) => {
        if (err) {
          conn.end();
          return res.json({ status: 'Offline', message: `SSH Connection OK, command failed: ${err.message}` });
        }
        let output = '';
        stream.on('data', (data) => { output += data; }).on('close', () => {
          conn.end();
          const result = output.trim();
          if (result === 'missing') {
            res.json({ status: 'Offline', message: 'Remote project directory DOES NOT exist.', version: 'Unknown' });
          } else {
            evaluateContainers(result, (cResult) => {
              const gitLine = result.split('\n').pop() || '';
              res.json({
                status: cResult.status,
                message: `SSH Connection OK (${cResult.running}/${cResult.total} containers running)`,
                version: gitLine.includes('nogit') ? 'No Git Repository' : gitLine,
                containersCount: cResult.total,
                containersRunning: cResult.running
              });
            });
          }
        });
      });
    }).on('error', (err) => {
      connError = err.message;
      res.json({ status: 'Offline', message: `SSH Connection failed: ${connError}`, version: 'Unknown' });
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

// Git Status & Update Checker endpoint
app.get('/api/hosts/:id/git-status', authMiddleware, (req, res) => {
  const { id } = req.params;
  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) return res.status(404).json({ error: 'Host not found' });

  const targetBranch = host.branch || 'main';

  if (host.type === 'local') {
    if (!fs.existsSync(host.projectDir)) {
      return res.json({ hasUpdate: false, currentCommit: 'Missing Directory', changelog: [] });
    }
    const gitDir = path.join(host.projectDir, '.git');
    if (!fs.existsSync(gitDir)) {
      return res.json({ hasUpdate: false, currentCommit: 'No Git Repo', changelog: [] });
    }

    const gitUrlFormatted = formatGitUrl(host.gitUrl);
    const fetchCmd = host.gitUrl ? `git remote set-url origin "${gitUrlFormatted}" 2>/dev/null; git fetch origin "${targetBranch}" 2>/dev/null` : `git fetch origin "${targetBranch}" 2>/dev/null`;

    exec(fetchCmd, { cwd: host.projectDir, timeout: 6000 }, () => {
      exec('git rev-parse --short HEAD', { cwd: host.projectDir }, (err1, headOut) => {
        const currentCommit = err1 ? 'Unknown' : headOut.trim();
        exec(`git rev-parse --short origin/${targetBranch}`, { cwd: host.projectDir }, (err2, remoteOut) => {
          const remoteCommit = err2 ? currentCommit : remoteOut.trim();
          const hasUpdate = Boolean(currentCommit && remoteCommit && currentCommit !== remoteCommit && remoteCommit !== 'Unknown');

          exec('git log -n 10 --pretty=format:"%h|%s|%cr|%an"', { cwd: host.projectDir }, (err3, logOut) => {
            const changelog = (logOut || '').split('\n').filter(Boolean).map(line => {
              const parts = line.split('|');
              return { hash: parts[0] || '', subject: parts[1] || '', date: parts[2] || '', author: parts[3] || '' };
            });
            res.json({
              hasUpdate,
              currentCommit,
              remoteCommit,
              branch: targetBranch,
              changelog
            });
          });
        });
      });
    });
  } else {
    const conn = new Client();
    conn.on('ready', () => {
      const gitUrlFormatted = formatGitUrl(host.gitUrl);
      const cmd = `cd "${host.projectDir}" 2>/dev/null && (git remote set-url origin "${gitUrlFormatted}" 2>/dev/null; git fetch origin "${targetBranch}" 2>/dev/null; git rev-parse --short HEAD; git rev-parse --short "origin/${targetBranch}"; git log -n 5 --pretty=format:"%h|%s|%cr|%an")`;
      conn.exec(cmd, (err, stream) => {
        if (err) { conn.end(); return res.json({ hasUpdate: false, currentCommit: 'Error', changelog: [] }); }
        let output = '';
        stream.on('data', data => output += data).on('close', () => {
          conn.end();
          const lines = output.split('\n').map(l => l.trim()).filter(Boolean);
          if (lines.length < 2) return res.json({ hasUpdate: false, currentCommit: 'Unknown', changelog: [] });
          const currentCommit = lines[0] || 'Unknown';
          const remoteCommit = lines[1] || currentCommit;
          const hasUpdate = Boolean(currentCommit !== remoteCommit && remoteCommit !== 'Unknown');
          const changelog = lines.slice(2).map(l => {
            const parts = l.split('|');
            return { hash: parts[0] || '', subject: parts[1] || '', date: parts[2] || '', author: parts[3] || '' };
          });
          res.json({ hasUpdate, currentCommit, remoteCommit, branch: targetBranch, changelog });
        });
      });
    }).on('error', () => res.json({ hasUpdate: false, currentCommit: 'SSH Error', changelog: [] }))
      .connect({
        host: host.ip, port: host.port, username: host.user,
        privateKey: fs.existsSync(host.sshKeyPath) ? fs.readFileSync(host.sshKeyPath) : host.sshKeyPath,
        readyTimeout: 5000
      });
  }
});

// Get Deployed docker compose containers list
app.get('/api/hosts/:id/containers', authMiddleware, (req, res) => {
  const { id } = req.params;
  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) {
    return res.status(404).json({ error: 'Host not found' });
  }

  const hostRole = host.allowedRole || 'admin';
  if (hostRole === 'admin' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden. Access restricted to administrator roles.' });
  }

  const parseOutput = (stdout) => {
    const trimmed = stdout.trim();
    if (!trimmed) return [];
    try {
      if (trimmed.startsWith('[')) {
        return JSON.parse(trimmed);
      }
      const lines = trimmed.split('\n').map(l => l.trim()).filter(Boolean);
      // Try to parse line-by-line JSON (some docker compose versions format logs as separate objects)
      if (lines[0].startsWith('{')) {
        return lines.map(l => JSON.parse(l));
      }
      throw new Error('Not JSON format');
    } catch (e) {
      const lines = trimmed.split('\n').map(l => l.trim()).filter(Boolean);
      if (lines.length <= 1) return [];
      const headers = lines[0].toLowerCase().split(/\s{2,}/);
      return lines.slice(1).map(line => {
        const parts = line.split(/\s{2,}/);
        const row = {};
        headers.forEach((h, idx) => {
          row[h] = parts[idx] || '';
        });
        return {
          Name: row.name || row.container || parts[0] || '',
          Service: row.service || '',
          State: row.status || row.state || parts[5] || '',
          Ports: row.ports || parts[6] || ''
        };
      });
    }
  };

  if (host.type === 'local') {
    if (!fs.existsSync(host.projectDir)) {
      return res.json([]);
    }

    const fallbackToDockerPs = () => {
      exec('docker ps -a --format "{{json .}}" 2>/dev/null', (psErr, psStdout) => {
        if (psErr || !psStdout || !psStdout.trim()) return res.json([]);
        return res.json(parseDockerPsOutput(psStdout, host));
      });
    };

    exec('docker compose ps --format json 2>/dev/null || docker-compose ps --format json 2>/dev/null', { cwd: host.projectDir }, (err, stdout) => {
      if (!err && stdout.trim()) {
        const parsed = parseOutput(stdout);
        if (parsed && parsed.length > 0) return res.json(parsed);
      }
      exec('docker compose ps 2>/dev/null || docker-compose ps 2>/dev/null', { cwd: host.projectDir }, (plainErr, plainStdout) => {
        if (!plainErr && plainStdout.trim()) {
          const parsedPlain = parseOutput(plainStdout);
          if (parsedPlain && parsedPlain.length > 0) return res.json(parsedPlain);
        }
        fallbackToDockerPs();
      });
    });
  } else {
    const conn = new Client();
    conn.on('ready', () => {
      conn.exec(`cd "${host.projectDir}" 2>/dev/null && (docker compose ps --format json 2>/dev/null || docker-compose ps --format json 2>/dev/null || docker compose ps 2>/dev/null || docker-compose ps 2>/dev/null)`, (err, stream) => {
        if (err) {
          conn.end();
          return res.json([]);
        }
        let output = '';
        stream.on('data', (data) => {
          output += data;
        }).on('close', (code) => {
          const parsed = parseOutput(output);
          if (parsed && parsed.length > 0) {
            conn.end();
            return res.json(parsed);
          }
          conn.exec('docker ps -a --format "{{json .}}" 2>/dev/null', (psErr, psStream) => {
            if (psErr) {
              conn.end();
              return res.json([]);
            }
            let psOutput = '';
            psStream.on('data', (psData) => {
              psOutput += psData;
            }).on('close', () => {
              conn.end();
              res.json(parseDockerPsOutput(psOutput, host));
            });
          });
        });
      });
    }).on('error', () => {
      res.json([]);
    }).connect({
      host: host.ip,
      port: host.port,
      username: host.user,
      privateKey: fs.existsSync(host.sshKeyPath) ? fs.readFileSync(host.sshKeyPath) : host.sshKeyPath,
      readyTimeout: 5000
    });
  }
});

// Helper to format byte counts into human-readable strings
function formatBytes(bytes) {
  if (typeof bytes !== 'number' || isNaN(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i >= 2 ? 1 : 0)} ${units[i]}`;
}

// Helper to execute commands on either local or remote host with Promise & timeout
function executeHostCommand(host, command, timeoutMs = 20000) {
  return new Promise((resolve) => {
    if (host.type === 'local') {
      const workingDir = (host.projectDir && fs.existsSync(host.projectDir)) ? host.projectDir : undefined;
      exec(command, { cwd: workingDir, maxBuffer: 15 * 1024 * 1024, timeout: timeoutMs }, (err, stdout, stderr) => {
        resolve({
          error: err,
          code: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
          stdout: stdout || '',
          stderr: stderr || ''
        });
      });
    } else {
      const conn = new Client();
      let streamOutput = '';
      let streamErr = '';
      let settled = false;

      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          try { conn.end(); } catch (e) {}
          resolve({ error: new Error('SSH command timed out'), code: 1, stdout: streamOutput, stderr: streamErr || 'Command timed out' });
        }
      }, timeoutMs);

      conn.on('ready', () => {
        conn.exec(command, (err, stream) => {
          if (err) {
            if (!settled) {
              settled = true;
              clearTimeout(timer);
              try { conn.end(); } catch (e) {}
              resolve({ error: err, code: 1, stdout: '', stderr: err.message });
            }
            return;
          }
          stream.on('data', (data) => { streamOutput += data.toString(); });
          stream.stderr.on('data', (data) => { streamErr += data.toString(); });
          stream.on('close', (code) => {
            if (!settled) {
              settled = true;
              clearTimeout(timer);
              try { conn.end(); } catch (e) {}
              resolve({ error: null, code: typeof code === 'number' ? code : 0, stdout: streamOutput, stderr: streamErr });
            }
          });
        });
      }).on('error', (err) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve({ error: err, code: 1, stdout: '', stderr: err.message });
        }
      });

      try {
        const privateKey = fs.existsSync(host.sshKeyPath) ? fs.readFileSync(host.sshKeyPath) : host.sshKeyPath;
        conn.connect({
          host: host.ip,
          port: host.port || 22,
          username: host.user,
          privateKey,
          readyTimeout: 8000
        });
      } catch (err) {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve({ error: err, code: 1, stdout: '', stderr: err.message });
        }
      }
    }
  });
}

// Endpoint: Get Host Filesystem and Docker disk usage metrics
app.get('/api/hosts/:id/disk', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) return res.status(404).json({ error: 'Host not found' });

  const hostRole = host.allowedRole || 'admin';
  if (hostRole === 'admin' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden. Access restricted to administrator roles.' });
  }

  let filesystem = null;

  // 1. Filesystem capacity
  if (host.type === 'local') {
    try {
      const targetDir = (host.projectDir && fs.existsSync(host.projectDir)) ? host.projectDir : '.';
      if (typeof fs.statfsSync === 'function') {
        const stats = fs.statfsSync(targetDir);
        const totalBytes = stats.bsize * stats.blocks;
        const freeBytes = stats.bsize * stats.bfree;
        const availBytes = stats.bsize * stats.bavail;
        const usedBytes = Math.max(0, totalBytes - freeBytes);
        const pct = totalBytes > 0 ? Math.round((usedBytes / totalBytes) * 100) : 0;
        filesystem = {
          total: formatBytes(totalBytes),
          used: formatBytes(usedBytes),
          available: formatBytes(availBytes),
          totalBytes,
          usedBytes,
          availableBytes: availBytes,
          percentUsed: pct,
          mount: targetDir
        };
      }
    } catch (e) {
      console.error('Local statfs error:', e.message);
    }
  } else {
    // Remote SSH: run df -Pk
    const dfRes = await executeHostCommand(host, `df -Pk "${host.projectDir}" 2>/dev/null || df -Pk /`, 10000);
    if (dfRes.stdout) {
      const lines = dfRes.stdout.trim().split('\n').map(l => l.trim()).filter(Boolean);
      if (lines.length >= 2) {
        const dataLine = lines[lines.length - 1];
        const parts = dataLine.split(/\s+/);
        if (parts.length >= 5) {
          const totalBytes = (parseInt(parts[1], 10) || 0) * 1024;
          const usedBytes = (parseInt(parts[2], 10) || 0) * 1024;
          const availBytes = (parseInt(parts[3], 10) || 0) * 1024;
          const pct = parseInt(parts[4].replace('%', ''), 10) || (totalBytes > 0 ? Math.round((usedBytes / totalBytes) * 100) : 0);
          filesystem = {
            total: formatBytes(totalBytes),
            used: formatBytes(usedBytes),
            available: formatBytes(availBytes),
            totalBytes,
            usedBytes,
            availableBytes: availBytes,
            percentUsed: pct,
            mount: parts[5] || '/'
          };
        }
      }
    }
  }

  // 2. Docker storage breakdown via docker system df
  const dockerMetrics = {
    images: { count: '0', active: '0', size: '0 B', reclaimable: '0 B' },
    containers: { count: '0', active: '0', size: '0 B', reclaimable: '0 B' },
    volumes: { count: '0', active: '0', size: '0 B', reclaimable: '0 B' },
    buildCache: { count: '0', active: '0', size: '0 B', reclaimable: '0 B' },
    available: false
  };

  const dfResult = await executeHostCommand(host, 'docker system df --format "{{json .}}" 2>/dev/null', 12000);
  if (dfResult.stdout && dfResult.stdout.trim()) {
    const lines = dfResult.stdout.trim().split('\n').map(l => l.trim()).filter(Boolean);
    let parsedCount = 0;
    lines.forEach(line => {
      try {
        const item = JSON.parse(line);
        const type = (item.Type || '').toLowerCase();
        const obj = {
          count: String(item.TotalCount || item.Count || '0'),
          active: String(item.Active || '0'),
          size: item.Size || '0 B',
          reclaimable: item.Reclaimable || '0 B'
        };
        if (type.includes('image')) {
          dockerMetrics.images = obj;
          parsedCount++;
        } else if (type.includes('container')) {
          dockerMetrics.containers = obj;
          parsedCount++;
        } else if (type.includes('volume')) {
          dockerMetrics.volumes = obj;
          parsedCount++;
        } else if (type.includes('cache')) {
          dockerMetrics.buildCache = obj;
          parsedCount++;
        }
      } catch (e) {}
    });
    if (parsedCount > 0) {
      dockerMetrics.available = true;
    }
  }

  // Fallback to plain table parsing if json was unsupported
  if (!dockerMetrics.available) {
    const plainDf = await executeHostCommand(host, 'docker system df 2>/dev/null', 10000);
    if (plainDf.stdout && plainDf.stdout.includes('TYPE')) {
      const pLines = plainDf.stdout.trim().split('\n').slice(1);
      pLines.forEach(pl => {
        const cols = pl.trim().split(/\s{2,}/);
        if (cols.length >= 4) {
          const type = cols[0].toLowerCase();
          const obj = {
            count: cols[1] || '0',
            active: cols[2] || '0',
            size: cols[3] || '0 B',
            reclaimable: cols[4] || '0 B'
          };
          if (type.includes('image')) dockerMetrics.images = obj;
          else if (type.includes('container')) dockerMetrics.containers = obj;
          else if (type.includes('volume')) dockerMetrics.volumes = obj;
          else if (type.includes('cache')) dockerMetrics.buildCache = obj;
          dockerMetrics.available = true;
        }
      });
    }
  }

  res.json({
    filesystem,
    docker: dockerMetrics,
    autoPrune: host.autoPrune || { enabled: false, mode: 'after-redeploy', lastRun: null }
  });
});

// Endpoint: List all Docker images with in-use status
app.get('/api/hosts/:id/images', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) return res.status(404).json({ error: 'Host not found' });

  const hostRole = host.allowedRole || 'admin';
  if (hostRole === 'admin' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden. Access restricted to administrator roles.' });
  }

  const [imagesRes, psRes] = await Promise.all([
    executeHostCommand(host, 'docker images --format "{{json .}}" 2>/dev/null', 15000),
    executeHostCommand(host, 'docker ps -a --format "{{json .}}" 2>/dev/null', 10000)
  ]);

  const activeImageNames = new Set();
  const activeContainerMap = {};

  if (psRes.stdout) {
    const psLines = psRes.stdout.trim().split('\n').map(l => l.trim()).filter(Boolean);
    psLines.forEach(line => {
      try {
        const c = JSON.parse(line);
        const img = (c.Image || '').trim();
        const cName = (c.Names || c.ID || 'container').split(',')[0].replace(/^\//, '').trim();
        if (img) {
          activeImageNames.add(img);
          if (!activeContainerMap[img]) activeContainerMap[img] = [];
          activeContainerMap[img].push(cName);
        }
      } catch (e) {}
    });
  }

  const images = [];
  if (imagesRes.stdout) {
    const imgLines = imagesRes.stdout.trim().split('\n').map(l => l.trim()).filter(Boolean);
    imgLines.forEach(line => {
      try {
        const item = JSON.parse(line);
        const repo = item.Repository || '<none>';
        const tag = item.Tag || '<none>';
        const rawId = item.ID || '';
        const shortId = rawId.replace(/^sha256:/, '').substring(0, 12);
        const fullRef = (repo !== '<none>' && tag !== '<none>') ? `${repo}:${tag}` : repo;

        let inUse = false;
        let attachedContainers = [];

        if (activeImageNames.has(fullRef)) {
          inUse = true;
          attachedContainers = activeContainerMap[fullRef] || [];
        } else if (activeImageNames.has(repo)) {
          inUse = true;
          attachedContainers = activeContainerMap[repo] || [];
        } else if (activeImageNames.has(shortId) || activeImageNames.has(rawId)) {
          inUse = true;
          attachedContainers = activeContainerMap[shortId] || activeContainerMap[rawId] || [];
        } else {
          for (const activeImg of activeImageNames) {
            if (rawId && (activeImg.includes(shortId) || rawId.includes(activeImg))) {
              inUse = true;
              attachedContainers = activeContainerMap[activeImg] || [];
              break;
            }
          }
        }

        if (!inUse && item.Containers && parseInt(item.Containers, 10) > 0) {
          inUse = true;
        }

        images.push({
          id: shortId,
          fullId: rawId,
          repository: repo,
          tag: tag,
          size: item.Size || '0 B',
          createdSince: item.CreatedSince || '',
          createdAt: item.CreatedAt || '',
          containers: item.Containers || (inUse ? '1' : '0'),
          inUse,
          containersInUse: attachedContainers
        });
      } catch (e) {}
    });
  }

  res.json({ images });
});

// Endpoint: Delete a single Docker image
app.delete('/api/hosts/:id/images/:imageId', authMiddleware, requireAdmin, async (req, res) => {
  const { id, imageId } = req.params;
  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) return res.status(404).json({ error: 'Host not found' });

  const sanitizedId = (imageId || '').trim();
  if (!sanitizedId || !/^[a-zA-Z0-9_\-.:/@]+$/.test(sanitizedId)) {
    return res.status(400).json({ error: 'Invalid Docker image identifier.' });
  }

  const force = req.query.force === 'true';
  const cmd = `docker rmi ${force ? '-f ' : ''}${sanitizedId}`;

  const result = await executeHostCommand(host, cmd, 20000);
  if (result.code !== 0) {
    const errMsg = (result.stderr || result.stdout || 'Failed to remove image.').trim();
    const isInUse = errMsg.toLowerCase().includes('being used') || errMsg.toLowerCase().includes('conflict');
    return res.status(400).json({
      error: errMsg,
      isInUse
    });
  }

  res.json({
    success: true,
    message: `Image ${sanitizedId} deleted successfully.`,
    output: result.stdout.trim()
  });
});

// Endpoint: Prune unused/dangling Docker images
app.post('/api/hosts/:id/images/prune', authMiddleware, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) return res.status(404).json({ error: 'Host not found' });

  const pruneAll = req.query.all === 'true';
  const cmd = pruneAll ? 'docker image prune -a -f' : 'docker image prune -f';

  const result = await executeHostCommand(host, cmd, 30000);
  if (result.code !== 0) {
    return res.status(400).json({
      error: (result.stderr || result.stdout || 'Failed to prune images.').trim()
    });
  }

  // Update lastRun timestamp
  const idx = hosts.findIndex(h => h.id === id);
  if (idx !== -1) {
    hosts[idx].autoPrune = {
      ...(hosts[idx].autoPrune || { enabled: false, mode: 'after-redeploy' }),
      lastRun: new Date().toISOString()
    };
    saveHosts(hosts);
  }

  res.json({
    success: true,
    message: 'Images pruned successfully.',
    output: (result.stdout || 'No unused images to remove.').trim()
  });
});

// Endpoint: Configure auto-prune settings for a host
app.put('/api/hosts/:id/autoprune', authMiddleware, requireAdmin, (req, res) => {
  const { id } = req.params;
  const { enabled, mode } = req.body;

  let hosts = getHosts();
  const idx = hosts.findIndex(h => h.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Host not found' });

  const validModes = ['after-redeploy', 'daily', 'weekly'];
  const chosenMode = validModes.includes(mode) ? mode : 'after-redeploy';

  hosts[idx].autoPrune = {
    enabled: Boolean(enabled),
    mode: chosenMode,
    lastRun: hosts[idx].autoPrune?.lastRun || null
  };

  saveHosts(hosts);
  res.json({
    success: true,
    autoPrune: hosts[idx].autoPrune
  });
});

// Helper to trigger auto-pruning on a host
function checkTriggerAutoPrune(host, emitLog = null) {
  if (!host || !host.autoPrune || !host.autoPrune.enabled) return;
  const log = emitLog || ((msg) => console.log(`[AutoPrune][${host.name}] ${msg}`));
  log(`\r\n\x1b[36m[Auto-Prune] Post-redeploy cleanup triggered: running 'docker image prune -f'...\x1b[0m\r\n`);

  executeHostCommand(host, 'docker image prune -f', 30000).then(({ stdout, stderr, code }) => {
    if (code === 0) {
      log(`\x1b[32m[Auto-Prune] Completed successfully:\x1b[0m\r\n${(stdout || 'Clean.').trim()}\r\n`);
      const allHosts = getHosts();
      const idx = allHosts.findIndex(h => h.id === host.id);
      if (idx !== -1) {
        allHosts[idx].autoPrune = {
          ...(allHosts[idx].autoPrune || {}),
          lastRun: new Date().toISOString()
        };
        saveHosts(allHosts);
      }
    } else {
      log(`\x1b[33m[Auto-Prune] Note during cleanup: ${(stderr || 'Completed with warnings').trim()}\x1b[0m\r\n`);
    }
  }).catch(err => {
    log(`\x1b[31m[Auto-Prune] Error: ${err.message}\x1b[0m\r\n`);
  });
}

// Background scheduler for daily and weekly auto-prune
function initAutoPruneScheduler() {
  setInterval(() => {
    try {
      const allHosts = getHosts();
      const now = Date.now();
      allHosts.forEach(host => {
        if (!host.autoPrune || !host.autoPrune.enabled) return;
        const mode = host.autoPrune.mode;
        const lastRunTime = host.autoPrune.lastRun ? new Date(host.autoPrune.lastRun).getTime() : 0;
        let shouldRun = false;

        if (mode === 'daily') {
          if (!lastRunTime || (now - lastRunTime) >= 24 * 3600 * 1000) {
            shouldRun = true;
          }
        } else if (mode === 'weekly') {
          if (!lastRunTime || (now - lastRunTime) >= 7 * 24 * 3600 * 1000) {
            shouldRun = true;
          }
        }

        if (shouldRun) {
          console.log(`[AutoPrune] Executing scheduled (${mode}) prune for host: ${host.name}`);
          checkTriggerAutoPrune(host);
        }
      });
    } catch (e) {
      console.error('Error in auto-prune scheduler interval:', e);
    }
  }, 60 * 60 * 1000);
}

// Helper to determine active env permissions stage
function getEnvPermission(host, userContext) {
  if (userContext.role === 'admin') {
    return 'write';
  }

  const policy = host.envPermissions || { default: 'none', users: {}, groups: {} };
  const username = userContext.username ? userContext.username.toLowerCase() : null;

  if (username && policy.users && policy.users[username]) {
    return policy.users[username];
  }

  if (userContext.groups && policy.groups) {
    let highest = 'none';
    for (const group of userContext.groups) {
      const rule = policy.groups[group];
      if (rule) {
        if (rule === 'write') {
          highest = 'write';
        } else if (rule === 'read' && highest !== 'write') {
          highest = 'read';
        }
      }
    }
    if (highest !== 'none') {
      return highest;
    }
  }

  return policy.default || 'none';
}

// System Docker Socket Status probe
app.get('/api/system-status', authMiddleware, (req, res) => {
  const socketPath = '/var/run/docker.sock';
  const hasLinuxSocket = fs.existsSync(socketPath);

  exec('docker info', (err, stdout, stderr) => {
    if (err) {
      const errCombined = ((err.message || '') + ' ' + (stderr || '')).toLowerCase();
      const isPermissionDenied = errCombined.includes('permission denied');
      return res.json({
        dockerConnected: false,
        permissionDenied: isPermissionDenied,
        commandAdvice: isPermissionDenied ? 'sudo chmod 666 /var/run/docker.sock' : null,
        message: isPermissionDenied
          ? 'Docker socket permission denied. Run "sudo chmod 666 /var/run/docker.sock" on your server host.'
          : 'Docker daemon is not reached inside dashboard: ' + err.message,
        hasSocket: hasLinuxSocket
      });
    }
    res.json({
      dockerConnected: true,
      permissionDenied: false,
      message: 'Docker daemon is accessible.',
      hasSocket: hasLinuxSocket
    });
  });
});

// Helper to resolve the location of the .env file for local hosts
function resolveEnvPath(projectDir) {
  const directPath = path.resolve(projectDir, '.env');
  if (fs.existsSync(directPath)) {
    try {
      if (fs.statSync(directPath).isFile()) {
        return directPath;
      }
    } catch (e) { }
  }
  // Check if data/.env exists (e.g. for persisted container volumes)
  const dataEnv = path.resolve(projectDir, 'data', '.env');
  if (fs.existsSync(dataEnv)) {
    try {
      if (fs.statSync(dataEnv).isFile()) {
        return dataEnv;
      }
    } catch (e) { }
  }
  return directPath;
}

// Helper to resolve the location of .env.example for local hosts
function resolveEnvExamplePath(projectDir) {
  const candidates = [
    path.resolve(projectDir, '.env.example'),
    path.resolve(projectDir, 'env.example'),
    path.resolve(projectDir, '.env.sample'),
    path.resolve(projectDir, 'env.sample'),
    path.resolve(projectDir, '.env.template')
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) {
      try {
        if (fs.statSync(c).isFile()) return c;
      } catch (e) { }
    }
  }
  const defaultAppCandidates = [
    path.resolve(__dirname, '.env.example'),
    '/app/.env.example'
  ];
  for (const c of defaultAppCandidates) {
    if (fs.existsSync(c)) {
      try {
        if (fs.statSync(c).isFile()) return c;
      } catch (e) { }
    }
  }
  return path.resolve(projectDir, '.env.example');
}

// Get .env file inside project host
app.get('/api/hosts/:id/env', authMiddleware, (req, res) => {
  const { id } = req.params;
  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) {
    return res.status(404).json({ error: 'Host not found' });
  }

  const permission = getEnvPermission(host, req.user);
  if (permission === 'none') {
    return res.status(403).json({ error: 'Forbidden. Access to env file is restricted.' });
  }

  if (host.type === 'local') {
    const envPath = resolveEnvPath(host.projectDir);
    if (!fs.existsSync(envPath)) {
      return res.json({ permission, content: '', filename: '.env' });
    }

    try {
      const stat = fs.statSync(envPath);
      if (stat.isDirectory()) {
        return res.json({ permission, content: '', filename: '.env' });
      }
      const data = fs.readFileSync(envPath, 'utf8');
      res.json({ permission, content: data, filename: '.env' });
    } catch (err) {
      return res.status(500).json({ error: `Failed to read local env: ${err.message}` });
    }
  } else {
    const conn = new Client();
    conn.on('ready', () => {
      conn.exec(`cat "${host.projectDir}/.env" 2>/dev/null || echo ""`, (err, stream) => {
        if (err) {
          conn.end();
          return res.status(500).json({ error: `SSH Command execution failed: ${err.message}` });
        }
        let output = '';
        stream.on('data', (data) => {
          output += data;
          if (output.length > 1000000) {
            stream.destroy();
          }
        }).on('close', () => {
          conn.end();
          res.json({ permission, content: output, filename: '.env' });
        });
      });
    }).on('error', (err) => {
      res.status(500).json({ error: `SSH Connection failed: ${err.message}` });
    }).connect({
      host: host.ip,
      port: host.port,
      username: host.user,
      privateKey: fs.existsSync(host.sshKeyPath) ? fs.readFileSync(host.sshKeyPath) : host.sshKeyPath,
      readyTimeout: 5000
    });
  }
});

// Update .env file inside project host
app.post('/api/hosts/:id/env', authMiddleware, (req, res) => {
  const { id } = req.params;
  const { content } = req.body;

  if (content === undefined) {
    return res.status(400).json({ error: 'Missing content field in request body.' });
  }

  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) {
    return res.status(404).json({ error: 'Host not found' });
  }

  const permission = getEnvPermission(host, req.user);
  if (permission !== 'write') {
    return res.status(403).json({ error: 'Forbidden. Write access is restricted.' });
  }

  if (host.type === 'local') {
    let envPath = path.resolve(host.projectDir, '.env');
    // If envPath is a directory (Docker mount artifact), write to data/.env
    try {
      if (fs.existsSync(envPath) && fs.statSync(envPath).isDirectory()) {
        envPath = path.resolve(host.projectDir, 'data', '.env');
      }
    } catch (e) { }

    const targetDir = path.dirname(envPath);
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }

    fs.writeFile(envPath, content, 'utf8', (err) => {
      if (err) {
        return res.status(500).json({ error: `Failed to save local env file: ${err.message}` });
      }

      // Also persist to data/.env so container rebuilds can never wipe the dashboard env
      if (host.id === 'local-docker' || host.projectDir === '/app') {
        try {
          const dataDir = path.join(__dirname, 'data');
          if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
          fs.writeFileSync(path.join(dataDir, '.env'), content, 'utf8');
        } catch (e) { }
      }

      res.json({ message: '.env file successfully updated.', filename: '.env' });
    });
  } else {
    const base64Content = Buffer.from(content).toString('base64');
    const conn = new Client();
    conn.on('ready', () => {
      const cmd = `mkdir -p "${host.projectDir}" && echo "${base64Content}" | base64 -d > "${host.projectDir}/.env"`;
      conn.exec(cmd, (err, stream) => {
        if (err) {
          conn.end();
          return res.status(500).json({ error: `SSH write failed: ${err.message}` });
        }
        stream.on('close', (code) => {
          conn.end();
          if (code === 0) {
            res.json({ message: '.env file successfully updated remotely.', filename: '.env' });
          } else {
            res.status(500).json({ error: `Remote write command closed with failure code: ${code}` });
          }
        });
      });
    }).on('error', (err) => {
      res.status(500).json({ error: `SSH Connection failed: ${err.message}` });
    }).connect({
      host: host.ip,
      port: host.port,
      username: host.user,
      privateKey: fs.existsSync(host.sshKeyPath) ? fs.readFileSync(host.sshKeyPath) : host.sshKeyPath,
      readyTimeout: 5000
    });
  }
});

// Get .env.example template file inside project host
app.get('/api/hosts/:id/env-example', authMiddleware, (req, res) => {
  const { id } = req.params;
  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) {
    return res.status(404).json({ error: 'Host not found' });
  }

  const hostRole = host.allowedRole || 'admin';
  if (hostRole === 'admin' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden. Access restricted.' });
  }

  // Permission for viewing .env.example: admin gets write, user gets read
  const permission = req.user.role === 'admin' ? 'write' : 'read';

  if (host.type === 'local') {
    const examplePath = resolveEnvExamplePath(host.projectDir || '.');
    if (!fs.existsSync(examplePath)) {
      return res.json({
        permission,
        content: '# No .env.example found for this environment.\n# You can create one here or copy from your project repository.\n',
        filename: '.env.example',
        exists: false
      });
    }

    try {
      const stat = fs.statSync(examplePath);
      if (stat.isDirectory()) {
        return res.json({
          permission,
          content: '# No .env.example found for this environment.\n',
          filename: '.env.example',
          exists: false
        });
      }
      const data = fs.readFileSync(examplePath, 'utf8');
      res.json({ permission, content: data, filename: path.basename(examplePath), exists: true });
    } catch (err) {
      return res.status(500).json({ error: `Failed to read local env.example: ${err.message}` });
    }
  } else {
    const conn = new Client();
    conn.on('ready', () => {
      const cmd = `if [ -f "${host.projectDir}/.env.example" ]; then cat "${host.projectDir}/.env.example"; elif [ -f "${host.projectDir}/env.example" ]; then cat "${host.projectDir}/env.example"; else echo "# No .env.example found on remote host."; fi`;
      conn.exec(cmd, (err, stream) => {
        if (err) {
          conn.end();
          return res.status(500).json({ error: `SSH Command execution failed: ${err.message}` });
        }
        let output = '';
        stream.on('data', (data) => {
          output += data;
          if (output.length > 1000000) stream.destroy();
        }).on('close', () => {
          conn.end();
          res.json({ permission, content: output, filename: '.env.example', exists: !output.includes('# No .env.example') });
        });
      });
    }).on('error', (err) => {
      res.status(500).json({ error: `SSH Connection error: ${err.message}` });
    }).connect({
      host: host.ip,
      port: host.port,
      username: host.user,
      privateKey: fs.existsSync(host.sshKeyPath) ? fs.readFileSync(host.sshKeyPath) : host.sshKeyPath,
      readyTimeout: 5000
    });
  }
});

// Save .env.example template file inside project host
app.post('/api/hosts/:id/env-example', authMiddleware, (req, res) => {
  const { id } = req.params;
  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) {
    return res.status(404).json({ error: 'Host not found' });
  }

  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden. Admin role required to edit .env.example.' });
  }

  const { content } = req.body;
  if (content === undefined || typeof content !== 'string') {
    return res.status(400).json({ error: 'Invalid content string in request body.' });
  }

  if (host.type === 'local') {
    try {
      const targetDir = host.projectDir || '.';
      if (!fs.existsSync(targetDir)) {
        fs.mkdirSync(targetDir, { recursive: true });
      }
      const examplePath = resolveEnvExamplePath(targetDir);
      fs.writeFileSync(examplePath, content, 'utf8');
      return res.json({ success: true, message: '.env.example updated successfully.', filename: '.env.example' });
    } catch (err) {
      return res.status(500).json({ error: `Failed to write .env.example: ${err.message}` });
    }
  } else {
    const base64Content = Buffer.from(content).toString('base64');
    const conn = new Client();
    conn.on('ready', () => {
      const cmd = `mkdir -p "${host.projectDir}" && echo "${base64Content}" | base64 -d > "${host.projectDir}/.env.example"`;
      conn.exec(cmd, (err, stream) => {
        if (err) {
          conn.end();
          return res.status(500).json({ error: `SSH write failed: ${err.message}` });
        }
        stream.on('close', (code) => {
          conn.end();
          if (code === 0) {
            res.json({ success: true, message: '.env.example updated remotely.', filename: '.env.example' });
          } else {
            res.status(500).json({ error: `Remote write command closed with failure code: ${code}` });
          }
        });
      });
    }).on('error', (err) => {
      res.status(500).json({ error: `SSH Connection failed: ${err.message}` });
    }).connect({
      host: host.ip,
      port: host.port,
      username: host.user,
      privateKey: fs.existsSync(host.sshKeyPath) ? fs.readFileSync(host.sshKeyPath) : host.sshKeyPath,
      readyTimeout: 5000
    });
  }
});

// Get Compose file details inside project host
app.get('/api/hosts/:id/compose', authMiddleware, (req, res) => {
  const { id } = req.params;
  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) {
    return res.status(404).json({ error: 'Host not found' });
  }

  const permission = getEnvPermission(host, req.user);
  if (permission === 'none') {
    return res.status(403).json({ error: 'Forbidden. No access permitted.' });
  }

  findComposeFile(host.projectDir, host.type, host, (err, filepath, filename) => {
    if (err) {
      return res.status(500).json({ error: `Failed to detect compose file: ${err.message}` });
    }

    if (host.type === 'local') {
      if (!fs.existsSync(filepath)) {
        return res.json({ permission, filename, content: '' });
      }
      fs.readFile(filepath, 'utf8', (readErr, data) => {
        if (readErr) {
          return res.status(500).json({ error: `Failed to read local compose file: ${readErr.message}` });
        }
        res.json({ permission, filename, content: data });
      });
    } else {
      const conn = new Client();
      conn.on('ready', () => {
        conn.exec(`cat "${filepath}" 2>/dev/null || echo ""`, (execErr, stream) => {
          if (execErr) {
            conn.end();
            return res.status(500).json({ error: `SSH Command execution failed: ${execErr.message}` });
          }
          let output = '';
          stream.on('data', (data) => {
            output += data;
            if (output.length > 1000000) { // Safety ceiling: 1MB
              stream.destroy();
            }
          }).on('close', () => {
            conn.end();
            res.json({ permission, filename, content: output });
          });
        });
      }).on('error', (connErr) => {
        res.status(500).json({ error: `SSH Connection failed: ${connErr.message}` });
      }).connect({
        host: host.ip,
        port: host.port,
        username: host.user,
        privateKey: fs.existsSync(host.sshKeyPath) ? fs.readFileSync(host.sshKeyPath) : host.sshKeyPath,
        readyTimeout: 5000
      });
    }
  });
});

// Update Compose file inside project host
app.post('/api/hosts/:id/compose', authMiddleware, (req, res) => {
  const { id } = req.params;
  const { content } = req.body;

  if (content === undefined) {
    return res.status(400).json({ error: 'Missing content field in request body.' });
  }

  const hosts = getHosts();
  const host = hosts.find(h => h.id === id);
  if (!host) {
    return res.status(404).json({ error: 'Host not found' });
  }

  const permission = getEnvPermission(host, req.user);
  if (permission !== 'write') {
    return res.status(403).json({ error: 'Forbidden. Write access is restricted.' });
  }

  findComposeFile(host.projectDir, host.type, host, (err, filepath, filename) => {
    if (err) {
      return res.status(500).json({ error: `Failed to detect compose file: ${err.message}` });
    }

    if (host.type === 'local') {
      fs.writeFile(filepath, content, 'utf8', (writeErr) => {
        if (writeErr) {
          return res.status(500).json({ error: `Failed to save local compose file: ${writeErr.message}` });
        }
        res.json({ message: `${filename} successfully updated.` });
      });
    } else {
      const base64Content = Buffer.from(content).toString('base64');
      const conn = new Client();
      conn.on('ready', () => {
        const cmd = `mkdir -p "${host.projectDir}" && echo "${base64Content}" | base64 -d > "${filepath}"`;
        conn.exec(cmd, (execErr, stream) => {
          if (execErr) {
            conn.end();
            return res.status(500).json({ error: `SSH write failed: ${execErr.message}` });
          }
          stream.on('close', (code) => {
            conn.end();
            if (code === 0) {
              res.json({ message: `${filename} successfully updated remotely.` });
            } else {
              res.status(500).json({ error: `Remote write command closed with failure code: ${code}` });
            }
          });
        });
      }).on('error', (connErr) => {
        res.status(500).json({ error: `SSH Connection failed: ${connErr.message}` });
      }).connect({
        host: host.ip,
        port: host.port,
        username: host.user,
        privateKey: fs.existsSync(host.sshKeyPath) ? fs.readFileSync(host.sshKeyPath) : host.sshKeyPath,
        readyTimeout: 5000
      });
    }
  });
});

// Sequentially search for docker compose config files
function findComposeFile(projectDir, type = 'local', host = null, callback) {
  const filenames = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'];
  if (type === 'local') {
    for (const fn of filenames) {
      const p = path.resolve(projectDir, fn);
      if (fs.existsSync(p)) {
        return callback(null, p, fn);
      }
    }
    return callback(null, path.resolve(projectDir, 'docker-compose.yml'), 'docker-compose.yml');
  } else {
    // For remote hosts, we execute test checks via SSH
    const conn = new Client();
    conn.on('ready', () => {
      const cmd = `cd "${projectDir}" && ( [ -f docker-compose.yml ] && echo "docker-compose.yml" || ( [ -f docker-compose.yaml ] && echo "docker-compose.yaml" || ( [ -f compose.yml ] && echo "compose.yml" || ( [ -f compose.yaml ] && echo "compose.yaml" || echo "docker-compose.yml" ) ) ) )`;
      conn.exec(cmd, (err, stream) => {
        if (err) {
          conn.end();
          return callback(err);
        }
        let filename = '';
        stream.on('data', (data) => {
          filename += data;
        }).on('close', () => {
          conn.end();
          filename = filename.trim() || 'docker-compose.yml';
          callback(null, `${projectDir}/${filename}`, filename);
        });
      });
    }).on('error', (err) => {
      callback(err);
    }).connect({
      host: host.ip,
      port: host.port,
      username: host.user,
      privateKey: fs.existsSync(host.sshKeyPath) ? fs.readFileSync(host.sshKeyPath) : host.sshKeyPath,
      readyTimeout: 5000
    });
  }
}

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
  const container = urlObj.searchParams.get('container') || '';

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
      ws.send(maskSecrets(formatted));
    }
  };

  // Determine commands to execute based on host action
  let commandStr = '';
  if (action === 'pull' || action === 'force-pull') {
    const targetBranch = host.branch || 'main';
    const isForce = (action === 'force-pull');
    if (host.type === 'local') {
      const gitDir = path.join(host.projectDir, '.git');
      const isCloneRequired = host.gitUrl && !fs.existsSync(gitDir);
      const gitUrlFormatted = formatGitUrl(host.gitUrl);
      if (isCloneRequired) {
        commandStr = `git clone -b "${targetBranch}" "${gitUrlFormatted}" .`;
      } else if (isForce) {
        commandStr = `git remote set-url origin "${gitUrlFormatted}" 2>/dev/null; git fetch origin "${targetBranch}" && git checkout -B "${targetBranch}" "origin/${targetBranch}" && git reset --hard "origin/${targetBranch}" && git clean -fd`;
      } else {
        commandStr = `git remote set-url origin "${gitUrlFormatted}" 2>/dev/null; git fetch origin && (git checkout "${targetBranch}" || git checkout -b "${targetBranch}" "origin/${targetBranch}") && git pull origin "${targetBranch}"`;
      }
      if (!fs.existsSync(host.projectDir)) {
        fs.mkdirSync(host.projectDir, { recursive: true });
      }
    } else {
      if (isForce) {
        commandStr = `git fetch origin "${targetBranch}" 2>/dev/null; git checkout -B "${targetBranch}" "origin/${targetBranch}" 2>/dev/null; git reset --hard "origin/${targetBranch}" 2>/dev/null; git clean -fd 2>/dev/null`;
      } else {
        commandStr = `git fetch origin 2>/dev/null; (git checkout "${targetBranch}" || git checkout -b "${targetBranch}" "origin/${targetBranch}") 2>/dev/null; git pull origin "${targetBranch}"`;
      }
    }
  } else if (action === 'redeploy' || action === 'force-redeploy') {
    if (action === 'force-redeploy') {
      commandStr = 'docker compose down --remove-orphans 2>/dev/null || docker-compose down --remove-orphans 2>/dev/null; (docker compose build --no-cache || docker-compose build --no-cache) && (docker compose up -d --force-recreate || docker-compose up -d --force-recreate)';
    } else {
      commandStr = 'docker compose up -d --build || docker-compose up -d --build';
    }
  } else if (action === 'redeploy-app') {
    // --no-deps rebuilds and starts app containers without restarting/recreating linked DB dependencies
    commandStr = 'docker compose up -d --build --no-deps || docker-compose up -d --build --no-deps';
  } else if (action === 'start') {
    commandStr = 'docker compose start || docker-compose start || docker compose up -d || docker-compose up -d';
  } else if (action === 'stop') {
    commandStr = 'docker compose stop || docker compose down || docker-compose stop || docker-compose down';
  } else if (action === 'logs') {
    commandStr = 'docker compose logs --tail=100 -f';
  } else if (action === 'container-logs') {
    if (!container) {
      ws.send(`\r\n\x1b[31mError: No container/service specified for container-logs action.\x1b[0m\r\n`);
      ws.close();
      return;
    }
    const cleanContainer = container.replace(/[^a-zA-Z0-9_\-]/g, '');
    commandStr = `docker compose logs --tail=100 -f ${cleanContainer} 2>/dev/null || docker-compose logs --tail=100 -f ${cleanContainer} 2>/dev/null || docker logs --tail=100 -f ${cleanContainer}`;
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
      const exitCode = typeof code === 'number' ? code : 1;
      if (exitCode === 0) {
        emitLog(`\r\n\x1b[32m=== Command completed successfully (exit code 0) ===\x1b[0m\r\n`);
        if ((action === 'redeploy' || action === 'force-redeploy') && host.autoPrune && host.autoPrune.enabled && host.autoPrune.mode === 'after-redeploy') {
          checkTriggerAutoPrune(host, emitLog);
        }
      } else {
        emitLog(`\r\n\x1b[31m=== Command failed with exit code ${exitCode} ===\x1b[0m\r\n`);
      }
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ __shipdeck_event: 'exit', code: exitCode, action }));
      }
      setTimeout(() => {
        if (ws.readyState === WebSocket.OPEN) ws.close();
      }, 150);
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
      let fullRemoteCommand = '';
      if ((action === 'pull' || action === 'force-pull') && host.gitUrl) {
        const gitUrlFormatted = formatGitUrl(host.gitUrl);
        const branch = host.branch || 'main';
        if (action === 'force-pull') {
          fullRemoteCommand = `mkdir -p "${host.projectDir}" && cd "${host.projectDir}" && ( [ -d .git ] && ( git remote set-url origin "${gitUrlFormatted}" 2>/dev/null; git fetch origin "${branch}" && git checkout -B "${branch}" "origin/${branch}" && git reset --hard "origin/${branch}" && git clean -fd ) || git clone -b "${branch}" "${gitUrlFormatted}" . )`;
        } else {
          fullRemoteCommand = `mkdir -p "${host.projectDir}" && cd "${host.projectDir}" && ( [ -d .git ] && ( git remote set-url origin "${gitUrlFormatted}" 2>/dev/null; git checkout "${branch}" && git pull ) || git clone -b "${branch}" "${gitUrlFormatted}" . )`;
        }
      } else {
        fullRemoteCommand = `mkdir -p "${host.projectDir}" && cd "${host.projectDir}" && ${commandStr}`;
      }

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
          const exitCode = typeof code === 'number' ? code : (signal ? 1 : 0);
          if (exitCode === 0) {
            emitLog(`\r\n\x1b[32m=== Command completed successfully (exit code 0) ===\x1b[0m\r\n`);
            if ((action === 'redeploy' || action === 'force-redeploy') && host.autoPrune && host.autoPrune.enabled && host.autoPrune.mode === 'after-redeploy') {
              checkTriggerAutoPrune(host, emitLog);
            }
          } else {
            emitLog(`\r\n\x1b[31m=== Command failed. Code: ${exitCode}, Signal: ${signal || 'none'} ===\x1b[0m\r\n`);
          }
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ __shipdeck_event: 'exit', code: exitCode, action }));
          }
          conn.end();
          ws.close();
          setTimeout(() => {
            if (ws.readyState === WebSocket.OPEN) ws.close();
          }, 150);
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
  initAutoPruneScheduler();
});
