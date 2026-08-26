const http = require('http');
const fs = require('fs');

function makeRequest(method, urlPath, body = null) {
    return new Promise((resolve, reject) => {
        const defaultHeaders = {
            'Content-Type': 'application/json',
            'x-dev-user': 'dev-admin',
            'x-dev-role': 'admin',
            'x-dev-groups': 'admins'
        };

        const req = http.request({
            hostname: 'localhost',
            port: 3001,
            path: urlPath,
            method: method,
            headers: defaultHeaders
        }, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, body: data ? JSON.parse(data) : null });
                } catch (e) {
                    resolve({ status: res.statusCode, body: data });
                }
            });
        });

        req.on('error', (err) => reject(err));
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

async function run() {
    console.log('--- STARTING HOST BRANCH & VERSION TESTS ---');
    try {
        // 1. Create a host with a custom branch
        const createRes = await makeRequest('POST', '/api/hosts', {
            name: 'Branch Version Test Host',
            type: 'local',
            projectDir: '.', // Pointing to current dir (a git repo)
            gitUrl: 'https://github.com/expressjs/express.git',
            branch: 'main',
            allowedRole: 'admin'
        });

        console.log('Host creation status:', createRes.status);
        console.log('Host creation branch:', createRes.body.branch);

        if (createRes.status !== 201) {
            throw new Error(`Failed to create host with status ${createRes.status}`);
        }

        const hostId = createRes.body.id;
        if (createRes.body.branch !== 'main') {
            throw new Error(`Expected branch 'main', got: ${createRes.body.branch}`);
        }

        // 2. Ping the host to trigger Git Log scanning
        console.log('Pinging the newly created host...');
        const pingRes = await makeRequest('GET', `/api/hosts/${hostId}/ping`);
        console.log('Ping status:', pingRes.status);
        console.log('Ping body:', pingRes.body);

        if (pingRes.status !== 200) {
            throw new Error(`Failed to ping host, status ${pingRes.status}`);
        }

        if (!pingRes.body.version || pingRes.body.version === 'Unknown' || pingRes.body.version === 'No Git Repository') {
            throw new Error(`Version extraction failed. Got: ${pingRes.body.version}`);
        }

        console.log(`Successfully retrieved active version info: ${pingRes.body.version}`);

        // 3. Clean up the host
        const deleteRes = await makeRequest('DELETE', `/api/hosts/${hostId}`);
        console.log('Clean up status:', deleteRes.status);

        console.log('--- ALL BRANCH & VERSION VERIFICATION TESTS SUCCEEDED ---');
        process.exit(0);
    } catch (err) {
        console.error('Test Suite Failed:', err);
        process.exit(1);
    }
}

run();
