const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

try {
    process.loadEnvFile(path.join(__dirname, '.env'));
} catch (error) {
    console.log('No .env file found — using environment variables / defaults');
}

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const PORTAL_PASSWORD = process.env.PORTAL_PASSWORD || 'portal123';

// ==================== ENCRYPTION ====================
if (!process.env.ENCRYPTION_KEY) {
    console.warn('⚠️  ENCRYPTION_KEY not set — using an insecure default. Set ENCRYPTION_KEY in production.');
}
const ENCRYPTION_KEY = crypto.createHash('sha256')
    .update(process.env.ENCRYPTION_KEY || 'dev-only-insecure-default-key-change-me')
    .digest();
const ENC_PREFIX = 'enc:';

function encryptValue(value) {
    if (value === undefined || value === null || value === '') return value;
    if (typeof value === 'string' && value.startsWith(ENC_PREFIX)) return value; // already encrypted

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    const ciphertext = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return ENC_PREFIX + Buffer.concat([iv, authTag, ciphertext]).toString('base64');
}

function decryptValue(value) {
    if (typeof value !== 'string' || !value.startsWith(ENC_PREFIX)) return value; // legacy plaintext passthrough

    try {
        const raw = Buffer.from(value.slice(ENC_PREFIX.length), 'base64');
        const iv = raw.subarray(0, 12);
        const authTag = raw.subarray(12, 28);
        const ciphertext = raw.subarray(28);
        const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
        decipher.setAuthTag(authTag);
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    } catch (error) {
        console.error('Decryption failed:', error.message);
        return null;
    }
}

function encryptCredentials(credentials) {
    return (credentials || []).map(cred => ({
        ...cred,
        password: encryptValue(cred.password),
        extraFields: (cred.extraFields || []).map(field =>
            field.masked ? { ...field, value: encryptValue(field.value) } : field
        )
    }));
}

// ==================== SESSION MANAGEMENT ====================
const sessions = {
    admin: {},
    portal: {}
};

function generateSessionId() {
    return Math.random().toString(36).substr(2, 9);
}

function isValidSession(sessionId, type = 'admin') {
    return sessions[type] && sessions[type][sessionId] !== undefined;
}

// ==================== FILE OPERATIONS ====================
function readData() {
    try {
        const data = fs.readFileSync(DATA_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading data.json:', error.message);
        return [];
    }
}

function writeData(data) {
    try {
        fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 4), 'utf8');
        return true;
    } catch (error) {
        console.error('Error writing to data.json:', error.message);
        return false;
    }
}

// ==================== AUTHENTICATION MIDDLEWARE ====================
function requireAuth(sessionId, type = 'admin') {
    return isValidSession(sessionId, type);
}

// ==================== SERVER ====================
const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const query = parsedUrl.query;

    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // Handle preflight
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    // ==================== ROUTES ====================

    // GET / - Serve frontend.html
    if (pathname === '/' || pathname === '/frontend.html') {
        fs.readFile(path.join(__dirname, 'frontend.html'), 'utf8', (err, data) => {
            if (err) {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('404 - File not found');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
        return;
    }

    // GET /login.html
    if (pathname === '/login.html') {
        fs.readFile(path.join(__dirname, 'login.html'), 'utf8', (err, data) => {
            if (err) {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('404 - File not found');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
        return;
    }

    // GET /management.html
    if (pathname === '/management.html') {
        fs.readFile(path.join(__dirname, 'management.html'), 'utf8', (err, data) => {
            if (err) {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('404 - File not found');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
        return;
    }

    // GET /css/styles.css
    if (pathname === '/css/styles.css') {
        fs.readFile(path.join(__dirname, 'css', 'styles.css'), 'utf8', (err, data) => {
            if (err) {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('404 - File not found');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/css' });
            res.end(data);
        });
        return;
    }

    // GET /data.json
    if (pathname === '/data.json') {
        const data = readData();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
        return;
    }

    // ==================== ADMIN AUTH API ====================

    // POST /api/auth/admin/login - Admin login
    if (pathname === '/api/auth/admin/login' && req.method === 'POST') {
        let body = '';

        req.on('data', chunk => {
            body += chunk.toString();
        });

        req.on('end', () => {
            try {
                const credentials = JSON.parse(body);
                const password = credentials.password;

                if (password === ADMIN_PASSWORD) {
                    const sessionId = generateSessionId();
                    sessions.admin[sessionId] = {
                        createdAt: Date.now(),
                        expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
                    };

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: true, 
                        sessionId: sessionId,
                        message: 'Admin login successful'
                    }));
                } else {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: false, 
                        error: 'Invalid password' 
                    }));
                }
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: error.message }));
            }
        });
        return;
    }

    // ==================== PORTAL AUTH API ====================

    // POST /api/auth/portal/login - Portal login
    if (pathname === '/api/auth/portal/login' && req.method === 'POST') {
        let body = '';

        req.on('data', chunk => {
            body += chunk.toString();
        });

        req.on('end', () => {
            try {
                const credentials = JSON.parse(body);
                const password = credentials.password;

                if (password === PORTAL_PASSWORD) {
                    const sessionId = generateSessionId();
                    sessions.portal[sessionId] = {
                        createdAt: Date.now(),
                        expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
                    };

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: true, 
                        sessionId: sessionId,
                        message: 'Portal login successful'
                    }));
                } else {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: false, 
                        error: 'Invalid password' 
                    }));
                }
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: error.message }));
            }
        });
        return;
    }

    // POST /api/auth/logout - Logout (admin or portal)
    if (pathname === '/api/auth/logout' && req.method === 'POST') {
        let body = '';

        req.on('data', chunk => {
            body += chunk.toString();
        });

        req.on('end', () => {
            try {
                const { sessionId, type } = JSON.parse(body);
                const sessionType = type || 'admin';
                if (sessions[sessionType]) {
                    delete sessions[sessionType][sessionId];
                }

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, message: 'Logout successful' }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: error.message }));
            }
        });
        return;
    }

    // GET /api/auth/verify - Verify session
    if (pathname === '/api/auth/verify' && req.method === 'GET') {
        const sessionId = query.sessionId;
        const type = query.type || 'admin';
        const valid = requireAuth(sessionId, type);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ valid: valid }));
        return;
    }

    // POST /api/decrypt - Decrypt a masked credential value (admin or portal)
    if (pathname === '/api/decrypt' && req.method === 'POST') {
        const sessionId = query.sessionId;

        if (!requireAuth(sessionId, 'admin') && !requireAuth(sessionId, 'portal')) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized' }));
            return;
        }

        let body = '';

        req.on('data', chunk => {
            body += chunk.toString();
        });

        req.on('end', () => {
            try {
                const { value } = JSON.parse(body);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ value: decryptValue(value) }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: error.message }));
            }
        });
        return;
    }

    // ==================== APPLICATIONS API ====================

    // GET /api/applications
    if (pathname === '/api/applications' && req.method === 'GET') {
        const data = readData();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
        return;
    }

    // POST /api/applications - Add new application (admin only)
    if (pathname === '/api/applications' && req.method === 'POST') {
        const sessionId = query.sessionId;
        
        if (!requireAuth(sessionId, 'admin')) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized' }));
            return;
        }

        let body = '';

        req.on('data', chunk => {
            body += chunk.toString();
        });

        req.on('end', () => {
            try {
                const newApp = JSON.parse(body);
                const applications = readData();

                // Validate required fields
                if (!newApp.name || !newApp.icon || !Array.isArray(newApp.categories) || newApp.categories.length === 0 || !newApp.url || !Array.isArray(newApp.credentials) || newApp.credentials.length === 0) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Missing required fields' }));
                    return;
                }

                // Add new app (masked credential values are encrypted at rest)
                newApp.credentials = encryptCredentials(newApp.credentials);
                applications.push(newApp);

                if (writeData(applications)) {
                    res.writeHead(201, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, message: 'Application added' }));
                } else {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Failed to save data' }));
                }
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: error.message }));
            }
        });
        return;
    }

    // PUT /api/applications/:id - Update application (admin only)
    if (pathname.startsWith('/api/applications/') && req.method === 'PUT') {
        const sessionId = query.sessionId;
        
        if (!requireAuth(sessionId, 'admin')) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized' }));
            return;
        }

        const id = parseInt(pathname.split('/')[3]);
        let body = '';

        req.on('data', chunk => {
            body += chunk.toString();
        });

        req.on('end', () => {
            try {
                const updatedApp = JSON.parse(body);
                let applications = readData();

                // Find and update application
                const index = applications.findIndex(app => app.id === id);
                if (index === -1) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Application not found' }));
                    return;
                }

                if (updatedApp.credentials) {
                    updatedApp.credentials = encryptCredentials(updatedApp.credentials);
                }
                applications[index] = { ...applications[index], ...updatedApp, id: id };

                if (writeData(applications)) {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, message: 'Application updated' }));
                } else {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Failed to save data' }));
                }
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: error.message }));
            }
        });
        return;
    }

    // DELETE /api/applications/:id - Delete application (admin only)
    if (pathname.startsWith('/api/applications/') && req.method === 'DELETE') {
        const sessionId = query.sessionId;
        
        if (!requireAuth(sessionId, 'admin')) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized' }));
            return;
        }

        const id = parseInt(pathname.split('/')[3]);
        let applications = readData();

        // Find and remove application
        const index = applications.findIndex(app => app.id === id);
        if (index === -1) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Application not found' }));
            return;
        }

        applications.splice(index, 1);

        if (writeData(applications)) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, message: 'Application deleted' }));
        } else {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Failed to save data' }));
        }
        return;
    }

    // 404 - Not found
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('404 - Not found');
});

server.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║    🏢 Millennium Radius Portal Server Started              ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  Server running on: http://localhost:${PORT}              
║                                                            ║
║  🏠 Portal:  http://localhost:${PORT}                     
║  ⚙️  Admin:   http://localhost:${PORT}/management.html   
║                                                            ║
║  Authentication:                                           ║
║    ✓ Portal password: ${PORTAL_PASSWORD}                    
║    ✓ Admin password: ${ADMIN_PASSWORD}                      
║    ✓ Session management (24 hours)                        ║
║    ✓ Environment variable support                         ║
║                                                            ║
║  Serving:                                                  ║
║    ✓ frontend.html (Portal UI with login)                 ║
║    ✓ management.html (Admin Console with login)           ║
║    ✓ data.json (Application Database)                     ║
║    ✓ /api/auth/* (Authentication endpoints)               ║
║    ✓ /api/applications/* (CRUD API)                       ║
║                                                            ║
╠════════════════════════════════════════════════════════════╣
║  Press Ctrl+C to stop the server                          ║
╚════════════════════════════════════════════════════════════╝
    `);
});
