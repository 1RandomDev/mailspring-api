require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const winston = require('winston');
const crypto = require('crypto');
const sqlite3 = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const API_PORT = 5101;

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp({format: 'YYYY-MM-DD HH:mm:ss'}),
        winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`)
    ),
    transports: [
        new winston.transports.Console()
    ]
});
const app = express();

if(!fs.existsSync('./data')) {
    fs.mkdirSync('./data');
}
const db = sqlite3('./data/mailspring-api.db');
db.transaction(() => {
    db.exec('CREATE TABLE IF NOT EXISTS identities(id VARCHAR PRIMARY KEY, firstName VARCHAR, lastName VARCHAR, emailAddress VARCHAR, passwordHash VARCHAR, createdAt VARCHAR, stripePlan VARCHAR, stripePlanEffective VARCHAR, stripeCustomerId VARCHAR, stripePeriodEnd VARCHAR, featureUsage VARCHAR);');
    db.exec('CREATE TABLE IF NOT EXISTS sessions(token VARCHAR PRIMARY KEY, identityId VARCHAR, lastLogin INTEGER);');
    db.exec('CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, event VARCHAR, object VARCHAR, objectId INTEGER, identityId VARCHAR, accountId VARCHAR, timestamp INTEGER);')
    db.exec('CREATE TABLE IF NOT EXISTS objects(id INTEGER PRIMARY KEY AUTOINCREMENT, object_id VARCHAR, object VARCHAR, object_type VARCHAR, aid VARCHAR, identity_id VARCHAR, plugin_id VARCHAR, v INTEGER, value VARCHAR, timestamp INTEGER);');
    db.exec('CREATE TABLE IF NOT EXISTS shared_activity(id INTEGER PRIMARY KEY AUTOINCREMENT, identityId VARCHAR, key VARCHAR, html VARCHAR, timestamp INTEGER);');
})();
cleanup();

let sessions = [];

app.use(express.json());
app.use(cookieParser());
app.use((req, res, next) => {
    logger.debug(`${req.method} ${req.path}`);
    next();
});
app.use((req, res, next) => {
    const path = req.path;
    if(path.startsWith('/api') || path.startsWith('/metadata') || path.startsWith('/deltas')) {
        if(path == '/api/resolve-dav-hosts') {
            next();
            return;
        }

        if(req.headers.authorization) {
            const auth = req.headers.authorization.split(' ')[1];
            const token = Buffer.from(auth, 'base64').toString().slice(0, -1);

            // Check token
            const identity = verifySession(token);
            if(identity) {
                req.identity = identity;
                next();
            } else {
                res.status(401).header('WWW-Authenticate', 'Basic').json({statusCode: 401, error: 'Unauthorized', message: 'Invalid token'});
            }
        } else {
            res.status(401).header('WWW-Authenticate', 'Basic').json({statusCode: 401, error: 'Unauthorized', message: 'Missing authentication'});
        }
    } else {
        next();
    }
});

// Public
app.get('/', (req, res) => {
    res.sendFile(path.resolve('./static/index.html'));
});
app.get(/\/open\/.+/, (req, res) => {
    res.sendFile(path.resolve('./static/blank.gif'));

    const messageId = req.path.match(/\/open\/(.+)/)[1];
    const accountId = req.query.me;
    const recipient = Buffer.from(req.query.recipient, 'base64').toString();
    
    db.transaction(() => {
        let stmt = db.prepare('SELECT * FROM objects WHERE object = \'metadata\' AND plugin_id = \'open-tracking\' AND aid = ? AND json_extract(value, \'$.uid\') = ?;');
        let object = stmt.get(accountId, messageId);
        
        if(object) {
            object.v++;
            object.value = JSON.parse(object.value);
            object.value.open_count++;
            object.value.open_data.push({
                timestamp: Date.now()/1000,
                recipient: recipient
            });
    
            stmt = db.prepare('UPDATE objects SET v = ?, value = ? WHERE id = ?;');
            stmt.run(object.v, JSON.stringify(object.value), object.id);
    
            emitEvent('modify', object);
        }
    })();
});
app.get(/\/link\/.+\/.+/, (req, res) => {
    const redirectUrl = req.query.redirect;
    if(!redirectUrl) {
        res.status(404).end("Expired or broken link.");
        return;
    }
    res.redirect(redirectUrl);

    const pathValues = req.path.match(/\/link\/(.+)\/(.+)/);
    const messageId = pathValues[1];
    const linkId = pathValues[2];
    const recipient = Buffer.from(req.query.recipient, 'base64').toString();

    db.transaction(() => {
        let stmt = db.prepare('SELECT * FROM objects WHERE object = \'metadata\' AND plugin_id = \'link-tracking\' AND json_extract(value, \'$.uid\') = ?;');
        let object = stmt.get(messageId);

        if(object) {
            object.v++;
            object.value = JSON.parse(object.value);
            const link = object.value.links[linkId];
            if(link) {
                link.click_count++;
                link.click_data.push({
                    timestamp: Date.now()/1000,
                    recipient: recipient
                });

                stmt = db.prepare('UPDATE objects SET v = ?, value = ? WHERE id = ?;');
                stmt.run(object.v, JSON.stringify(object.value), object.id);
        
                emitEvent('modify', object);
            }
        }
    })();
});
app.get(/\/activity\/.+/, (req, res) => {
    const key = req.path.match(/\/activity\/(.+)/)[1];

    const stmt = db.prepare('SELECT html FROM shared_activity WHERE key = ?;');
    const data = stmt.get(key);

    if(data) {
        res.send(data.html);
    } else {
        res.status(404).end('Invalid or expired link.');
    }
});

// Accout related
app.get('/dashboard', (req, res) => {
    res.redirect('/');
});
app.get('/onboarding', (req, res) => {
    const identity = verifySession(req.cookies.session);
    if(identity) {
        const identityEncoded = Buffer.from(JSON.stringify(identity)).toString('base64');
        res.render(path.resolve('./static/onboarding.ejs'), {identityEncoded: identityEncoded});
    } else {
        res.sendFile(path.resolve('./static/login.html'));
    }
});
app.post('/login', (req, res) => {
    if(!req.body) {
        res.status(400).json({statusCode: 400, error: 'Bad Request', message: 'No data provided'});
        return;
    }
    if(!req.body.emailAddress) {
        res.status(400).json({statusCode: 400, error: 'Bad Request', message: 'Key "emailAddress" is required'});
        return;
    }
    if(!req.body.password) {
        res.status(400).json({statusCode: 400, error: 'Bad Request', message: 'Key "password" is required'});
        return;
    }

    const identity = loginUser(req.body.emailAddress, req.body.password);
    if(identity.error) {
        res.status(identity.statusCode);
    } else {
        res.cookie('session', identity.token, {
            secure: true
        });
    }
    res.json(identity);
});

// API
app.post('/api/resolve-dav-hosts', async (req, res) => {
    // Forward to Mailspring API
    try {
        const hosts = await axios.post('https://id.getmailspring.com/api/resolve-dav-hosts', req.body);
        res.json(hosts.data);
    } catch(err) {
        res.status(err.response.status).json(err.response.data);
    }
});
app.post('/api/feature_usage_event', (req, res) => {
    // Don't do anything, unlimitted use of features
    res.json({sucess: true})
});
app.get('/api/me', (req, res) => {
    // Mark session as still active
    const stmt = db.prepare('UPDATE sessions SET lastLogin = ? WHERE token = ?;');
    stmt.run(Math.round(Date.now()/1000), req.identity.token);

    delete req.identity.token;
    res.json(req.identity);
});
app.post('/api/share-static-page', (req, res) => {
    if(!req.body) {
        res.status(400).json({statusCode: 400, error: 'Bad Request', message: 'No data provided'});
        return;
    }
    if(!req.body.html) {
        res.status(400).json({statusCode: 400, error: 'Bad Request', message: 'Key "html" is required'});
        return;
    }

    const key = crypto.randomBytes(30).toString('hex');
    const baseUrl = process.env.SHARE_URL || 'http://localhost:5101';

    const stmt = db.prepare('INSERT INTO shared_activity(identityId, key, html, timestamp) VALUES (?, ?, ?, ?);');
    stmt.run(req.identity.id, key, req.body.html, Math.round(Date.now()/1000));

    res.json({link: baseUrl+'/activity/'+key});
});

// Metadata
app.post(/\/metadata\/.+\/.+\/.+/, (req, res) => {
    const pathValues = req.path.match(/\/metadata\/(.+)\/(.+)\/(.+)/);
    const accountId = pathValues[1];
    const objectId = pathValues[2];
    const pluginId = pathValues[3];

    if(!req.body) {
        res.status(400).json({statusCode: 400, error: 'Bad Request', message: 'No data provided'});
        return;
    }
    if(!req.body.objectType) {
        res.status(400).json({statusCode: 400, error: 'Bad Request', message: 'Key "objectType" is required'});
        return;
    }
    if(!req.body.value) {
        res.status(400).json({statusCode: 400, error: 'Bad Request', message: 'Key "value" is required'});
        return;
    }
    if(!req.body.version) {
        res.status(400).json({statusCode: 400, error: 'Bad Request', message: 'Key "version" is required'});
        return;
    }

    let stmt = db.prepare('SELECT * FROM objects WHERE object = \'metadata\' AND object_id = ? AND object_type = ? AND aid = ? AND plugin_id = ? AND identity_id = ?;');
    let object = stmt.get(objectId, req.body.objectType, accountId, pluginId, req.identity.id);
    
    if(object) {
        // Update
        if(req.body.version >= object.v) {
            object.v++;
            object.value = req.body.value;
            stmt = db.prepare('UPDATE objects SET v = ?, value = ? WHERE object = \'metadata\' AND object_id = ? AND object_type = ? AND aid = ? AND plugin_id = ? AND identity_id = ?;');
            stmt.run(object.v, JSON.stringify(object.value), objectId, req.body.objectType, accountId, pluginId, req.identity.id);
            
            emitEvent('modify', object);
            res.json(object);
        } else {
            res.status(409).json({statusCode: 409, error: 'Conflict', message: 'Version conflict'});
            return;
        }
    } else {
        // Create
        db.transaction(() => {
            stmt = db.prepare('INSERT INTO objects(object_id, object, object_type, aid, identity_id, plugin_id, v, value, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);');
            stmt.run(objectId, 'metadata', req.body.objectType, accountId, req.identity.id, pluginId, 1, JSON.stringify(req.body.value), Math.round(Date.now() / 1000));
            
            stmt = db.prepare('SELECT * FROM objects WHERE id = last_insert_rowid();');
            object = stmt.get();
            object.value = JSON.parse(object.value);
            
            emitEvent('create', object)
            res.json(object);
        })();
    }
});
app.get(/\/metadata\/.+/, (req, res) => {
    const accountId = req.path.match(/\/metadata\/(.+)/)[1];
    const limit = req.query.limit || 500;
    const offset = req.query.offset || 0;
    const stmt = db.prepare('SELECT * FROM objects WHERE object = \'metadata\' AND aid = ? AND identity_id = ? LIMIT ? OFFSET ?;');

    const objects = stmt.all(accountId, req.identity.id, limit, offset);
    objects.forEach(obj => {
        obj.value = JSON.parse(obj.value);
    });
    res.json(objects);
});
app.get(/\/deltas\/.+\/head/, (req, res) => {
    const accountId = req.path.match(/\/deltas\/(.+)\/head/)[1];
    const stmt = db.prepare('SELECT MAX(id) AS cursor FROM events WHERE identityId = ? AND accountId = ?;');
    const data = stmt.get(req.identity.id, accountId);
    res.json({cursor: data.cursor || 0});
});
app.get(/\/deltas\/.+\/streaming/, (req, res) => {
    if(!req.query.cursor) {
        res.status(400).json({statusCode: 400, error: 'Bad Request', message: 'Parameter "cursor" is required'});
        return;
    }
    const session = {
        send: (data) => {
            res.write(data+'\n');
        },
        sessionId: crypto.randomUUID(),
        identityId: req.identity.id,
        accountId: req.path.match(/\/deltas\/(.*)\/streaming/)[1],
        cursor: req.query.cursor
    };

    res.writeHead(200);
    db.transaction(() => {
        let stmt = db.prepare('SELECT * FROM events WHERE identityId = ? AND accountId = ? AND id > ?');
        let events = stmt.all(session.identityId, session.accountId, session.cursor);
        events.forEach(event => {
            event.cursor = event.id.toString();
            stmt = db.prepare('SELECT * FROM objects WHERE id = ?;');
            event.attributes = stmt.get(event.objectId);
            event.attributes.value = JSON.parse(event.attributes.value);

            res.write(JSON.stringify(event)+'\n');
        });
    })();

    // Heartbeat
    const heartbeatIntervall = setInterval(() => {
        res.write('\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n');
    }, 10000);

    // Close after 15min
    const sessionTimeout = setTimeout(() => {
        clearInterval(heartbeatIntervall);
        res.end();
        sessions = sessions.filter(s => s != session);
        logger.debug('Stream closed after 15min: '+JSON.stringify(session));
    }, 900000);

    session.close = () => {
        clearInterval(heartbeatIntervall);
        clearTimeout(sessionTimeout);
        res.end();
        sessions = sessions.filter(s => s != session);
        logger.debug('Stream closed: '+JSON.stringify(session));
    }
    sessions.push(session);

    res.on('close', () => session.close());
    logger.debug('Stream initialized: '+JSON.stringify(session));
});

app.listen(API_PORT, () => {
    logger.info(`Example app listening on port ${API_PORT}`)
});

function emitEvent(eventName, object) {
    db.transaction(() => {
        let stmt = db.prepare('INSERT INTO events(event, object, objectId, identityId, accountId, timestamp) VALUES (?, ?, ?, ?, ?, ?);');
        stmt.run(eventName, object.object, object.id, object.identity_id, object.aid, Math.round(Date.now() / 1000));
    
        stmt = db.prepare('SELECT * FROM events WHERE id = last_insert_rowid();');
        let event = stmt.get();
        event.cursor = event.id.toString();
        event.attributes = object;
        event = JSON.stringify(event);

        sessions.forEach(session => {
            if(session.identityId == object.identity_id && session.accountId == object.aid) {
                session.send(event);
            }
        });
    })();
}

function fetchIdentity(identityId) {
    const stmt = db.prepare('SELECT * FROM identities WHERE id = ?;');
    return stmt.get(identityId);
}
function loginUser(email, password) {
    const stmt = db.prepare('SELECT * FROM identities WHERE emailAddress = ?;');
    const identity = stmt.get(email);

    if(identity) {
        const pwHashSplit = identity.passwordHash.split('.');
        const pwSalt = pwHashSplit[1];
        const correctPwHash = pwHashSplit[0];
        const currentPwHash = crypto.pbkdf2Sync(password, pwSalt, 1000, 64, `sha512`).toString(`hex`);

        if(currentPwHash === correctPwHash) {
            delete identity.passwordHash;
            identity.token = createSession(identity.id);
            identity.featureUsage = JSON.parse(identity.featureUsage);
            return identity;
        } else {
            return {statusCode: 401, error: 'Unauthorized', message: 'Invalid email address or password.'};
        }
    } else {
        return{statusCode: 401, error: 'Unauthorized', message: 'Invalid email address or password.'};
    }
}
function createSession(identityId) {
    const token = crypto.randomUUID();
    const stmt = db.prepare('INSERT INTO sessions(token, identityId, lastLogin) VALUES (?, ?, ?);');
    stmt.run(token, identityId, Math.round(Date.now()/1000));
    return token;
}
function verifySession(token) {
    if(!token) return false;

    const stmt = db.prepare('SELECT * FROM sessions WHERE token = ?;');
    const session = stmt.get(token);
    if(session && session.lastLogin > Date.now()/1000 - 2629800) { // Expired after 1 month of inactivity
        const identity = fetchIdentity(session.identityId);
        delete identity.passwordHash;
        identity.token = token;
        identity.featureUsage = JSON.parse(identity.featureUsage);
        return identity;
    }
    return false;
}

function cleanup() {
    logger.info('Deleting expired sessions...');
    let stmt = db.prepare('DELETE FROM sessions WHERE lastLogin < ?;');
    let result = stmt.run(Date.now()/1000 - 2629800);
    logger.info(`Deleted ${result.changes} sessions`);
}
