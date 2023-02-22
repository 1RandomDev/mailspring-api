require('dotenv').config();
const express = require('express');
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
db.exec('CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, event VARCHAR, object VARCHAR, objectId VARCHAR, identityId VARCHAR, accountId VARCHAR);')
db.exec('CREATE TABLE IF NOT EXISTS objects(id INTEGER PRIMARY KEY AUTOINCREMENT, object_id VARCHAR, object VARCHAR, object_type VARCHAR, aid VARCHAR, identity_id VARCHAR, plugin_id VARCHAR, v INTEGER, value VARCHAR);');

let sessions = [];
const identity = {
    id: '5237197a-8ae3-4462-aba7-7249d678bd9b',
    token: '5237197a-8ae3-4462-aba7-7249d678bd9b',
    firstName: 'Custom',
    lastName: 'Server',
    emailAddress: 'customserver@example.com',
    object: 'identity',
    createdAt: '2023-01-01T12:00:00.000Z',
    stripePlan: 'Pro',
    stripePlanEffective: 'Pro',
    stripeCustomerId: '',
    stripePeriodEnd: '2023-01-01T12:00:00.000Z',
    featureUsage: {
        snooze: {
            quota: 1000,
            period: 'weekly',
            usedInPeriod: 0,
            featureLimitName: 'pro-limit'
        },
        'send-later': {
            quota: 1000,
            period: 'weekly',
            usedInPeriod: 0,
            featureLimitName: 'pro-limit'
        },
        'thread-sharing': {
            quota: 1000,
            period: 'weekly',
            usedInPeriod: 0,
            featureLimitName: 'pro-limit'
        },
        'link-tracking': {
            quota: 1000,
            period: 'weekly',
            usedInPeriod: 0,
            featureLimitName: 'pro-limit'
        },
        'open-tracking': {
            quota: 1000,
            period: 'weekly',
            usedInPeriod: 0,
            featureLimitName: 'pro-limit'
        },
        'contact-profiles': {
            quota: 1000,
            period: 'weekly',
            usedInPeriod: 0,
            featureLimitName: 'pro-limit'
        },
        'send-reminders': {
            quota: 1000,
            period: 'weekly',
            usedInPeriod: 0,
            featureLimitName: 'pro-limit'
        },
        translation: {
            quota: 1000,
            period: 'weekly',
            usedInPeriod: 0,
            featureLimitName: 'pro-limit'
        }
    }
};

app.use(express.json());
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

        const authheader = req.headers.authorization;
        if(authheader) {
            const auth = authheader.split(' ')[1];
            const token = Buffer.from(auth, 'base64').toString();
            // TODO: Implement propper authentication with database
            if(token.slice(0, -1) === identity.token) {
                req.identity = identity;
                next();
            } else {
                res.status(401).json({statusCode: 401, error: 'Unauthorized', message: 'Invalid token'});
            }
        } else {
            res.status(401).json({statusCode: 401, error: 'Unauthorized', message: 'Missing authentication'});
        }
    } else {
        next();
    }
});

app.get('/', (req, res) => {
    res.end();
});
app.get('/onboarding', (req, res) => {
    const identityEncoded = Buffer.from(JSON.stringify(identity)).toString('base64');
    res.send(`<!DOCTYPE html>
<html>
    <body>
        <div id="identity-result" style="display:none;">${identityEncoded}</div>
    </body>
</html>`);
});
app.get(/\/open\/.+/, (req, res) => {
    const messageId = req.path.match(/\/open\/(.+)/)[1];
    const accountId = req.query.me;
    const recipient = Buffer.from(req.query.recipient, 'base64').toString();
    console.log(messageId, accountId, recipient);
    

    res.sendFile(path.resolve('./blank.gif'));
});

// API
app.post('/api/resolve-dav-hosts', async (req, res) => {
    try {
        const hosts = await axios.post('https://id.getmailspring.com/api/resolve-dav-hosts', req.body);
        res.json(hosts.data);
    } catch(err) {
        res.status(err.response.status).json(err.response.data);
    }
});
app.get('/api/me', (req, res) => {
    res.json(identity);
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
            res.json(object);
        } else {
            res.status(409).json({statusCode: 409, error: 'Conflict', message: 'Version conflict'});
            return;
        }
    } else {
        // Create
        db.transaction(() => {
            stmt = db.prepare('INSERT INTO objects(object_id, object, object_type, aid, identity_id, plugin_id, v, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?);');
            stmt.run(objectId, 'metadata', req.body.objectType, accountId, req.identity.id, pluginId, 1, JSON.stringify(req.body.value));
            
            stmt = db.prepare('SELECT * FROM objects WHERE id = last_insert_rowid();');
            object = stmt.get();
            object.value = JSON.parse(object.value);
            res.json(object);
        })();
    }
});
app.get(/\/metadata\/.+/, (req, res) => {
    const accountId = req.path.match(/\/metadata\/(.+)/)[1];
    const limit = req.query.limit || 500;
    const offset = req.query.offset || 0;
    const stmt = db.prepare('SELECT data FROM metadata WHERE identityId = ? AND accountId = ? LIMIT ? OFFSET ?;');

    const entries = [];
    stmt.all(req.identity.id, accountId, limit, offset).forEach(row => {
        entries.push(JSON.parse(row.data));
    });
    res.json(entries);
});
app.get(/\/deltas\/.+\/head/, (req, res) => {
    const accountId = req.path.match(/\/deltas\/(.+)\/head/)[1];
    const stmt = db.prepare('SELECT MAX(cursor) AS cursor FROM metadata WHERE identityId = ? AND accountId = ?;');
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
    const stmt = db.prepare('SELECT cursor, data FROM metadata WHERE identityId = ? AND accountId = ? AND cursor > ?');
    stmt.all(session.identityId, session.accountId, session.cursor).forEach(row => {
        const data = JSON.parse(row.data);
        res.write(JSON.stringify({
            object: 'metadata',
            cursor: row.cursor.toString(),
            attributes: data
        })+'\n');
    });

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
    logger.debug('Stream initialized: '+JSON.stringify(session));
});

app.listen(API_PORT, () => {
    logger.info(`Example app listening on port ${API_PORT}`)
});
