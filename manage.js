#!/usr/bin/env node

const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const readline = require("readline-sync");
const sqlite3 = require('better-sqlite3');
const crypto = require('crypto');

const argv = yargs(hideBin(process.argv))
    .detectLocale(false)
    .strict()
    .alias('h', 'help')
    .alias('v', 'version')
    .demandCommand(1)
    .command('user <operation> [options]', 'Magage user accounts.', (yargs) => {
        return yargs.command('add [options]', 'Create a new user.', (yargs) => {
            return yargs.option('fullName', {
                alias: 'n',
                require: true
            }).option('email', {
                alias: 'e',
                require: true
            }).option('password', {
                alias: 'p',
                require: true
            });
        }).command('delete [options]', 'Delete a user.', (yargs) => {
            return yargs.option('email', {
                alias: 'e',
                require: true
            });
        }).command('changepw [options]', 'Change the password of a user.', (yargs) => {
            return yargs.option('email', {
                alias: 'e',
                require: true
            }).option('newPassword', {
                alias: 'p'
            });
        }).command('info [options]', 'Show details about a user.', (yargs) => {
            return yargs.option('email', {
                alias: 'e',
                conflicts: 'id'
            }).options('id', {
                alias: 'i',
                conflicts: 'email'
            }).check(({email, id}) => {
                if(!email && !id) {
                    throw new Error('One of the following option is required: email, id');
                }
                return true;
            });
        }).command('list', 'List all users.', (yargs) => {
            return yargs.option('json', {
                alias: 'j'
            });
        });
    })
    .argv;

const db = sqlite3('./data/mailspring-api.db');
db.transaction(() => {
    db.exec('CREATE TABLE IF NOT EXISTS identities(id VARCHAR PRIMARY KEY, firstName VARCHAR, lastName VARCHAR, emailAddress VARCHAR, passwordHash VARCHAR, createdAt VARCHAR, stripePlan VARCHAR, stripePlanEffective VARCHAR, stripeCustomerId VARCHAR, stripePeriodEnd VARCHAR, featureUsage VARCHAR);');
    db.exec('CREATE TABLE IF NOT EXISTS sessions(token VARCHAR PRIMARY KEY, identityId VARCHAR, lastLogin INTEGER);');
    db.exec('CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, event VARCHAR, object VARCHAR, objectId INTEGER, identityId VARCHAR, accountId VARCHAR, timestamp INTEGER);')
    db.exec('CREATE TABLE IF NOT EXISTS objects(id INTEGER PRIMARY KEY AUTOINCREMENT, object_id VARCHAR, object VARCHAR, object_type VARCHAR, aid VARCHAR, identity_id VARCHAR, plugin_id VARCHAR, v INTEGER, value VARCHAR, timestamp INTEGER);');
    db.exec('CREATE TABLE IF NOT EXISTS shared_pages(id INTEGER PRIMARY KEY AUTOINCREMENT, identityId VARCHAR, key VARCHAR, html VARCHAR, timestamp INTEGER);');
    db.exec('CREATE TABLE IF NOT EXISTS shared_assets(id INTEGER PRIMARY KEY AUTOINCREMENT, identityId VARCHAR, key VARCHAR, filename VARCHAR, filetype VARCHAR, file BLOB, timestamp INTEGER);');
})();

switch(argv._[0]) {
    case 'user':
        manageUsers();
        break;
}

db.close();


function manageUsers() {
    switch(argv._[1]) {
        case 'add':
            db.transaction(() => {
                let stmt = db.prepare('SELECT id FROM identities WHERE emailAddress = ?;');
                let identity = stmt.get(argv.email);
                if(identity) {
                    console.log('Email address already in use.');
                    return;
                }
                const identityId = crypto.randomUUID();
                
                let date = new Date();
                date.setMilliseconds(0);
                date = date.toISOString();
                const fullNameSplit = argv.fullName.split(' ');
                const passwordHash = hashPassword(argv.password.toString());
                identity = {
                    id: identityId,
                    firstName: fullNameSplit[0],
                    lastName: fullNameSplit[1] || '',
                    emailAddress: argv.email,
                    passwordHash: passwordHash,
                    object: 'identity',
                    createdAt: date,
                    stripePlan: 'Pro',
                    stripePlanEffective: 'Pro',
                    stripeCustomerId: identityId,
                    stripePeriodEnd: date,
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
                }
            
                stmt = db.prepare('INSERT INTO identities(id, firstName, lastName, emailAddress, passwordHash, createdAt, stripePlan, stripePlanEffective, stripeCustomerId, stripePeriodEnd, featureUsage) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);');
                stmt.run(identity.id, identity.firstName, identity.lastName, identity.emailAddress, identity.passwordHash, identity.createdAt, identity.stripePlan, identity.stripePlanEffective, identity.stripeCustomerId, identity.stripePeriodEnd, JSON.stringify(identity.featureUsage));
        
                delete identity.passwordHash;
                console.log('Created user:');
                console.log(JSON.stringify(identity, null, 4));
            })();
            break;

        case 'delete':
            db.transaction(() => {
                let stmt = db.prepare('SELECT id, firstName, lastName FROM identities WHERE emailAddress = ?;');
                let identity = stmt.get(argv.email);
                if(!identity) {
                    console.log('There is no user with this email address.');
                    return;
                }

                stmt = db.prepare('DELETE FROM objects WHERE identity_id = ?;');
                stmt.run(identity.id);

                stmt = db.prepare('DELETE FROM events WHERE identityId = ?;');
                stmt.run(identity.id);

                stmt = db.prepare('DELETE FROM shared_pages WHERE identityId = ?;');
                stmt.run(identity.id);

                stmt = db.prepare('DELETE FROM shares_assets WHERE identityId = ?;');
                stmt.run(identity.id);

                stmt = db.prepare('DELETE FROM sessions WHERE identityId = ?;');
                stmt.run(identity.id);

                stmt = db.prepare('DELETE FROM identities WHERE id = ?;');
                stmt.run(identity.id);

                console.log(`Deleted user "${identity.firstName} ${identity.lastName}"`);
            })();
            break;
        
        case 'changepw':
            db.transaction(() => {
                let stmt = db.prepare('SELECT id, firstName, lastName FROM identities WHERE emailAddress = ?;');
                let identity = stmt.get(argv.email);
                if(!identity) {
                    console.log('There is no user with this email address.');
                    return;
                }

                let newPassword = argv.newPassword;
                if(!newPassword) {
                    newPassword = readline.question('Please enter a new password: ', {hideEchoBack: true});
                }

                stmt = db.prepare('UPDATE identities SET passwordHash = ? WHERE id = ?;');
                stmt.run(hashPassword(newPassword.toString()), identity.id);

                stmt = db.prepare('DELETE FROM sessions WHERE identityId = ?;');
                stmt.run(identity.id);

                console.log(`Updated password for user "${identity.firstName} ${identity.lastName}"`);
            })();
            break;

        case 'info':
            db.transaction(() => {
                let stmt = db.prepare(`SELECT * FROM identities WHERE ${argv.id ? 'id' : 'emailAddress'} = ?;`);
                let identity = stmt.get(argv.id || argv.email);
                if(!identity) {
                    console.log('There is no user with this id or email address.');
                    return;
                }

                delete identity.passwordHash;
                identity.featureUsage = JSON.parse(identity.featureUsage);

                console.log(JSON.stringify(identity, null, 4));
            })();
            break;

        case 'list':
            db.transaction(() => {
                let stmt = db.prepare('SELECT * FROM identities;');
                let identitys = stmt.all();
                
                if(identitys.length == 0) {
                    console.log('No users registered yet.');
                    return;
                }

                if(argv.json) {
                    identitys.forEach(identity => {
                        delete identity.passwordHash;
                        identity.featureUsage = JSON.parse(identity.featureUsage);
                    });
                    console.log(JSON.stringify(identitys, null, 4));
                } else {
                    console.log('All registered users:');
                    identitys.forEach(identity => {
                        console.log(`- ${identity.firstName} ${identity.lastName} | ${identity.emailAddress} | ${identity.id}`);
                    });
                }
            })();
            break;
    }
}

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return hash+'.'+salt;
}

process.on('SIGINT', () => {
    process.exit();
});
