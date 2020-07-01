import express from 'express';
import session from 'express-session';
import sessionStore from 'express-session-rsdb';
import axios from 'axios';
import dotenv from 'dotenv';
import winston from 'winston';

const app = express();

dotenv.config();

const {
    CLIENT_ID,
    CLIENT_SECRET,
    APP_SCOPE,
    APP_URI,
    SERVER_PORT,
    SESSION_KEY,
    VERIFY_TOKEN,
    OAUTH_PATH,
    SUB_PATH,
    SESSION_STORAGE_DIR,
    NODE_ENV,
    SLACK_WEBHOOK
} = process.env;

let subscriptionId;

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    // defaultMeta: { service: 'user-service' },
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'warning' }),
    ],
});

//
// If we're not in production then log to the `console` with the format:
// `${info.level}: ${info.message} JSON.stringify({ ...rest }) `
//
if (NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.simple(),
    }));
}

app.use(express.json());

app.use(session({
    store: new sessionStore({
        data_storage_area: SESSION_STORAGE_DIR,
    }),
    secret: SESSION_KEY,
    secure: NODE_ENV === 'production',
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 30
    }
}));

app.get( '/', async (req, res) => {
    if (!req.session.data && CLIENT_ID && APP_URI) {
        return res.send(`
            <a href="https://www.strava.com/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${APP_URI}${OAUTH_PATH}&response_type=code&scope=${APP_SCOPE}">
                Login with Strava
            </a>
        `);
    }

    return res.send(`Already authenticated!`);
});

app.get(OAUTH_PATH, async (req, res) => {
    const { scope, code } = req.query;

    if (scope.indexOf(APP_SCOPE) === -1) {
        res.statusMessage = 'Scope not granted.';
        return res.status(400).end('Scope not granted.');
    }

    if (!code) {
        res.statusMessage = 'Code not provided.';
        return res.status(400).end('Code not provided.');
    }

    try {
        const response = await getAccessToken(code, 'authorization_code');
        setSessionData(response.data, req.session);
        res.redirect(302, `${APP_URI}`);
    } catch (error) {
        logger.error(JSON.stringify(error));
        res.statusMessage = 'Missing access token';
        res.status(400).end('Unable to retrieve access token.');
    }
});

app.get(SUB_PATH, (req, res) => {
    const { 'hub.challenge': hubChallenge, 'hub.mode': hubMode, 'hub.verify_token': hubToken } = req.query;
    if (hubMode === 'subscribe' && hubToken === VERIFY_TOKEN) {
        res.send({ 'hub.challenge': hubChallenge });
    }
});

app.post(SUB_PATH, async (req, res) => {
    if (
        req.body.object_type !== 'activity' ||
        req.body.aspect_type !== 'create' ||
        req.body.subscription_id !== subscriptionId
    ) {
        res.status(200).end();
    }

    req.sessionStore.all((error, sessions) => {
        let session = sessions.find(session => session.data.athleteId === req.body.owner_id);
        if (session) {
            const date = new Date();
            if (session.data.expires_at <= date.getTime()) {
                try {
                    const response = getAccessToken(session.data.refresh_token, 'refresh_token');
                    session = setSessionData(response.data, session);
                    req.sessionStore.touch(session.data.id, session, error => logger.error(JSON.stringify(error)));
                } catch (error) {
                    logger.error(JSON.stringify(error.response.data));
                }
            }
            sendActivity(session, req.body.object_id);
            res.status(200).end();
        }
    });
});

const server = app.listen(SERVER_PORT, async () => {
    logger.info(`Example app listening at ${APP_URI}`)
    subscriptionId = await subscriptionCheck();
})

async function getAccessToken(code, grantType) {
    let grantParams;
    if (grantType === 'authorization_code') {
        grantParams = `&code=${code}&grant_type=${grantType}`;
    } else if (grantType === 'refresh_token') {
        grantParams = `&refresh_token=${code}&grant_type=${grantType}`
    }

    return await axios({
        method: 'post',
        url: `https://www.strava.com/api/v3/oauth/token?client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&${grantParams}`,
        headers: {
            accept: 'application/json'
        }
    });
}

function setSessionData(data, session) {
    if (data && data.access_token) {
        if (!session.data) {
            session.data = {};
        }

        session.data.access_token = data.access_token;
        session.data.refresh_token = data.refresh_token;
        session.data.expires_at = new Date().getTime() + (data.expires_in * 1000);
        session.data.expires_in = data.expires_in;
        session.data.token_type = data.token_type;
        if (session.id) {
            session.data.id = session.id;
        }
        if (data.athlete) {
            if (data.athlete.id) {
                session.data.athleteId = data.athlete.id;
            }
            if (data.athlete.firstname) {
                session.data.firstname = data.athlete.firstname;
            }
        }
    }

    return session;
}

async function subscriptionCheck() {
    try {
        const response = await axios({
            method: 'get',
            url: `https://www.strava.com/api/v3/push_subscriptions?client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}`,
            headers: {
                accept: 'application/json'
            }
        })
        logger.info(JSON.stringify(response.data));
        if (response.data.length === 0) {
            return await createSubscription();
        }
        return response.data[0].id;
    } catch (error) {
        logger.error(`${JSON.stringify(error.response.data)}`);
    }
}

async function createSubscription() {
    try {
        const response = await axios({
            method: 'post',
            url: `https://www.strava.com/api/v3/push_subscriptions?client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&callback_url=${APP_URI}${SUB_PATH}&verify_token=${VERIFY_TOKEN}`,
            headers: {
                accept: 'application/json'
            }
        });
        logger.info(`Subscription created: ${JSON.stringify(response.data)}`);
        return response.data.id;
    } catch (error) {
        logger.error(`Failed to create subscription: ${JSON.stringify(error.response.data)}`);
        server.close(() => {
            logger.info('Shutting down.');
        });
    }
}

async function sendActivity(session, activityId) {
    setTimeout(() => {
        axios({
            type: 'get',
            url: `https://www.strava.com/api/v3/activities/${activityId}`,
            headers: {
                Authorization: `Bearer ${session.data.access_token}`
            }
        })
        .then(response => {
            const { data } = response;
            const minutes = Math.floor(data.moving_time / 60);
            const seconds = data.moving_time - (minutes * 60);
            const { firstname } = session.data;
            const message = {
                blocks: [
                    {
                        type: 'section',
                        text: {
                            type: 'mrkdwn',
                            text: `*${data.name}*\n${firstname} did a ${(data.distance / 1000).toFixed(1)}km
                                ${data.type} in ${minutes}:${seconds >= 10 ? seconds : seconds === 0 ? `00` : `0${seconds}`} and gained ${data.total_elevation_gain}m
                                (${Math.round(data.total_elevation_gain * 3.28084)}ft.) in elevation :mountain:.
                                ${firstname} hit a max speed of ${(data.max_speed * 3.6).toFixed(1)}kph.`
                        }
                    }
                ]
            };
            if (data.photos.count > 0) {
                message.blocks[0].accessory = {
                    type: 'image',
                    image_url: data.photos.primary.urls[100]
                }
            }
            axios({
                type: 'post',
                url: SLACK_WEBHOOK,
                data: message
            })
            .then(() => {
                logger.info('Message sent.');
            })
            .catch(slackError => {
                logger.error(JSON.stringify(slackError.response.data));
            })
        })
        .catch(error => logger.error(`Failed to get activity: ${JSON.stringify(error.response.data)}`));
    }, 1000);
}
