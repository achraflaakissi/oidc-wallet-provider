const express = require('express');
const assert = require('assert');
const { Provider } = require('oidc-provider');
const bodyParser = require('body-parser');
const path = require('path');
const { DynamoDB } = require('aws-sdk');
const Adapter = require('./adapter');
const axios = require('axios');
const AWSCognito = require('amazon-cognito-identity-js');
// Adapter.setConfig({
//     // When running on lambda, parameters are unnecessary because using environment variables.
//     dynamoDB: new DynamoDB({ region: 'us-east-1' }),
//     tableName: 'oidc-provider'
// })


const app = express();

const parse = bodyParser.urlencoded({ extended: false });

// simple account model for this application, user list is defined like so
const Account = require('./account');

function setNoCache(req, res, next) {
    res.set('Pragma', 'no-cache');
    res.set('Cache-Control', 'no-cache, no-store');
    next();
}
const registerUser = (email) => {
    return new Promise((resolve, reject) => {
        const poolData = {
            UserPoolId: 'us-east-1_ZxDPgYtkZ',
            ClientId: '77gj6vhlfl6sscljnpnejj2li3',
            // Storage: new AWSCognito.CookieStorage({domain: '.wonderbnb.com'})
        };

        const userPool = new AWSCognito.CognitoUserPool(poolData);

        if (!email) {
            reject('Required fields are missing.');
            return;
        } else {
            email = email.toLocaleLowerCase();

            const attributeList = [];
            attributeList.push(new AWSCognito.CognitoUserAttribute({ Name: 'email', Value: email }));
            userPool.signUp(email, 'AAaa001#####', attributeList, null, (err, result) => {
                if (err) {
                    reject(err);
                    return;
                }
                const cognitoUser = result.user;
                resolve('Signup successful: ' + JSON.stringify(result.user));
            });
        }

    });
}
//Middlewares
app.use(express.static(__dirname + '/public'));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static("public"));
const configuration = {
    adapter: Adapter,
    clients: [],
    pkce: {
        required: () => false,
    },
    interactions: {
        url(ctx, interaction) {
            return `/interaction/${interaction.uid}`;
        },
    },
    features: {
        // disable the packaged interactions
        devInteractions: { enabled: false },
    },
    // let's tell oidc-provider you also support the email scope, which will contain email and
    // email_verified claims
    claims: {
        openid: ['sub'],
        email: ['email', 'email_verified'],
    },
    // oidc-provider only looks up the accounts by their ID when it has to read the claims,
    // passing it our Account model method is sufficient, it should return a Promise that resolves
    // with an object with accountId property and a claims method.
    findAccount: Account.findAccount,
};

app.get('/interaction/:uid', setNoCache, async (req, res, next) => {
    try {
        const details = await oidc.interactionDetails(req, res);
        // console.log('see what else is available to you for interaction views', details);
        const {
            uid, prompt, params,
        } = details;
        console.log('verify if the user exist ....')
        const client = await oidc.Client.find(params.client_id);

        if (prompt.name === 'login') {
            return res.render('login', {
                client,
                uid,
                details: prompt.details,
                params,
                title: 'Sign-in',
                flash: undefined,
            });
        }

        return res.render('interaction', {
            client,
            uid,
            details: prompt.details,
            params,
            title: 'Authorize',
        });
    } catch (err) {
        return next(err);
    }
});
app.post('/interaction/:uid/confirm', setNoCache, parse, async (req, res, next) => {
    try {
        const interactionDetails = await oidc.interactionDetails(req, res);
        console.log('interactionDetails', interactionDetails);
        const { prompt: { name, details }, params, session: { accountId } } = interactionDetails;
        assert.strictEqual(name, 'consent');

        let { grantId } = interactionDetails;
        let grant;

        if (grantId) {
            // we'll be modifying existing grant in existing session
            grant = await oidc.Grant.find(grantId);
        } else {
            // we're establishing a new grant
            grant = new oidc.Grant({
                accountId,
                clientId: params.client_id,
            });
        }
        console.log('details.missingOIDCScope', details.missingOIDCScope);
        console.log('details', details);
        if (details.missingOIDCScope) {
            grant.addOIDCScope(details.missingOIDCScope.join(' '));
            // use grant.rejectOIDCScope to reject a subset or the whole thing
        }
        if (details.missingOIDCClaims) {
            grant.addOIDCClaims(details.missingOIDCClaims);
            // use grant.rejectOIDCClaims to reject a subset or the whole thing
        }
        if (details.missingResourceScopes) {
            console.log('missingResourceScopes', missingResourceScopes);
            // eslint-disable-next-line no-restricted-syntax
            for (const [indicator, scopes] of Object.entries(details.missingResourceScopes)) {
                console.log('indicator', indicator);
                grant.addResourceScope(indicator, scopes.join(' '));
                // use grant.rejectResourceScope to reject a subset or the whole thing
            }
        }

        grantId = await grant.save();

        const consent = {};
        if (!interactionDetails.grantId) {
            // we don't have to pass grantId to consent, we're just modifying existing one
            consent.grantId = grantId;
        }

        const result = { consent };
        await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
    } catch (err) {
        next(err);
    }
});

app.post('/interaction/:uid/login', setNoCache, parse, async (req, res, next) => {
    try {
        const { uid, prompt, params } = await oidc.interactionDetails(req, res);
        assert.strictEqual(prompt.name, 'login');
        const client = await oidc.Client.find(params.client_id);

        const accountId = await Account.authenticate(req.body.address, req.body.signedMessage, uid, req.body.nounce);
        console.log('accountId ============>', accountId);
        // const resp = await axios.post(`https://v900e2c4ig.execute-api.us-east-1.amazonaws.com/dev/findUserMaiToWallet`, { email: accountId + '@mailtowallet.com' });
        // console.log('resp', resp.data.response);
        // if (resp.data.response && resp.data.response.Item) {
        //     console.log('the user exist')
        // } else {
        //     await registerUser(accountId + '@mailtowallet.com');
        // }
        if (!accountId) {
            res.render('login', {
                client,
                uid,
                details: prompt.details,
                params: {
                    ...params,
                    login_hint: req.body.address,
                },
                title: 'Sign-in',
                flash: 'Invalid signing, Please try again.',
            });
            return;
        }

        const result = {
            login: { accountId },
        };

        await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
        next(err);
    }
});

app.get('/interaction/:uid/abort', setNoCache, async (req, res, next) => {
    try {
        const result = {
            error: 'access_denied',
            error_description: 'End-User aborted interaction',
        };
        await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
        next(err);
    }
});

const oidc = new Provider('http://localhost:3070', configuration);

app.use("/oidc", oidc.callback());

app.listen(8080, function () {
    console.log('OIDC is listening on port 8080!');
});