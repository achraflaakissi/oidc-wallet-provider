const { Issuer } = require('openid-client');

Issuer.discover('https://mailtowallet.sitecreatortest.com/oidc').then(issuer => {
    const { Client } = issuer;
    console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata);
    const client = new issuer.Client({
        client_id: 'oidcCLIENT',
        client_secret: 'bar',
        redirect_uris: ["http://localhost:8080/login/callback"],
        response_types: ['code'],
        scope: 'openid email'
    }); // => Client
    console.log('client', client.userinfo());
});