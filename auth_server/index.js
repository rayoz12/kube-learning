// None of this is secure at all, rather it exists just for the sake of deploying k8s

const users = require("./users.json");

const express = require('express');
const express_jwt = require('express-jwt');
const jwt = require('jsonwebtoken');

const secret = "sdnjkawndjkwndjkandjkn129329439084324i4ufn4fj-03jkj"

const app = express();
const port = 3000;

app.use(express.json());

app.post('/login', (req, res) => {
    const creds = req.body;
    console.log(creds, users);

    const user = users.find(it => creds.username === it.username && creds.password === it.password);
    if (user === undefined) {
        res.status(400).end();
        return;
    }

    const userJWT = {
        username: user.username,
        details: user.details
    };

    const signedJwt = jwt.sign(userJWT, secret, {algorithm: "HS256"});

    res.json({token: signedJwt});
});

app.use(express_jwt({secret, algorithms: ["HS256"]}));

app.get('/me', (req, res) => {
    res.json(req.user.details);
});

app.listen(port, () => {
    console.log(`Auth Microservice listening at http://localhost:${port}`)
})