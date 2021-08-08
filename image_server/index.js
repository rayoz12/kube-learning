/**
 * This Microservice handles serving images
 * It's secured by using a JWT that's verified by the auth microservice
 * 
 * Securing Images
 * We want to able to get images using a GET Request but that's not possible when using JWT authentication.
 * We can secure images by using a nonce on the end of the request that we validated.
 * The end result is that we can add images to the page by just setting the src tag.
 * 
 * 1. The page requests for this nonce with their JWT token
 * 2. We pass the JWT Token to the auth microservice to verify it
 * 3. It comes back with if the user is authorised
 * 4. If the user is authorised we return a nonce (and store it temporarily)
 * 5. The page then does a get request on the image with the nonce as a query param (http://.../image.jpg?nonce=23143423)
 * 6. We validate this and return the image
 */

/**
 * Container Communication
 * 
 * I'm aware that communicating directly to containers using a synchronous method like http is an anti-pattern
 * however for the sake of keeping this simple (the irony of doing something like this in k8s) I don't want to
 * deploy anything like a service mesh.
 */


require('dotenv').config();

const crypto = require("crypto");
const path = require("path");
const fs = require("fs").promises;


const {PORT, AUTH_SERVER_HOSTNAME, AUTH_SERVER_PORT, NONCE_TIMEOUT} = process.env;

if (AUTH_SERVER_HOSTNAME == undefined) {
    console.error("AUTH_SERVER_HOSTNAME not defined in Environment!");
    process.exit();
}
if (AUTH_SERVER_PORT == undefined) {
    console.error("AUTH_SERVER_PORT not defined in Environment!");
    process.exit();
}

// Convert to a number;
const nonceTimeout = NONCE_TIMEOUT ? parseInt(NONCE_TIMEOUT): 60000;

const axios = require("axios").default;
const express = require('express');

class NonceManager {
    validNonces = [];

    generateNonce() {
        const nonce = crypto.randomBytes(20).toString('hex');
        this.validNonces.push(nonce);
        
        // Remove it after a minute
        setTimeout(() => {
            this.removeNonce(nonce);
        }, nonceTimeout);

        return nonce;
    }

    verifyNonce(nonce) {
        return this.validNonces.includes(nonce);
    }

    removeNonce(nonce) {
        const index = this.validNonces.findIndex(it => it === nonce);
        this.validNonces.splice(index, 1);
    }
}

const nonceManager = new NonceManager();


const app = express();
const port = PORT ? parseInt(PORT) : 3001;

app.use(express.json());

app.get('/validate', async (req, res) => {
    const token = req.get("Authorization");
    let response;
    try {
        const response = await axios.get(`http://${AUTH_SERVER_HOSTNAME}:${AUTH_SERVER_PORT}/me`, {headers: {
            AUTHORIZATION:token
        }});
        // If it hasn't failed the user is validated
        const nonce = nonceManager.generateNonce();
        res.json({nonce});
    }
    catch (error) {
        if (error.response) {
            if (error.response.status === 401) {
                res.sendStatus(401);
                return;
            }
        }
        res.sendStatus(500);
    }
});

app.get("/images/*.jpg", async (req, res) => {
    const nonce = req.query.nonce;

    if (nonce === undefined) {
        res.sendStatus(404);
        return;
    }
    
    if (nonceManager.verifyNonce(nonce)) {
        // Get the file requested
        const file = req.url
            .split("?") // Strip the nonce
            .shift() // Get the file name
            .slice(8); // Remove '/images/'
        
            // console.log(req.url, file);
        
        try {
            const root = path.join(__dirname, "images");
            await fs.stat(path.join(root, file));
            res.sendFile(file, {root});
        }
        catch (e) {
            res.sendStatus(404);
        }
    }
    else {
        console.error("Failed to verify Nonce");
        res.sendStatus(404);
    }
});

app.listen(port, () => {
    console.log(`Image Microservice listening at http://localhost:${port}`)
})
