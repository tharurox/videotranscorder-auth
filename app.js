// Authentication Service (app.js)

const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
const { CognitoUserPool, CognitoUserAttribute, CognitoUser, AuthenticationDetails } = require('amazon-cognito-identity-js');
const AWS = require('aws-sdk');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

const app = express();
const port = 4000;

// Setup session and flash
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

app.use(flash());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Set up Cognito pool
const poolData = {
    UserPoolId: 'ap-southeast-2_Up85TT9kx',
    ClientId: '3jlv0og5l1mkjnq1tdb7bg3ini'
};
const userPool = new CognitoUserPool(poolData);

// Google OAuth setup
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
passport.use(new passport.Strategy(
    {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL
    },
    (accessToken, refreshToken, profile, done) => {
        done(null, profile);
    }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Routes
app.get('/register', (req, res) => res.send('Registration Page'));
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const attributeList = [new CognitoUserAttribute({ Name: 'email', Value: username })];

    userPool.signUp(username, password, attributeList, null, (err, data) => {
        if (err) {
            req.flash('error_msg', `Error: ${err.message}`);
            return res.redirect('/register');
        }
        req.flash('success_msg', 'Registration successful!');
        res.redirect('/login');
    });
});

app.get('/login', (req, res) => res.send('Login Page'));
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const authDetails = new AuthenticationDetails({ Username: username, Password: password });
    const cognitoUser = new CognitoUser({ Username: username, Pool: userPool });

    cognitoUser.authenticateUser(authDetails, {
        onSuccess: (result) => {
            req.session.user = result.getIdToken().getJwtToken();
            res.redirect('/');
        },
        onFailure: (err) => {
            req.flash('error_msg', `Login failed: ${err.message}`);
            res.redirect('/login');
        }
    });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => res.redirect('/'));

// Logout route
app.get('/logout', (req, res) => {
    req.logout();
    req.session.destroy(() => res.redirect('/login'));
});

// Middleware to check authentication
function isAuthenticated(req, res, next) {
    if (req.session && req.session.user) return next();
    res.redirect('/login');
}

// Protected route example
app.get('/', isAuthenticated, (req, res) => res.send('Welcome to the protected page'));

// Start the server
app.listen(port, () => console.log(`Authentication Service running on port ${port}`));
