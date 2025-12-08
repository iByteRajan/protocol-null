const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs'); // Added FS module to read HTML files
const app = express();
const port = process.env.PORT || 3000;
// --- Configuration ---
const SECRET_KEY = 'super_secret_ctf_key_dont_leak';
const FLAG = 'FLAG{JWT_N0N3_4DM1N_Byp4ss_Succ3ss}';

app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'views')));

// --- Authentication Middleware ---
function authenticateToken(req, res, next) {
    let token = req.cookies.auth || '';

    if (token && token.split('.').length === 2) {
        token += '.';
    }
    
    if (!token) return res.redirect('/');

    try {
        // 1. Try Valid Verification
        jwt.verify(token, SECRET_KEY);
        const decoded = jwt.decode(token);
        req.user = decoded;
        next();
    } catch (e) {
        // 2. VULNERABILITY: Check for 'none' algorithm
        const parts = token.split('.');
        if (parts.length === 3 && parts[2] === '') {
            try {
                const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
                if (header.alg && header.alg.toLowerCase() === 'none') {
                    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
                    req.user = payload;
                    return next(); 
                }
            } catch (err) {}
        }
        return res.status(403).send('Invalid Token Signature');
    }
}

// --- Routes ---

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/login/guest', (req, res) => {
    const payload = {
        role: 'guest',
        user: 'newbieza',
        id: '102'
    };
    const guestToken = jwt.sign(payload, SECRET_KEY, { algorithm: 'HS256', expiresIn: '1h' });
    res.cookie('auth', guestToken, { httpOnly: false }); 
    res.redirect('/admin');
});

app.get('/admin', authenticateToken, (req, res) => {
    if (req.user && req.user.role === 'admin') {
        // Read the separated HTML file
        const successPath = path.join(__dirname, 'views', 'admin_granted.html');
        let htmlContent = fs.readFileSync(successPath, 'utf8');

        // Inject the dynamic data (User & Flag) into the HTML
        htmlContent = htmlContent.replace('{{USER}}', req.user.user);
        htmlContent = htmlContent.replace('{{FLAG}}', FLAG);

        res.status(200).send(htmlContent);
    } else {
        res.status(403).sendFile(path.join(__dirname, 'views', 'admin_denied.html'));
    }
});

app.listen(port, () => {
    console.log(`\n======================================================`);
    console.log(`🔥 Level 1: Protocol Null is running!`);
    console.log(`   http://localhost:${port}`);
    console.log(`======================================================\n`);
});