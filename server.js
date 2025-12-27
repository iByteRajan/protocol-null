// --- CommonJS (No conflicts) ---
const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const path = require("path");
const fs = require("fs");
const dotenv = require("dotenv");
const fetch = require("node-fetch");
dotenv.config();

const app = express();
const port = process.env.PORT || 3002;
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
      const teamcode = req.query.teamcode; 
  console.log("➡️ Guest login from teamcode:", teamcode);
    const guestToken = jwt.sign(payload, SECRET_KEY, { algorithm: 'HS256', expiresIn: '1h' });
    res.cookie('auth', guestToken, { httpOnly: false }); 
 res.redirect(`/admin?teamcode=${teamcode}`);

});
 
  const questionId = process.env.QUESTION_ID;

app.get('/admin',authenticateToken,async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).sendFile(path.join(__dirname, 'views', 'admin_denied.html'));
    }

    const teamcode = req.query.teamcode;
    if (!teamcode) return res.status(400).json({ message: "teamcode missing" });
    if (!questionId) return res.status(500).json({ message: "No active question" });
    const store = await fetch("https://buggit-backend-yy8i.onrender.com/api/store-result", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ teamcode, questionId })
    });
    const result = await store.json();
    console.log("Stored in Main Backend:", result);


  return res.redirect("https://bug-hunt-manager-tau.vercel.app/level/694d39a21eea528e8a64289f/dashboard");


  } catch (error) {
    console.error("Error contacting main backend:", error);
    return res.status(500).json({ message: "Failed to sync with main backend" });
  }
});

app.listen(port, () => {
    console.log(`\n======================================================`);
    console.log(`🔥 Level 1: Protocol Null is running!`);
    console.log(`   http://localhost:${port}`);
    console.log(`======================================================\n`);
});