require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Terlalu banyak percobaan. Coba lagi 15 menit lagi.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Mengambil data dari .env
const USERS = {
  [process.env.ADMIN_USERNAME]: {
    passwordHash: process.env.ADMIN_PASSWORD_HASH,
    role: 'admin',
  },
};

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Input tidak valid' });
    }

    const user = USERS[username];
    const dummyHash = '$2a$10$abcdefghijklmnopqrstuv';
    const hashToCheck = user ? user.passwordHash : dummyHash;
    
    // Pencocokan password
    const match = await bcrypt.compare(password, hashToCheck);

    if (!user || !match) {
      return res.status(401).json({ error: 'Username atau password salah' });
    }

    const token = jwt.sign(
      { sub: username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h', algorithm: 'HS256' }
    );

    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000,
    });

    res.json({ success: true, message: 'Login berhasil' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/dashboard', (req, res) => {
  const token = req.cookies?.auth_token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Belum login' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ message: 'Selamat datang di dashboard admin!', user: decoded.sub });
  } catch {
    res.status(401).json({ error: 'Token tidak valid' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.json({ success: true });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

module.exports = app;
