const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const os = require('os');

function getLocalIPs() {
  const ifaces = os.networkInterfaces();
  const ips = [];
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) ips.push(iface.address);
    }
  }
  return ips;
}
const session = require('express-session');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const bcrypt = require('bcryptjs');

const port = 3676;
const app = express();

// parse form bodies (for POST /login)
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));
// session middleware (simple setup for dev; set SESSION_SECRET in .env for production)
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

function ensureAuthenticated(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.redirect('/login');
}

app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Login handler implemented below after User model to allow DB verification
// (see implementation later in this file)


// Connect to local MongoDB (database name: "login")
console.log('Attempting to connect to MongoDB...', process.env.MONGO_URI ? 'URI found' : 'URI MISSING');
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server started on port ${port}`);
  const ips = getLocalIPs();
  if (ips.length) {
    console.log('Accessible on your LAN at:');
    ips.forEach(ip => console.log(`  http://${ip}:${port}`));
  } else {
    console.log('No non-internal IPv4 address detected; try connecting using your machine IP.');
  }
});
const userschema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userschema);

// Serve registration page
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

// Register new user (password hashed)
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashed });
    await newUser.save();
    console.log('User registered:', { id: newUser._id, username: newUser.username });
    return res.redirect('/login');
  } catch (err) {
    console.error('Register error:', err);
    return res.redirect('/register?error=1');
  }
});

// Login handler: verify credentials
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('Login attempt:', username);
  try {
    const user = await User.findOne({ username });
    console.log('Found user?:', !!user, user ? { id: user._id, username: user.username } : null);
    if (!user) return res.redirect('/login?error=1');
    const match = await bcrypt.compare(password, user.password);
    console.log('Password match:', match);
    if (!match) return res.redirect('/login?error=1');
    // successful login: set session and redirect to public gymog page
    req.session.userId = user._id;
    // in development, also echo a debug param
    if (process.env.NODE_ENV === 'development') {
      console.log('Login successful (dev):', user.username);
      return res.redirect('/gymog.html?debug=1');
    }
    return res.redirect('/gymog.html');
  } catch (err) {
    console.error('Login error:', err);
    return res.redirect('/login?error=1');
  }
});

// Dev helpers to create and log in a test user quickly (only in development)
if (process.env.NODE_ENV === 'development') {
  app.get('/dev/create-test-user', async (req, res) => {
    try {
      const username = 'test';
      const password = 'test1234';
      let user = await User.findOne({ username });
      if (!user) {
        const hashed = await bcrypt.hash(password, 10);
        user = new User({ username, password: hashed });
        await user.save();
        console.log('Dev: created test user', username);
      } else {
        console.log('Dev: test user already exists');
      }
      return res.json({ ok: true, username, note: 'Use /dev/login-test to set session' });
    } catch (err) {
      console.error('Dev create-test-user error:', err);
      return res.status(500).json({ ok: false, error: String(err) });
    }
  });

  app.get('/dev/login-test', async (req, res) => {
    try {
      const username = 'test';
      const user = await User.findOne({ username });
      if (!user) return res.status(404).json({ ok: false, error: 'test user not found' });
      req.session.userId = user._id;
      console.log('Dev: session set for test user');
      return res.redirect('/gymog.html?dev_login=1');
    } catch (err) {
      console.error('Dev login-test error:', err);
      return res.status(500).json({ ok: false, error: String(err) });
    }
  });
}

// Protected gym route (serves private/gym.html)
app.get('/gym', ensureAuthenticated, (req, res) => {
  return res.sendFile(path.join(__dirname, 'private', 'gym.html'));
});

// Simple logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Dev-only debug endpoint: lists users without passwords (only enabled when NODE_ENV=development)
if (process.env.NODE_ENV === 'development') {
  app.get('/debug/users', async (req, res) => {
    try {
      const users = await User.find().select('-password').lean();
      return res.json(users);
    } catch (err) {
      console.error('Debug users error:', err);
      return res.status(500).json({ error: 'failed to fetch users' });
    }
  });
  console.log('Dev debug routes enabled: GET /debug/users');
}