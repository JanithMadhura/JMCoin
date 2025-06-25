const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const User = require('./models/User');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Trust proxy if behind reverse proxy/load balancer (for correct IP)
app.set('trust proxy', true);

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Auth middleware to protect routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']; // "Bearer token"
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ msg: 'Invalid or expired token' });
    req.user = user; // { id, email }
    next();
  });
};

// Register route
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ msg: 'User already exists' });

    const passwordHash = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      passwordHash,
      balance: 0,
      loginIps: [],
    });

    await newUser.save();

    res.json({ msg: 'User registered successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) return res.status(401).json({ msg: 'Invalid password' });

    // Get real client IP address, trusting reverse proxy headers
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // Update login IPs, keep last 5 only
    user.loginIps = user.loginIps || [];
    user.loginIps.push({ ip: clientIp, date: new Date() });
    if (user.loginIps.length > 5) user.loginIps = user.loginIps.slice(-5);

    await user.save();

    // Generate JWT token with user id and email
    const token = jwt.sign(
      { id: user._id.toString(), email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      token,
      user: {
        email: user.email,
        balance: user.balance,
        loginIps: user.loginIps,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Protected route to get logged-in user's info
app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    if (!user) return res.status(404).json({ msg: 'User not found' });

    res.json({
      email: user.email,
      name: user.name,
      balance: user.balance,
      loginIps: user.loginIps,
      joinedAt: user.createdAt,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Public route to get user profile by email (optional)
app.get('/api/user-profile/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const user = await User.findOne({ email }).select('-passwordHash');
    if (!user) return res.status(404).json({ msg: 'User not found' });

    // sanitize and fallback if structure is off
    const recentIps = user.loginIps
    .slice(-5) // last 5 entries
    .map(entry => ({
        ip: entry.ip,
        date: entry.date,
    }));

    res.json({
      userId: user._id,
      name: user.name,
      joinedAt: user.createdAt,
      recentIps,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});


app.get('/api/dashboard', authenticateToken, async (req, res) => {
  const user = await User.findOne({ email: req.user.email });
  if (!user) return res.status(404).json({ msg: 'User not found' });

  res.json({ balance: user.balance });
});

module.exports = serverless(app);
