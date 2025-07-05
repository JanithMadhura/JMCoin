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

//const ObjectId = mongoose.Types.ObjectId;

//User.updateOne({ _id: new ObjectId("6868f455ee8821f36e0b4171") }, { $set: { isAdmin: true } })
  //.then(() => console.log('Admin set!'))
  //.catch(console.error);



// Register route
const PendingUser = require('./models/PendingUser');
const sendVerificationEmail = require('./utils/sendEmail');

app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, captcha } = req.body;

    if (!captcha) return res.status(400).json({ msg: 'No captcha token' });

    const fetch = (await import('node-fetch')).default;
    const secretKey = process.env.RECAPTCHA_SECRET_KEY; // Set this in your .env

    const verifyRes = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${secretKey}&response=${captcha}`,
    });
    const verifyData = await verifyRes.json();

    if (!verifyData.success) {
      return res.status(400).json({ msg: 'Failed reCAPTCHA verification' });
    }

    // If user already exists in final users collection
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ msg: 'User already exists' });

    // Remove any old pending verification
    const existingPending = await PendingUser.findOne({ email });
    if (existingPending) await existingPending.deleteOne();

    const passwordHash = await bcrypt.hash(password, 10);

    // Generate a 6-digit verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Save to pending collection
    const pendingUser = new PendingUser({
      name,
      email,
      passwordHash,
      verificationCode
    });

    await pendingUser.save();

    // Send verification email
    await sendVerificationEmail(email, verificationCode);

    res.json({ msg: 'Verification code sent to your email' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});


app.post('/api/verify', async (req, res) => {
  try {
    const { email, code } = req.body;

    const pendingUser = await PendingUser.findOne({ email });
    if (!pendingUser) return res.status(404).json({ msg: 'No pending verification for this email' });

    if (pendingUser.verificationCode !== code)
      return res.status(400).json({ msg: 'Invalid verification code' });

    // Move to User collection
    const newUser = new User({
      name: pendingUser.name,
      email: pendingUser.email,
      passwordHash: pendingUser.passwordHash,
      balance: 0,
      loginIps: [],
    });

    await newUser.save();
    await pendingUser.deleteOne();

    res.json({ msg: 'Email verified and account created successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});


// Login route
app.post('/api/login', async (req, res) => {
  try {
    const { email, password, captcha } = req.body;

    if (!captcha) return res.status(400).json({ msg: 'No captcha token' });

    const fetch = (await import('node-fetch')).default;
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;

    const verifyRes = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${secretKey}&response=${captcha}`,
    });
    const verifyData = await verifyRes.json();

    if (!verifyData.success) {
      return res.status(400).json({ msg: 'Failed reCAPTCHA verification' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) return res.status(401).json({ msg: 'Invalid password' });

    // Get real client IP address, trusting reverse proxy headers
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // 🔒 Check VPN/Proxy using ip-api
    try {
      const fetch = (await import('node-fetch')).default;
      const response = await fetch(`http://ip-api.com/json/${clientIp}?fields=proxy,hosting,org,query`);

      const ipInfo = await response.json();

      if (
        ipInfo.proxy ||
        ipInfo.hosting ||
        /vpn|cloud|ovh|linode|digitalocean|aws/i.test(ipInfo.org)
      ) {
        return res.status(403).json({ msg: 'VPN or proxy detected. Please disable and try again.' });
      }
    } catch (err) {
      console.error('⚠️ VPN check failed:', err.message);
    }

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
        isAdmin: user.isAdmin
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

const adminOnly = require('./middleware/adminOnly');

// New route to get all users (admin only)
app.get('/api/admin/users', authenticateToken, adminOnly, async (req, res) => {
  try {
    const users = await User.find().select('-passwordHash'); // Exclude password hashes
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

app.get('/api/admin/dashboard', authenticateToken, adminOnly, (req, res) => {
  res.json({ msg: 'Welcome to the admin dashboard!' });
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

// in server.js or routes/auth.js
const ResetCode = require('./models/ResetCode');

app.post('/api/request-password-reset', async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ msg: 'User not found' });

  const code = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code

  await ResetCode.deleteMany({ email }); // remove previous codes
  await ResetCode.create({
    email,
    code,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 mins
  });

  try {
    await sendVerificationEmail(email, code);
    res.json({ msg: 'Verification code sent' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Failed to send verification email' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, password } = req.body;
    //console.log('Reset Password Payload:', req.body);

    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ msg: 'User not found' });

    // Hash new password
    const passwordHash = await bcrypt.hash(password, 10);
    user.passwordHash = passwordHash;

    await user.save();

    // Optionally: delete reset codes for that email if you want to clean up
    await ResetCode.deleteMany({ email });

    res.json({ msg: 'Password reset successful' });

  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ msg: 'Server error during password reset' });
  }
});

app.post('/api/verify-reset-code', async (req, res) => {
  try {
    const { email, code } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: 'User not found' });

    const resetEntry = await ResetCode.findOne({ email, code });
    if (!resetEntry) {
      return res.status(400).json({ msg: 'Invalid code or email' });
    }

    if (Date.now() > resetEntry.expiresAt) {
      return res.status(400).json({ msg: 'Code expired. Please request a new one.' });
    }

    

    res.json({ msg: 'Code verified successfully' });

  } catch (err) {
    console.error('Code Verify Error:', err);
    res.status(500).json({ msg: 'Server error during verification' });
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

const WithdrawalRequest = require('./models/WithdrawalRequest');

// Withdrawal Request Endpoint
app.post('/api/request-withdrawal', authenticateToken, async (req, res) => {
  try {
    const { amount, paymentMethod, paymentDetails } = req.body;
    const userId = req.user.id;

    // Validate input (you should add more validation)
    if (!amount || amount <= 0) {
      return res.status(400).json({ msg: 'Invalid withdrawal amount' });
    }

    // Get User and Validate balance
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }

    if (user.balance < amount) {
      return res.status(400).json({ msg: 'Insufficient balance' });
    }
    if (user.balance < 5000) {
      return res.status(400).json({ msg: 'insufficient balance. Minimum balance of 5000 JMC required' });
    }
    // Perform the Withdrawal
    user.balance -= amount; // Subtract the amount
    await user.save();

    // Create a new WithdrawalRequest record
    const withdrawalRequest = new WithdrawalRequest({
      user: userId,
      amount: amount,
      paymentMethod: paymentMethod,
      paymentDetails: paymentDetails
    });

    await withdrawalRequest.save();

    // **Here you would typically trigger the actual payment process (e.g., PayPal API call)**

    res.json({ msg: 'Withdrawal request submitted successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Admin endpoint to get all withdrawal requests
app.get('/api/admin/withdrawals', authenticateToken, adminOnly, async (req, res) => {
  try {
    const withdrawals = await WithdrawalRequest.find().populate('user', 'name email'); // Populate user details
    res.json(withdrawals);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

module.exports = app;
