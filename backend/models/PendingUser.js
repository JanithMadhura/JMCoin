const mongoose = require('mongoose');

const PendingUserSchema = new mongoose.Schema({
    name: String,
    email: String,
    passwordHash: String,
    verificationCode: String,
    createdAt: { type: Date, default: Date.now, expires: 600 } // expires in 10 mins
});

module.exports = mongoose.model('PendingUser', PendingUserSchema);
