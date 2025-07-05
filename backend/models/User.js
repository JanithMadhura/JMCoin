const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    passwordHash: String,
    balance: { type: Number, default: 0 },
    loginIps: [
        {
        ip: String,
        date: Date,
        }
    ],
    resetCode: String,
    resetCodeExpires: Date,
    isAdmin: { type: Boolean, default: false }
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);
