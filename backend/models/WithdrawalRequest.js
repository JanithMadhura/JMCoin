const mongoose = require('mongoose');

const WithdrawalRequestSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // Reference to the User model
        required: true
    },
    amount: {
        type: Number,
        required: true,
        min: 0.01 // Ensure it's a positive amount
    },
    paymentMethod: {
        type: String,
        required: true,
        enum: ['LTC']
    },
    paymentDetails: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'completed', 'rejected'],
        default: 'pending'
    },
    requestedAt: {
        type: Date,
        default: Date.now
    },
    processedAt: {
        type: Date
    },
    processedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User' // Reference to the Admin User model (if applicable)
    }
});

module.exports = mongoose.model('WithdrawalRequest', WithdrawalRequestSchema);