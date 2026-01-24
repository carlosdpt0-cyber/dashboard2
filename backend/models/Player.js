const mongoose = require('mongoose');

const playerSchema = new mongoose.Schema({
    playerId: {
        type: String,
        required: true,
        unique: true
    },
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },
    balance: {
        type: Number,
        default: 0,
        min: 0
    },
    totalDeposits: {
        type: Number,
        default: 0
    },
    totalWithdrawals: {
        type: Number,
        default: 0
    },
    status: {
        type: String,
        enum: ['active', 'suspended', 'banned', 'inactive'],
        default: 'active'
    },
    kycStatus: {
        type: String,
        enum: ['pending', 'verified', 'rejected', 'not_required'],
        default: 'pending'
    },
    country: String,
    currency: {
        type: String,
        default: 'EUR'
    },
    lastLogin: Date,
    lastActivity: Date,
    registrationDate: {
        type: Date,
        default: Date.now
    },
    metadata: {
        ipAddress: String,
        device: String,
        referralCode: String,
        tags: [String]
    },
    notes: [{
        content: String,
        createdBy: String,
        createdAt: {
            type: Date,
            default: Date.now
        }
    }]
});

playerSchema.index({ username: 1 });
playerSchema.index({ email: 1 });
playerSchema.index({ status: 1 });
playerSchema.index({ lastActivity: -1 });

module.exports = mongoose.model('Player', playerSchema);