const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
    user: {
        _id: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        name: String,
        email: String,
        role: String
    },
    action: {
        type: String,
        required: true,
        enum: [
            'login', 'logout', 'create', 'update', 'delete',
            'security', 'system', 'deposit', 'withdrawal',
            'bonus', 'game', 'email', 'payment', 'report'
        ]
    },
    module: {
        type: String,
        required: true,
        enum: [
            'auth', 'players', 'withdrawals', 'deposits',
            'payments', 'staff', 'settings', 'system',
            'games', 'bonuses', 'reports', 'email'
        ]
    },
    message: {
        type: String,
        required: true
    },
    details: String,
    ip: String,
    location: String,
    userAgent: String,
    sessionId: String,
    metadata: mongoose.Schema.Types.Mixed,
    timestamp: {
        type: Date,
        default: Date.now
    },
    read: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

// Índices para melhor performance
logSchema.index({ timestamp: -1 });
logSchema.index({ 'user._id': 1, timestamp: -1 });
logSchema.index({ action: 1, timestamp: -1 });
logSchema.index({ module: 1, timestamp: -1 });
logSchema.index({ ip: 1 });

// Middleware para formatar dados do usuário
logSchema.pre('save', function(next) {
    if (this.user && this.user._id) {
        this.user._id = this.user._id.toString();
    }
    next();
});

module.exports = mongoose.model('Log', logSchema);