const mongoose = require('mongoose');

// Modelo de Staff
const StaffSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    role: { 
        type: String, 
        enum: ['admin', 'chefe_departamento', 'financeiro', 'support', 'gestor'],
        default: 'support'
    },
    department: { type: String },
    isActive: { type: Boolean, default: true },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

// Modelo de Jogador
const PlayerSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    balance: { type: Number, default: 0, min: 0 },
    status: { 
        type: String, 
        enum: ['active', 'inactive', 'banned', 'pending'],
        default: 'active'
    },
    isOnline: { type: Boolean, default: false },
    lastLogin: { type: Date },
    totalDeposits: { type: Number, default: 0 },
    totalWithdrawals: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

// Modelo de Levantamento
const WithdrawalSchema = new mongoose.Schema({
    playerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Player', required: true },
    amount: { type: Number, required: true, min: 10 },
    method: { 
        type: String, 
        enum: ['bank_transfer', 'credit_card', 'ewallet', 'crypto'],
        required: true
    },
    status: { 
        type: String, 
        enum: ['pending', 'approved', 'rejected', 'processing', 'completed'],
        default: 'pending'
    },
    requestedAt: { type: Date, default: Date.now },
    processedAt: { type: Date },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Staff' },
    notes: { type: String }
});

// Modelo de Pagamento (depósito)
const PaymentSchema = new mongoose.Schema({
    playerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Player', required: true },
    amount: { type: Number, required: true, min: 10 },
    method: { 
        type: String, 
        enum: ['bank_transfer', 'credit_card', 'ewallet', 'crypto'],
        required: true
    },
    status: { 
        type: String, 
        enum: ['pending', 'approved', 'rejected', 'processing', 'completed'],
        default: 'pending'
    },
    requestedAt: { type: Date, default: Date.now },
    processedAt: { type: Date },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Staff' },
    transactionId: { type: String, unique: true }
});

// Modelo de Alerta
const AlertSchema = new mongoose.Schema({
    type: { 
        type: String, 
        enum: ['security', 'financial', 'system', 'user', 'warning'],
        required: true
    },
    title: { type: String, required: true },
    message: { type: String, required: true },
    priority: { 
        type: String, 
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'medium'
    },
    isResolved: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    resolvedAt: { type: Date },
    resolvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Staff' }
});

// Modelo de Notificação
const NotificationSchema = new mongoose.Schema({
    staffId: { type: mongoose.Schema.Types.ObjectId, ref: 'Staff', required: true },
    type: { 
        type: String, 
        enum: ['info', 'warning', 'success', 'error', 'system'],
        default: 'info'
    },
    title: { type: String, required: true },
    message: { type: String, required: true },
    isRead: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    link: { type: String } // Link para ação
});

// Exportar modelos
module.exports = {
    Staff: mongoose.model('Staff', StaffSchema),
    Player: mongoose.model('Player', PlayerSchema),
    Withdrawal: mongoose.model('Withdrawal', WithdrawalSchema),
    Payment: mongoose.model('Payment', PaymentSchema),
    Alert: mongoose.model('Alert', AlertSchema),
    Notification: mongoose.model('Notification', NotificationSchema)
};