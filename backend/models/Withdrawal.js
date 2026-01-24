// backend/models/Withdrawal.js
const mongoose = require('mongoose');

const withdrawalSchema = new mongoose.Schema({
    player: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    amount: {
        type: Number,
        required: true,
        min: 1
    },
    method: {
        type: String,
        enum: ['bank', 'card', 'ewallet', 'crypto'],
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'processing', 'completed', 'rejected', 'cancelled'],
        default: 'pending'
    },
    transactionId: {
        type: String,
        unique: true
    },
    // Detalhes bancários
    bankDetails: {
        accountHolder: String,
        iban: String,
        bankName: String,
        swift: String
    },
    // Detalhes carteira eletrónica/cripto
    walletAddress: String,
    walletType: String,
    
    // Histórico e notas
    notes: String,
    internalNotes: String,
    rejectionReason: String,
    
    // Metadados
    processedBy: String,
    approvedAt: Date,
    rejectedAt: Date,
    completedAt: Date,
    
    // Timestamps
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Gerar ID de transação antes de salvar
withdrawalSchema.pre('save', function(next) {
    if (!this.transactionId) {
        const timestamp = Date.now().toString().slice(-6);
        const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
        this.transactionId = `WD${timestamp}${random}`;
    }
    this.updatedAt = new Date();
    next();
});

module.exports = mongoose.model('Withdrawal', withdrawalSchema);