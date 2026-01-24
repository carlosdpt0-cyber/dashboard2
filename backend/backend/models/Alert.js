const mongoose = require('mongoose');

const AlertSchema = new mongoose.Schema({
    type: {
        type: String,
        enum: ['security', 'fraud', 'withdrawal', 'payment', 'player', 'system', 'warning'],
        default: 'system'
    },
    severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'medium'
    },
    title: {
        type: String,
        required: true,
        trim: true
    },
    message: {
        type: String,
        required: true
    },
    playerId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    playerName: {
        type: String,
        default: null
    },
    staffId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Staff',
        default: null
    },
    staffName: {
        type: String,
        default: null
    },
    relatedTo: {
        type: String,
        default: null
    },
    relatedId: {
        type: mongoose.Schema.Types.ObjectId,
        default: null
    },
    isResolved: {
        type: Boolean,
        default: false
    },
    resolvedBy: {
        type: String,
        default: null
    },
    resolvedAt: {
        type: Date,
        default: null
    },
    metadata: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
}, {
    collection: 'alerts',
    timestamps: false // Já temos createdAt e updatedAt manualmente
});

// Índices para melhor performance
AlertSchema.index({ isResolved: 1 });
AlertSchema.index({ severity: 1 });
AlertSchema.index({ type: 1 });
AlertSchema.index({ createdAt: -1 });
AlertSchema.index({ playerId: 1 });
AlertSchema.index({ staffId: 1 });

// Middleware para atualizar updatedAt antes de salvar
AlertSchema.pre('save', function(next) {
    this.updatedAt = new Date();
    next();
});

// Método estático para criar alerta de segurança
AlertSchema.statics.createSecurityAlert = async function(title, message, severity = 'high', metadata = {}) {
    const alert = new this({
        type: 'security',
        severity,
        title,
        message,
        metadata
    });
    return await alert.save();
};

// Método estático para criar alerta de fraude
AlertSchema.statics.createFraudAlert = async function(playerId, playerName, title, message, metadata = {}) {
    const alert = new this({
        type: 'fraud',
        severity: 'critical',
        title,
        message,
        playerId,
        playerName,
        metadata
    });
    return await alert.save();
};

// Método estático para criar alerta de levantamento
AlertSchema.statics.createWithdrawalAlert = async function(playerId, playerName, amount, metadata = {}) {
    const alert = new this({
        type: 'withdrawal',
        severity: amount > 5000 ? 'high' : 'medium',
        title: 'Levantamento Suspeito',
        message: `Levantamento de €${amount} por ${playerName}`,
        playerId,
        playerName,
        metadata: {
            amount,
            ...metadata
        }
    });
    return await alert.save();
};

// Método estático para criar alerta de pagamento
AlertSchema.statics.createPaymentAlert = async function(playerId, playerName, amount, metadata = {}) {
    const alert = new this({
        type: 'payment',
        severity: amount > 5000 ? 'medium' : 'low',
        title: 'Pagamento Grande',
        message: `Pagamento de €${amount} por ${playerName}`,
        playerId,
        playerName,
        metadata: {
            amount,
            ...metadata
        }
    });
    return await alert.save();
};

// Método estático para criar alerta de jogador
AlertSchema.statics.createPlayerAlert = async function(playerId, playerName, title, message, severity = 'medium', metadata = {}) {
    const alert = new this({
        type: 'player',
        severity,
        title,
        message,
        playerId,
        playerName,
        metadata
    });
    return await alert.save();
};

// Método estático para criar alerta de sistema
AlertSchema.statics.createSystemAlert = async function(title, message, severity = 'medium', metadata = {}) {
    const alert = new this({
        type: 'system',
        severity,
        title,
        message,
        metadata
    });
    return await alert.save();
};

// Método estático para criar alerta de warning
AlertSchema.statics.createWarningAlert = async function(title, message, severity = 'medium', metadata = {}) {
    const alert = new this({
        type: 'warning',
        severity,
        title,
        message,
        metadata
    });
    return await alert.save();
};

// Método estático para marcar alerta como resolvido
AlertSchema.statics.markAsResolved = async function(alertId, resolvedBy, notes = '') {
    return await this.findByIdAndUpdate(
        alertId,
        {
            isResolved: true,
            resolvedBy,
            resolvedAt: new Date(),
            $push: {
                'metadata.resolutionNotes': {
                    note: notes,
                    resolvedBy,
                    resolvedAt: new Date()
                }
            }
        },
        { new: true }
    );
};

// Método estático para obter alertas não resolvidos
AlertSchema.statics.getUnresolvedAlerts = async function(limit = 50) {
    return await this.find({ isResolved: false })
        .sort({ severity: -1, createdAt: -1 })
        .limit(limit);
};

// Método estático para obter alertas por tipo
AlertSchema.statics.getAlertsByType = async function(type, limit = 100) {
    return await this.find({ type, isResolved: false })
        .sort({ createdAt: -1 })
        .limit(limit);
};

// Método estático para obter alertas críticos
AlertSchema.statics.getCriticalAlerts = async function(limit = 50) {
    return await this.find({ 
        isResolved: false,
        severity: { $in: ['critical', 'high'] }
    })
    .sort({ createdAt: -1 })
    .limit(limit);
};

// Método estático para obter estatísticas
AlertSchema.statics.getStats = async function() {
    const total = await this.countDocuments();
    const unresolved = await this.countDocuments({ isResolved: false });
    const critical = await this.countDocuments({ 
        isResolved: false,
        severity: 'critical'
    });
    const high = await this.countDocuments({ 
        isResolved: false,
        severity: 'high'
    });
    const medium = await this.countDocuments({ 
        isResolved: false,
        severity: 'medium'
    });
    const low = await this.countDocuments({ 
        isResolved: false,
        severity: 'low'
    });
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const last24Hours = await this.countDocuments({
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });
    
    const last7Days = await this.countDocuments({
        createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    });
    
    return {
        total,
        unresolved,
        severity: {
            critical,
            high,
            medium,
            low
        },
        recent: {
            last24Hours,
            last7Days
        }
    };
};

// Método para formatar o alerta para exibição
AlertSchema.methods.toDisplayFormat = function() {
    const alert = this.toObject();
    
    // Adicionar propriedades calculadas
    alert.timeAgo = this.getTimeAgo();
    alert.severityClass = this.getSeverityClass();
    alert.typeIcon = this.getTypeIcon();
    
    return alert;
};

// Método de instância para obter tempo relativo
AlertSchema.methods.getTimeAgo = function() {
    if (!this.createdAt) return 'Agora mesmo';
    
    const now = new Date();
    const diffMs = now - this.createdAt;
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHour = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHour / 24);
    
    if (diffSec < 60) return 'Agora mesmo';
    if (diffMin < 60) return `${diffMin} min atrás`;
    if (diffHour < 24) return `${diffHour} h atrás`;
    if (diffDay < 7) return `${diffDay} d atrás`;
    return this.createdAt.toLocaleDateString('pt-PT');
};

// Método de instância para obter classe CSS de severidade
AlertSchema.methods.getSeverityClass = function() {
    switch(this.severity) {
        case 'critical': return 'alert-critical';
        case 'high': return 'alert-high';
        case 'medium': return 'alert-medium';
        case 'low': return 'alert-low';
        default: return 'alert-medium';
    }
};

// Método de instância para obter ícone de tipo
AlertSchema.methods.getTypeIcon = function() {
    switch(this.type) {
        case 'security': return 'shield-alert';
        case 'fraud': return 'user-x';
        case 'withdrawal': return 'credit-card';
        case 'payment': return 'dollar-sign';
        case 'player': return 'user';
        case 'system': return 'server';
        case 'warning': return 'alert-triangle';
        default: return 'bell';
    }
};

// Verificar se o modelo já existe antes de criar
let Alert;
try {
    Alert = mongoose.model('Alert', AlertSchema, 'alerts');
} catch (error) {
    // Se já existe, use o modelo existente
    Alert = mongoose.model('Alert');
}

module.exports = Alert;