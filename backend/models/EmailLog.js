const mongoose = require('mongoose');

const EmailLogSchema = new mongoose.Schema({
    // Destinatários do email
    to: [{
        type: String,
        required: true,
        validate: {
            validator: function(v) {
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
            },
            message: props => `${props.value} não é um email válido!`
        }
    }],
    
    // Assunto do email
    subject: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200
    },
    
    // Conteúdo do email (primeiros 500 caracteres)
    content: {
        type: String,
        default: ''
    },
    
    // Template usado (se aplicável)
    template: {
        type: String,
        enum: ['manual', 'welcome', 'deposit_bonus', 'withdrawal_approved', 'withdrawal_rejected', 'newsletter', 'promotion', 'system'],
        default: 'manual'
    },
    
    // Quem enviou o email
    sentBy: {
        staffId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Staff',
            required: true
        },
        staffName: {
            type: String,
            required: true,
            trim: true
        },
        staffEmail: {
            type: String,
            trim: true
        }
    },
    
    // Data de envio
    sentAt: {
        type: Date,
        default: Date.now
    },
    
    // Status do email
    status: {
        type: String,
        enum: ['pending', 'sending', 'sent', 'failed', 'partial'],
        default: 'pending'
    },
    
    // Quantidade de jogadores que receberam o email
    playersCount: {
        type: Number,
        default: 0,
        min: 0
    },
    
    // Informações de erro (se falhou)
    error: {
        type: String,
        default: null
    },
    
    // Tentativas de envio
    attempts: {
        type: Number,
        default: 0,
        min: 0
    },
    
    // Última tentativa
    lastAttempt: {
        type: Date,
        default: null
    },
    
    // Metadados adicionais
    metadata: {
        campaignId: String,
        segment: String,
        language: String,
        attachments: [String],
        replyTo: String,
        cc: [String],
        bcc: [String]
    },
    
    // Estatísticas de entrega (se disponível)
    deliveryStats: {
        delivered: { type: Number, default: 0 },
        opened: { type: Number, default: 0 },
        clicked: { type: Number, default: 0 },
        bounced: { type: Number, default: 0 },
        unsubscribed: { type: Number, default: 0 },
        complained: { type: Number, default: 0 }
    },
    
    // ID do provedor de email externo
    providerId: {
        type: String,
        default: null
    },
    
    // Categorização
    category: {
        type: String,
        enum: ['marketing', 'transactional', 'notification', 'support', 'system'],
        default: 'marketing'
    },
    
    // Prioridade do email
    priority: {
        type: String,
        enum: ['low', 'normal', 'high', 'urgent'],
        default: 'normal'
    },
    
    // Tags para filtragem
    tags: [{
        type: String,
        lowercase: true,
        trim: true
    }]
}, {
    collection: 'email_logs',
    timestamps: {
        createdAt: 'created_at',
        updatedAt: 'updated_at'
    },
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Índices para melhor performance
EmailLogSchema.index({ sentAt: -1 });
EmailLogSchema.index({ 'sentBy.staffId': 1 });
EmailLogSchema.index({ status: 1 });
EmailLogSchema.index({ template: 1 });
EmailLogSchema.index({ category: 1 });
EmailLogSchema.index({ tags: 1 });
EmailLogSchema.index({ 'metadata.campaignId': 1 });

// Virtual para verificar se o email está em um estado final
EmailLogSchema.virtual('isFinal').get(function() {
    return ['sent', 'failed', 'partial'].includes(this.status);
});

// Virtual para verificar se pode ser reenviado
EmailLogSchema.virtual('canRetry').get(function() {
    return this.status === 'failed' && this.attempts < 3;
});

// Virtual para obter a taxa de abertura
EmailLogSchema.virtual('openRate').get(function() {
    if (this.playersCount === 0) return 0;
    return Math.round((this.deliveryStats.opened / this.playersCount) * 100);
});

// Virtual para obter a taxa de clique
EmailLogSchema.virtual('clickRate').get(function() {
    if (this.playersCount === 0) return 0;
    return Math.round((this.deliveryStats.clicked / this.playersCount) * 100);
});

// Método para marcar como enviando
EmailLogSchema.methods.markAsSending = function() {
    this.status = 'sending';
    this.attempts += 1;
    this.lastAttempt = new Date();
    return this.save();
};

// Método para marcar como enviado
EmailLogSchema.methods.markAsSent = function(providerId = null) {
    this.status = 'sent';
    this.providerId = providerId;
    return this.save();
};

// Método para marcar como falhado
EmailLogSchema.methods.markAsFailed = function(error) {
    this.status = 'failed';
    this.error = error;
    return this.save();
};

// Método para marcar como parcialmente enviado
EmailLogSchema.methods.markAsPartial = function(successCount, error = null) {
    this.status = 'partial';
    this.playersCount = successCount;
    this.error = error;
    return this.save();
};

// Método para atualizar estatísticas de entrega
EmailLogSchema.methods.updateDeliveryStats = function(stats) {
    if (stats.delivered !== undefined) this.deliveryStats.delivered = stats.delivered;
    if (stats.opened !== undefined) this.deliveryStats.opened = stats.opened;
    if (stats.clicked !== undefined) this.deliveryStats.clicked = stats.clicked;
    if (stats.bounced !== undefined) this.deliveryStats.bounced = stats.bounced;
    if (stats.unsubscribed !== undefined) this.deliveryStats.unsubscribed = stats.unsubscribed;
    if (stats.complained !== undefined) this.deliveryStats.complained = stats.complained;
    return this.save();
};

// Método estático para obter estatísticas por período
EmailLogSchema.statics.getStats = async function(startDate, endDate) {
    const match = {};
    
    if (startDate) {
        match.sentAt = { $gte: new Date(startDate) };
    }
    
    if (endDate) {
        match.sentAt = match.sentAt || {};
        match.sentAt.$lte = new Date(endDate);
    }
    
    const stats = await this.aggregate([
        { $match: match },
        {
            $group: {
                _id: null,
                total: { $sum: 1 },
                sent: { $sum: { $cond: [{ $eq: ['$status', 'sent'] }, 1, 0] } },
                failed: { $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] } },
                pending: { $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] } },
                sending: { $sum: { $cond: [{ $eq: ['$status', 'sending'] }, 1, 0] } },
                totalPlayers: { $sum: '$playersCount' },
                totalOpened: { $sum: '$deliveryStats.opened' },
                totalClicked: { $sum: '$deliveryStats.clicked' }
            }
        }
    ]);
    
    return stats[0] || {
        total: 0,
        sent: 0,
        failed: 0,
        pending: 0,
        sending: 0,
        totalPlayers: 0,
        totalOpened: 0,
        totalClicked: 0
    };
};

// Método estático para obter emails recentes
EmailLogSchema.statics.getRecent = async function(limit = 10) {
    return this.find()
        .sort({ sentAt: -1 })
        .limit(limit)
        .populate('sentBy.staffId', 'name email')
        .lean();
};

// Método estático para obter emails por status
EmailLogSchema.statics.getByStatus = async function(status, page = 1, limit = 20) {
    const skip = (page - 1) * limit;
    
    const [emails, total] = await Promise.all([
        this.find({ status })
            .sort({ sentAt: -1 })
            .skip(skip)
            .limit(limit)
            .populate('sentBy.staffId', 'name email')
            .lean(),
        this.countDocuments({ status })
    ]);
    
    return {
        emails,
        total,
        pages: Math.ceil(total / limit),
        currentPage: page
    };
};

// Método estático para obter emails por staff
EmailLogSchema.statics.getByStaff = async function(staffId, page = 1, limit = 20) {
    const skip = (page - 1) * limit;
    
    const [emails, total] = await Promise.all([
        this.find({ 'sentBy.staffId': staffId })
            .sort({ sentAt: -1 })
            .skip(skip)
            .limit(limit)
            .populate('sentBy.staffId', 'name email')
            .lean(),
        this.countDocuments({ 'sentBy.staffId': staffId })
    ]);
    
    return {
        emails,
        total,
        pages: Math.ceil(total / limit),
        currentPage: page
    };
};

// Método estático para obter campanhas
EmailLogSchema.statics.getCampaigns = async function() {
    return this.aggregate([
        {
            $match: {
                'metadata.campaignId': { $exists: true, $ne: null }
            }
        },
        {
            $group: {
                _id: '$metadata.campaignId',
                campaignId: { $first: '$metadata.campaignId' },
                totalEmails: { $sum: 1 },
                totalPlayers: { $sum: '$playersCount' },
                sent: { $sum: { $cond: [{ $eq: ['$status', 'sent'] }, 1, 0] } },
                failed: { $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] } },
                totalOpened: { $sum: '$deliveryStats.opened' },
                totalClicked: { $sum: '$deliveryStats.clicked' },
                lastSent: { $max: '$sentAt' },
                firstSent: { $min: '$sentAt' }
            }
        },
        {
            $project: {
                _id: 0,
                campaignId: 1,
                totalEmails: 1,
                totalPlayers: 1,
                sent: 1,
                failed: 1,
                totalOpened: 1,
                totalClicked: 1,
                openRate: {
                    $cond: [
                        { $eq: ['$totalPlayers', 0] },
                        0,
                        { $round: [{ $multiply: [{ $divide: ['$totalOpened', '$totalPlayers'] }, 100] }, 2] }
                    ]
                },
                clickRate: {
                    $cond: [
                        { $eq: ['$totalPlayers', 0] },
                        0,
                        { $round: [{ $multiply: [{ $divide: ['$totalClicked', '$totalPlayers'] }, 100] }, 2] }
                    ]
                },
                lastSent: 1,
                firstSent: 1
            }
        },
        { $sort: { lastSent: -1 } }
    ]);
};

// Pré-save middleware para garantir consistência
EmailLogSchema.pre('save', function(next) {
    // Garantir que playersCount é igual ao número de destinatários
    if (this.to && Array.isArray(this.to)) {
        this.playersCount = this.to.length;
    }
    
    // Adicionar tags automáticas baseadas no template
    if (this.template && !this.tags.includes(this.template)) {
        this.tags.push(this.template);
    }
    
    // Adicionar tag de categoria
    if (this.category && !this.tags.includes(this.category)) {
        this.tags.push(this.category);
    }
    
    // Adicionar tag de status
    if (this.status && !this.tags.includes(this.status)) {
        this.tags.push(this.status);
    }
    
    next();
});

const EmailLog = mongoose.model('EmailLog', EmailLogSchema);

module.exports = EmailLog;