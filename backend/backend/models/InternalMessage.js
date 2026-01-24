const mongoose = require('mongoose');

const internalMessageSchema = new mongoose.Schema({
    senderId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Staff',
        required: true
    },
    recipientId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Staff',
        required: true
    },
    message: {
        type: String,
        required: true,
        trim: true
    },
    read: {
        type: Boolean,
        default: false
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Índices para melhor performance
internalMessageSchema.index({ senderId: 1, recipientId: 1 });
internalMessageSchema.index({ recipientId: 1, read: 1 });
internalMessageSchema.index({ timestamp: -1 });

// Método estático para obter conversa entre dois usuários
internalMessageSchema.statics.getConversation = async function(userId1, userId2, limit = 50) {
    return this.find({
        $or: [
            { senderId: userId1, recipientId: userId2 },
            { senderId: userId2, recipientId: userId1 }
        ]
    })
    .sort({ timestamp: 1 })
    .limit(limit)
    .populate('senderId', 'name role photo')
    .populate('recipientId', 'name role photo')
    .lean();
};

// Método para marcar mensagens como lidas
internalMessageSchema.statics.markAsRead = async function(senderId, recipientId) {
    return this.updateMany(
        {
            senderId: senderId,
            recipientId: recipientId,
            read: false
        },
        {
            $set: { read: true }
        }
    );
};

// Método para contar mensagens não lidas
internalMessageSchema.statics.countUnread = async function(userId) {
    return this.countDocuments({
        recipientId: userId,
        read: false
    });
};

const InternalMessage = mongoose.model('InternalMessage', internalMessageSchema);

module.exports = InternalMessage;