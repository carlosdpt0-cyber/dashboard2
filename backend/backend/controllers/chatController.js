const Staff = require('../models/Staff');
const InternalMessage = require('../models/InternalMessage');
const UserNotification = require('../models/Notification');
const { createSystemLog } = require('./systemController');

// ==============================
// CONTROLADOR DE CHAT INTERNO
// ==============================

class ChatController {
    
    /**
     * Renderizar página principal do chat
     */
    async renderChatPage(req, res) {
        try {
            const currentUserId = req.user ? req.user._id : req.session.staff.id;
            
            // Buscar todos os staff (exceto o próprio)
            const staffMembers = await Staff.find({
                _id: { $ne: currentUserId },
                isActive: true
            })
            .select('name email role photo isOnline lastActive')
            .sort({ isOnline: -1, name: 1 })
            .lean();
            
            // Contar mensagens não lidas para cada staff
            const staffWithUnread = await Promise.all(
                staffMembers.map(async (staff) => {
                    const unreadCount = await InternalMessage.countDocuments({
                        senderId: staff._id,
                        recipientId: currentUserId,
                        read: false
                    });
                    
                    return {
                        ...staff,
                        unreadCount,
                        lastActiveFormatted: this.formatTime(staff.lastActive),
                        statusClass: staff.isOnline ? 'online' : 'offline'
                    };
                })
            );
            
            // Buscar últimas conversas
            const recentConversations = await this.getRecentConversations(currentUserId);
            
            // Notificações do utilizador
            const userNotifications = await UserNotification.find({ 
                userId: currentUserId 
            })
            .sort({ createdAt: -1 })
            .limit(10)
            .lean();

            res.render('chat', {
                title: 'Chat Interno',
                breadcrumb: 'Chat',
                staffMembers: staffWithUnread,
                recentConversations,
                user: req.session.staff,
                notifications: {
                    unreadCount: await UserNotification.countDocuments({ 
                        userId: currentUserId,
                        read: false 
                    }),
                    notifications: userNotifications
                },
                currentUserId: currentUserId,
                currentUserName: req.user ? req.user.name : req.session.staff.name
            });
        } catch (error) {
            console.error('Erro ao carregar chat:', error);
            req.flash('error', 'Erro ao carregar chat');
            res.redirect('/dashboard');
        }
    }
    
    /**
     * Obter conversa com um utilizador específico
     */
    async getConversation(req, res) {
        try {
            const { staffId } = req.params;
            const currentUserId = req.user ? req.user._id : req.session.staff.id;
            
            if (!staffId || staffId === 'undefined') {
                return res.status(400).json({
                    success: false,
                    error: 'ID de utilizador inválido'
                });
            }
            
            // Verificar se o staff existe
            const staff = await Staff.findById(staffId)
                .select('name email role photo isOnline lastActive')
                .lean();
            
            if (!staff) {
                return res.status(404).json({
                    success: false,
                    error: 'Utilizador não encontrado'
                });
            }
            
            // Obter mensagens da conversa
            const messages = await InternalMessage.getConversation(currentUserId, staffId, 100);
            
            // Marcar mensagens como lidas
            if (messages.length > 0) {
                await InternalMessage.markAsRead(staffId, currentUserId);
            }
            
            // Formatar mensagens
            const formattedMessages = messages.map(msg => ({
                id: msg._id,
                senderId: msg.senderId._id,
                senderName: msg.senderId.name,
                senderPhoto: msg.senderId.photo,
                senderRole: msg.senderId.role,
                recipientId: msg.recipientId._id,
                recipientName: msg.recipientId.name,
                recipientPhoto: msg.recipientId.photo,
                message: msg.message,
                timestamp: msg.timestamp,
                formattedTime: this.formatTime(msg.timestamp),
                formattedDate: this.formatDate(msg.timestamp),
                isCurrentUser: msg.senderId._id.toString() === currentUserId.toString(),
                read: msg.read
            }));
            
            res.json({
                success: true,
                conversation: {
                    staff: {
                        id: staff._id,
                        name: staff.name,
                        email: staff.email,
                        role: staff.role,
                        photo: staff.photo,
                        isOnline: staff.isOnline,
                        lastActive: staff.lastActive,
                        lastActiveFormatted: this.formatTime(staff.lastActive)
                    },
                    messages: formattedMessages
                }
            });
        } catch (error) {
            console.error('Erro ao obter conversa:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao carregar conversa'
            });
        }
    }
    
    /**
     * Enviar mensagem
     */
    async sendMessage(req, res) {
        try {
            const { recipientId, message } = req.body;
            const currentUserId = req.user ? req.user._id : req.session.staff.id;
            const currentUserName = req.user ? req.user.name : req.session.staff.name;
            
            // Validações
            if (!recipientId || !message || !message.trim()) {
                return res.status(400).json({
                    success: false,
                    error: 'Destinatário e mensagem são obrigatórios'
                });
            }
            
            // Não pode enviar para si mesmo
            if (recipientId === currentUserId.toString()) {
                return res.status(400).json({
                    success: false,
                    error: 'Não pode enviar mensagens para si mesmo'
                });
            }
            
            // Verificar se o destinatário existe
            const recipient = await Staff.findById(recipientId);
            if (!recipient) {
                return res.status(404).json({
                    success: false,
                    error: 'Destinatário não encontrado'
                });
            }
            
            // Criar e salvar mensagem
            const newMessage = new InternalMessage({
                senderId: currentUserId,
                recipientId: recipientId,
                message: message.trim(),
                read: false,
                timestamp: new Date()
            });
            
            await newMessage.save();
            
            // Popular dados para resposta
            const populatedMessage = await InternalMessage.findById(newMessage._id)
                .populate('senderId', 'name role photo')
                .populate('recipientId', 'name role photo')
                .lean();
            
            // Criar notificação para o destinatário
            await UserNotification.create({
                userId: recipientId,
                title: 'Nova Mensagem no Chat',
                message: `${currentUserName} enviou-lhe uma mensagem`,
                type: 'info',
                relatedTo: 'chat',
                relatedId: newMessage._id
            });
            
            // Log do sistema
            if (req && req.session && req.session.staff) {
                await createSystemLog(
                    currentUserId,
                    {
                        name: currentUserName,
                        email: req.user ? req.user.email : req.session.staff.email,
                        role: req.user ? req.user.role : req.session.staff.role
                    },
                    'create',
                    'chat',
                    `Mensagem enviada para ${recipient.name}`,
                    `Mensagem: ${message.substring(0, 50)}...`,
                    req
                );
            }
            
            // Formatar resposta
            const responseMessage = {
                id: populatedMessage._id,
                senderId: populatedMessage.senderId._id,
                senderName: populatedMessage.senderId.name,
                senderPhoto: populatedMessage.senderId.photo,
                recipientId: populatedMessage.recipientId._id,
                recipientName: populatedMessage.recipientId.name,
                message: populatedMessage.message,
                timestamp: populatedMessage.timestamp,
                formattedTime: this.formatTime(populatedMessage.timestamp),
                isCurrentUser: true,
                read: false
            };
            
            res.json({
                success: true,
                message: 'Mensagem enviada com sucesso',
                data: responseMessage
            });
        } catch (error) {
            console.error('Erro ao enviar mensagem:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao enviar mensagem: ' + error.message
            });
        }
    }
    
    /**
     * Marcar mensagens como lidas
     */
    async markAsRead(req, res) {
        try {
            const { staffId } = req.params;
            const currentUserId = req.user ? req.user._id : req.session.staff.id;
            
            if (!staffId) {
                return res.status(400).json({
                    success: false,
                    error: 'ID de utilizador inválido'
                });
            }
            
            await InternalMessage.markAsRead(staffId, currentUserId);
            
            res.json({
                success: true,
                message: 'Mensagens marcadas como lidas'
            });
        } catch (error) {
            console.error('Erro ao marcar mensagens como lidas:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao atualizar status das mensagens'
            });
        }
    }
    
    /**
     * Obter contagem de mensagens não lidas
     */
    async getUnreadCount(req, res) {
        try {
            const currentUserId = req.user ? req.user._id : req.session.staff.id;
            const count = await InternalMessage.countUnread(currentUserId);
            
            res.json({
                success: true,
                count: count
            });
        } catch (error) {
            console.error('Erro ao contar mensagens não lidas:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao contar mensagens não lidas'
            });
        }
    }
    
    /**
     * Obter staff online
     */
    async getOnlineStaff(req, res) {
        try {
            const currentUserId = req.user ? req.user._id : req.session.staff.id;
            
            const onlineStaff = await Staff.find({
                _id: { $ne: currentUserId },
                isActive: true,
                isOnline: true
            })
            .select('name email role photo lastActive')
            .sort({ name: 1 })
            .lean();
            
            const formattedStaff = onlineStaff.map(staff => ({
                ...staff,
                lastActiveFormatted: this.formatTime(staff.lastActive)
            }));
            
            res.json({
                success: true,
                onlineStaff: formattedStaff,
                count: formattedStaff.length
            });
        } catch (error) {
            console.error('Erro ao obter staff online:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao carregar staff online'
            });
        }
    }
    
    /**
     * Pesquisar staff
     */
    async searchStaff(req, res) {
        try {
            const { query } = req.query;
            const currentUserId = req.user ? req.user._id : req.session.staff.id;
            
            if (!query || query.length < 2) {
                return res.json({
                    success: true,
                    staff: []
                });
            }
            
            const staff = await Staff.find({
                _id: { $ne: currentUserId },
                isActive: true,
                $or: [
                    { name: { $regex: query, $options: 'i' } },
                    { email: { $regex: query, $options: 'i' } },
                    { role: { $regex: query, $options: 'i' } },
                    { department: { $regex: query, $options: 'i' } }
                ]
            })
            .select('name email role photo isOnline lastActive')
            .limit(20)
            .lean();
            
            const staffWithUnread = await Promise.all(
                staff.map(async (member) => {
                    const unreadCount = await InternalMessage.countDocuments({
                        senderId: member._id,
                        recipientId: currentUserId,
                        read: false
                    });
                    
                    return {
                        ...member,
                        unreadCount,
                        lastActiveFormatted: this.formatTime(member.lastActive)
                    };
                })
            );
            
            res.json({
                success: true,
                staff: staffWithUnread
            });
        } catch (error) {
            console.error('Erro ao pesquisar staff:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao pesquisar staff'
            });
        }
    }
    
    /**
     * Apagar mensagem
     */
    async deleteMessage(req, res) {
        try {
            const { messageId } = req.params;
            const currentUserId = req.user ? req.user._id : req.session.staff.id;
            
            if (!messageId) {
                return res.status(400).json({
                    success: false,
                    error: 'ID de mensagem inválido'
                });
            }
            
            const message = await InternalMessage.findById(messageId);
            
            if (!message) {
                return res.status(404).json({
                    success: false,
                    error: 'Mensagem não encontrada'
                });
            }
            
            // Verificar permissão (apenas o remetente pode apagar)
            if (message.senderId.toString() !== currentUserId.toString()) {
                return res.status(403).json({
                    success: false,
                    error: 'Não tem permissão para apagar esta mensagem'
                });
            }
            
            await InternalMessage.deleteOne({ _id: messageId });
            
            // Log do sistema
            if (req && req.session && req.session.staff) {
                await createSystemLog(
                    currentUserId,
                    {
                        name: req.user ? req.user.name : req.session.staff.name,
                        email: req.user ? req.user.email : req.session.staff.email,
                        role: req.user ? req.user.role : req.session.staff.role
                    },
                    'delete',
                    'chat',
                    'Mensagem apagada',
                    `Mensagem ID: ${messageId}`,
                    req
                );
            }
            
            res.json({
                success: true,
                message: 'Mensagem apagada com sucesso'
            });
        } catch (error) {
            console.error('Erro ao apagar mensagem:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao apagar mensagem'
            });
        }
    }
    
    /**
     * Obter estatísticas do chat
     */
    async getChatStats(req, res) {
        try {
            const currentUserId = req.user ? req.user._id : req.session.staff.id;
            
            // Total de mensagens enviadas
            const sentMessages = await InternalMessage.countDocuments({
                senderId: currentUserId
            });
            
            // Total de mensagens recebidas
            const receivedMessages = await InternalMessage.countDocuments({
                recipientId: currentUserId
            });
            
            // Mensagens não lidas
            const unreadMessages = await InternalMessage.countDocuments({
                recipientId: currentUserId,
                read: false
            });
            
            // Staff com quem conversou
            const conversationPartners = await InternalMessage.aggregate([
                {
                    $match: {
                        $or: [
                            { senderId: currentUserId },
                            { recipientId: currentUserId }
                        ]
                    }
                },
                {
                    $group: {
                        _id: {
                            $cond: [
                                { $eq: ['$senderId', currentUserId] },
                                '$recipientId',
                                '$senderId'
                            ]
                        }
                    }
                },
                {
                    $lookup: {
                        from: 'staffs',
                        localField: '_id',
                        foreignField: '_id',
                        as: 'staff'
                    }
                },
                {
                    $unwind: '$staff'
                },
                {
                    $project: {
                        _id: 1,
                        name: '$staff.name',
                        role: '$staff.role',
                        photo: '$staff.photo',
                        isOnline: '$staff.isOnline'
                    }
                },
                { $limit: 10 }
            ]);
            
            res.json({
                success: true,
                stats: {
                    sentMessages,
                    receivedMessages,
                    unreadMessages,
                    totalMessages: sentMessages + receivedMessages,
                    conversationPartners: conversationPartners.length
                },
                recentPartners: conversationPartners
            });
        } catch (error) {
            console.error('Erro ao obter estatísticas do chat:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao obter estatísticas'
            });
        }
    }
    
    // ==============================
    // MÉTODOS AUXILIARES PRIVADOS
    // ==============================
    
    /**
     * Obter conversas recentes
     */
    async getRecentConversations(userId) {
        try {
            const conversations = await InternalMessage.aggregate([
                {
                    $match: {
                        $or: [
                            { senderId: userId },
                            { recipientId: userId }
                        ]
                    }
                },
                {
                    $sort: { timestamp: -1 }
                },
                {
                    $group: {
                        _id: {
                            $cond: [
                                { $eq: ['$senderId', userId] },
                                '$recipientId',
                                '$senderId'
                            ]
                        },
                        lastMessage: { $first: '$$ROOT' },
                        unreadCount: {
                            $sum: {
                                $cond: [
                                    {
                                        $and: [
                                            { $eq: ['$recipientId', userId] },
                                            { $eq: ['$read', false] }
                                        ]
                                    },
                                    1,
                                    0
                                ]
                            }
                        }
                    }
                },
                {
                    $lookup: {
                        from: 'staffs',
                        localField: '_id',
                        foreignField: '_id',
                        as: 'staff'
                    }
                },
                {
                    $unwind: '$staff'
                },
                {
                    $project: {
                        _id: 1,
                        staffId: '$_id',
                        staffName: '$staff.name',
                        staffRole: '$staff.role',
                        staffPhoto: '$staff.photo',
                        staffIsOnline: '$staff.isOnline',
                        lastMessage: {
                            id: '$lastMessage._id',
                            message: '$lastMessage.message',
                            timestamp: '$lastMessage.timestamp',
                            senderId: '$lastMessage.senderId',
                            isCurrentUser: { $eq: ['$lastMessage.senderId', userId] }
                        },
                        unreadCount: 1,
                        lastActive: '$staff.lastActive'
                    }
                },
                {
                    $sort: { 'lastMessage.timestamp': -1 }
                },
                { $limit: 10 }
            ]);
            
            return conversations.map(conv => ({
                ...conv,
                lastMessage: {
                    ...conv.lastMessage,
                    formattedTime: this.formatTime(conv.lastMessage.timestamp),
                    shortMessage: conv.lastMessage.message.length > 50 
                        ? conv.lastMessage.message.substring(0, 50) + '...' 
                        : conv.lastMessage.message
                },
                lastActiveFormatted: this.formatTime(conv.lastActive)
            }));
        } catch (error) {
            console.error('Erro ao obter conversas recentes:', error);
            return [];
        }
    }
    
    /**
     * Formatar hora
     */
    formatTime(date) {
        if (!date) return 'Nunca';
        
        const now = new Date();
        const messageDate = new Date(date);
        const diffMs = now - messageDate;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'Agora mesmo';
        if (diffMins < 60) return `Há ${diffMins} min`;
        if (diffHours < 24) return `Há ${diffHours} h`;
        if (diffDays === 1) return 'Ontem';
        if (diffDays < 7) return `Há ${diffDays} dias`;
        
        return messageDate.toLocaleDateString('pt-PT', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric'
        });
    }
    
    /**
     * Formatar data completa
     */
    formatDate(date) {
        if (!date) return '';
        
        return new Date(date).toLocaleDateString('pt-PT', {
            day: '2-digit',
            month: 'long',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }
}

module.exports = new ChatController();