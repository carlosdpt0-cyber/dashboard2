const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');

// Modelos (se já existirem, use-os)
const Staff = mongoose.model('Staff') || require('../models/Staff');
const InternalMessage = mongoose.model('InternalMessage') || require('../models/InternalMessage');
const User = mongoose.model('User') || require('../models/User');

// Middleware de autenticação
const requireAuth = (req, res, next) => {
    if (req.session && req.session.staff && req.session.staff.loggedIn) {
        return next();
    }
    res.status(401).json({ success: false, error: 'Não autenticado' });
};

// Middleware de permissão
const requirePermission = (...permissions) => {
    return (req, res, next) => {
        if (!req.session || !req.session.staff) {
            return res.status(401).json({ success: false, error: 'Sessão expirada' });
        }
        
        const staff = req.session.staff;
        
        if (staff.role === 'admin') {
            return next();
        }
        
        if (permissions.length === 0) {
            return next();
        }
        
        const hasPermission = permissions.some(permission => 
            staff.permissions && staff.permissions.includes(permission)
        );
        
        if (!hasPermission) {
            return res.status(403).json({ 
                success: false, 
                error: 'Permissão negada'
            });
        }
        
        next();
    };
};

// ==============================
// ROTAS DO CHAT INTERNO
// ==============================

// 1. Obter todos os membros da equipa (exceto o próprio)
router.get('/api/chat/staff', requireAuth, async (req, res) => {
    try {
        const currentUserId = req.session.staff.id;
        
        const staffMembers = await Staff.find({
            _id: { $ne: currentUserId },
            isActive: true
        })
        .select('name email role photo isOnline lastActive')
        .sort({ isOnline: -1, name: 1 })
        .lean();
        
        // Adicionar contagem de mensagens não lidas
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
                    lastActiveFormatted: new Date(staff.lastActive).toLocaleTimeString('pt-PT', {
                        hour: '2-digit',
                        minute: '2-digit'
                    })
                };
            })
        );
        
        res.json({
            success: true,
            staffMembers: staffWithUnread
        });
        
    } catch (error) {
        console.error('Erro ao obter staff:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao carregar membros da equipa'
        });
    }
});

// 2. Obter conversa com um staff específico
router.get('/api/chat/messages/:staffId', requireAuth, async (req, res) => {
    try {
        const { staffId } = req.params;
        const currentUserId = req.session.staff.id;
        
        if (!mongoose.Types.ObjectId.isValid(staffId)) {
            return res.status(400).json({
                success: false,
                error: 'ID inválido'
            });
        }
        
        // Verificar se o staff existe
        const staffExists = await Staff.findById(staffId);
        if (!staffExists) {
            return res.status(404).json({
                success: false,
                error: 'Membro da equipa não encontrado'
            });
        }
        
        // Obter mensagens da conversa
        const messages = await InternalMessage.getConversation(currentUserId, staffId, 100);
        
        // Formatar mensagens
        const formattedMessages = messages.map(msg => ({
            _id: msg._id,
            senderId: msg.senderId._id,
            recipientId: msg.recipientId._id,
            message: msg.message,
            read: msg.read,
            timestamp: msg.timestamp,
            senderName: msg.senderId.name,
            senderPhoto: msg.senderId.photo,
            recipientName: msg.recipientId.name
        }));
        
        res.json({
            success: true,
            messages: formattedMessages
        });
        
    } catch (error) {
        console.error('Erro ao obter mensagens:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao carregar mensagens'
        });
    }
});

// 3. Enviar mensagem
router.post('/api/chat/send', requireAuth, async (req, res) => {
    try {
        const { recipientId, message } = req.body;
        const currentUserId = req.session.staff.id;
        
        // Validações
        if (!recipientId || !message || !message.trim()) {
            return res.status(400).json({
                success: false,
                error: 'Destinatário e mensagem são obrigatórios'
            });
        }
        
        if (recipientId === currentUserId) {
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
        
        // Buscar dados completos para resposta
        const populatedMessage = await InternalMessage.findById(newMessage._id)
            .populate('senderId', 'name role photo')
            .populate('recipientId', 'name role photo')
            .lean();
        
        // Enviar notificação via WebSocket (se disponível)
        if (req.app.get('wss')) {
            const wss = req.app.get('wss');
            wss.clients.forEach(client => {
                if (client.readyState === 1 && client.userId === recipientId) {
                    client.send(JSON.stringify({
                        type: 'chat_message',
                        messageId: newMessage._id,
                        senderId: currentUserId,
                        senderName: populatedMessage.senderId.name,
                        message: message,
                        timestamp: newMessage.timestamp
                    }));
                }
            });
        }
        
        // Atualizar status online do remetente
        await Staff.findByIdAndUpdate(currentUserId, {
            lastActive: new Date()
        });
        
        res.json({
            success: true,
            message: 'Mensagem enviada com sucesso',
            data: {
                _id: populatedMessage._id,
                senderId: populatedMessage.senderId._id,
                recipientId: populatedMessage.recipientId._id,
                message: populatedMessage.message,
                timestamp: populatedMessage.timestamp,
                senderName: populatedMessage.senderId.name,
                recipientName: populatedMessage.recipientId.name
            }
        });
        
    } catch (error) {
        console.error('Erro ao enviar mensagem:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao enviar mensagem: ' + error.message
        });
    }
});

// 4. Marcar mensagens como lidas
router.post('/api/chat/mark-read/:staffId', requireAuth, async (req, res) => {
    try {
        const { staffId } = req.params;
        const currentUserId = req.session.staff.id;
        
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
});

// 5. Contar mensagens não lidas
router.get('/api/chat/unread-count', requireAuth, async (req, res) => {
    try {
        const currentUserId = req.session.staff.id;
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
});

// 6. Obter mensagens não lidas
router.get('/api/chat/unread-messages', requireAuth, async (req, res) => {
    try {
        const currentUserId = req.session.staff.id;
        
        const unreadMessages = await InternalMessage.find({
            recipientId: currentUserId,
            read: false
        })
        .populate('senderId', 'name role photo')
        .sort({ timestamp: -1 })
        .limit(20)
        .lean();
        
        // Agrupar por remetente
        const groupedMessages = unreadMessages.reduce((acc, message) => {
            const senderId = message.senderId._id.toString();
            if (!acc[senderId]) {
                acc[senderId] = {
                    sender: message.senderId,
                    messages: [],
                    count: 0
                };
            }
            acc[senderId].messages.push(message);
            acc[senderId].count++;
            return acc;
        }, {});
        
        res.json({
            success: true,
            messages: Object.values(groupedMessages)
        });
        
    } catch (error) {
        console.error('Erro ao obter mensagens não lidas:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao carregar mensagens não lidas'
        });
    }
});

// 7. Eliminar mensagem
router.delete('/api/chat/message/:messageId', requireAuth, async (req, res) => {
    try {
        const { messageId } = req.params;
        const currentUserId = req.session.staff.id;
        
        if (!mongoose.Types.ObjectId.isValid(messageId)) {
            return res.status(400).json({
                success: false,
                error: 'ID de mensagem inválido'
            });
        }
        
        const message = await InternalMessage.findOne({
            _id: messageId,
            $or: [
                { senderId: currentUserId },
                { recipientId: currentUserId }
            ]
        });
        
        if (!message) {
            return res.status(404).json({
                success: false,
                error: 'Mensagem não encontrada ou não tem permissão'
            });
        }
        
        // Se for o remetente, marcar como "eliminada para mim"
        if (message.senderId.toString() === currentUserId) {
            message.deletedBySender = true;
        } else {
            message.deletedByRecipient = true;
        }
        
        // Se ambos eliminaram, apagar realmente
        if (message.deletedBySender && message.deletedByRecipient) {
            await InternalMessage.findByIdAndDelete(messageId);
        } else {
            await message.save();
        }
        
        res.json({
            success: true,
            message: 'Mensagem eliminada'
        });
        
    } catch (error) {
        console.error('Erro ao eliminar mensagem:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao eliminar mensagem'
        });
    }
});

// 8. Atualizar status online
router.post('/api/chat/update-status', requireAuth, async (req, res) => {
    try {
        const { isOnline } = req.body;
        const currentUserId = req.session.staff.id;
        
        await Staff.findByIdAndUpdate(currentUserId, {
            isOnline: isOnline === true,
            lastActive: new Date()
        });
        
        // Notificar outros via WebSocket
        if (req.app.get('wss')) {
            const wss = req.app.get('wss');
            wss.clients.forEach(client => {
                if (client.readyState === 1) {
                    client.send(JSON.stringify({
                        type: 'staff_status',
                        staffId: currentUserId,
                        isOnline: isOnline === true,
                        lastActive: new Date()
                    }));
                }
            });
        }
        
        res.json({
            success: true,
            message: 'Status atualizado'
        });
        
    } catch (error) {
        console.error('Erro ao atualizar status:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao atualizar status'
        });
    }
});

// 9. Buscar conversas recentes
router.get('/api/chat/recent-conversations', requireAuth, async (req, res) => {
    try {
        const currentUserId = req.session.staff.id;
        
        // Buscar últimas mensagens de cada conversa
        const recentMessages = await InternalMessage.aggregate([
            {
                $match: {
                    $or: [
                        { senderId: mongoose.Types.ObjectId(currentUserId) },
                        { recipientId: mongoose.Types.ObjectId(currentUserId) }
                    ]
                }
            },
            {
                $sort: { timestamp: -1 }
            },
            {
                $group: {
                    _id: {
                        $cond: {
                            if: { $eq: ["$senderId", mongoose.Types.ObjectId(currentUserId)] },
                            then: "$recipientId",
                            else: "$senderId"
                        }
                    },
                    lastMessage: { $first: "$$ROOT" },
                    unreadCount: {
                        $sum: {
                            $cond: [
                                { 
                                    $and: [
                                        { $eq: ["$recipientId", mongoose.Types.ObjectId(currentUserId)] },
                                        { $eq: ["$read", false] }
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
                    staff: {
                        _id: '$staff._id',
                        name: '$staff.name',
                        role: '$staff.role',
                        photo: '$staff.photo',
                        isOnline: '$staff.isOnline',
                        lastActive: '$staff.lastActive'
                    },
                    lastMessage: {
                        _id: '$lastMessage._id',
                        message: '$lastMessage.message',
                        timestamp: '$lastMessage.timestamp',
                        senderId: '$lastMessage.senderId'
                    },
                    unreadCount: 1
                }
            },
            {
                $sort: { 'lastMessage.timestamp': -1 }
            },
            {
                $limit: 20
            }
        ]);
        
        res.json({
            success: true,
            conversations: recentMessages
        });
        
    } catch (error) {
        console.error('Erro ao buscar conversas recentes:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao carregar conversas'
        });
    }
});

// ==============================
// ROTAS DE EMAIL (SIMULADO - APENAS PARA CHAT INTERNO)
// ==============================

// 10. Página principal de email/chat
router.get('/email', requireAuth, requirePermission('view_email'), async (req, res) => {
    try {
        const currentUserId = req.session.staff.id;
        
        // Buscar staff
        const staffMembers = await Staff.find({
            _id: { $ne: currentUserId },
            isActive: true
        })
        .select('name email role photo isOnline lastActive')
        .sort({ isOnline: -1, name: 1 })
        .lean();
        
        // Contar mensagens não lidas
        const unreadInternalCount = await InternalMessage.countDocuments({
            recipientId: currentUserId,
            read: false
        });
        
        // Buscar conversas recentes
        const recentConversations = await InternalMessage.aggregate([
            {
                $match: {
                    $or: [
                        { senderId: mongoose.Types.ObjectId(currentUserId) },
                        { recipientId: mongoose.Types.ObjectId(currentUserId) }
                    ]
                }
            },
            {
                $sort: { timestamp: -1 }
            },
            {
                $limit: 5
            },
            {
                $lookup: {
                    from: 'staffs',
                    localField: 'senderId',
                    foreignField: '_id',
                    as: 'sender'
                }
            },
            {
                $lookup: {
                    from: 'staffs',
                    localField: 'recipientId',
                    foreignField: '_id',
                    as: 'recipient'
                }
            },
            {
                $unwind: '$sender'
            },
            {
                $unwind: '$recipient'
            },
            {
                $project: {
                    _id: 1,
                    message: 1,
                    timestamp: 1,
                    read: 1,
                    sender: {
                        _id: '$sender._id',
                        name: '$sender.name',
                        photo: '$sender.photo'
                    },
                    recipient: {
                        _id: '$recipient._id',
                        name: '$recipient.name',
                        photo: '$recipient.photo'
                    },
                    isFromMe: {
                        $eq: ['$sender._id', mongoose.Types.ObjectId(currentUserId)]
                    }
                }
            }
        ]);
        
        res.render('email', {
            title: 'Sistema de Comunicação',
            breadcrumb: 'Comunicação',
            user: req.session.staff,
            staffMembers: staffMembers,
            unreadInternalCount: unreadInternalCount,
            recentConversations: recentConversations,
            stats: {
                totalPlayers: 0,
                playersWithEmail: 0,
                newsletterSubscribers: 0
            },
            emailLogs: []
        });
        
    } catch (error) {
        console.error('Erro ao carregar página de comunicação:', error);
        req.flash('error', 'Erro ao carregar página de comunicação');
        res.redirect('/dashboard');
    }
});

// 11. Enviar mensagem de email (simulado - apenas para chat interno)
router.post('/api/email/send', requireAuth, requirePermission('send_emails'), async (req, res) => {
    try {
        const { recipients, subject, message } = req.body;
        const currentUserId = req.session.staff.id;
        
        // Esta função agora é apenas para chat interno
        // Se recipients for um ID de staff, enviar mensagem interna
        if (mongoose.Types.ObjectId.isValid(recipients)) {
            const staff = await Staff.findById(recipients);
            if (staff) {
                // Enviar como mensagem interna
                const newMessage = new InternalMessage({
                    senderId: currentUserId,
                    recipientId: recipients,
                    message: `${subject}: ${message}`,
                    read: false,
                    timestamp: new Date()
                });
                
                await newMessage.save();
                
                return res.json({
                    success: true,
                    message: 'Mensagem interna enviada com sucesso',
                    type: 'internal'
                });
            }
        }
        
        // Se for um grupo de jogadores, apenas simular
        res.json({
            success: true,
            message: 'Email simulado enviado com sucesso (sistema de chat interno ativo)',
            type: 'simulated'
        });
        
    } catch (error) {
        console.error('Erro ao enviar email:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao processar envio'
        });
    }
});

// ==============================
// WEBSOCKET HANDLERS PARA CHAT EM TEMPO REAL
// ==============================

function setupWebSocketHandlers(wss) {
    wss.on('connection', (ws, req) => {
        console.log('🔗 Nova conexão WebSocket para chat');
        
        // Autenticar conexão
        ws.on('message', async (message) => {
            try {
                const data = JSON.parse(message);
                
                // Conectar usuário ao chat
                if (data.type === 'chat_connect' && data.userId) {
                    ws.userId = data.userId;
                    console.log(`✅ Usuário ${data.userId} conectado ao chat`);
                    
                    // Atualizar status como online
                    await Staff.findByIdAndUpdate(data.userId, {
                        isOnline: true,
                        lastActive: new Date()
                    });
                    
                    // Notificar outros sobre o status online
                    wss.clients.forEach(client => {
                        if (client.readyState === 1 && client.userId !== data.userId) {
                            client.send(JSON.stringify({
                                type: 'staff_online',
                                staffId: data.userId,
                                timestamp: new Date()
                            }));
                        }
                    });
                }
                
                // Receber mensagem via WebSocket
                if (data.type === 'chat_message' && ws.userId) {
                    const { recipientId, message } = data;
                    
                    // Salvar no banco de dados
                    const newMessage = new InternalMessage({
                        senderId: ws.userId,
                        recipientId: recipientId,
                        message: message,
                        read: false,
                        timestamp: new Date()
                    });
                    
                    await newMessage.save();
                    
                    // Enviar para o destinatário
                    wss.clients.forEach(client => {
                        if (client.readyState === 1 && client.userId === recipientId) {
                            client.send(JSON.stringify({
                                type: 'chat_message',
                                messageId: newMessage._id,
                                senderId: ws.userId,
                                message: message,
                                timestamp: newMessage.timestamp
                            }));
                        }
                    });
                    
                    // Confirmar para o remetente
                    ws.send(JSON.stringify({
                        type: 'chat_sent',
                        messageId: newMessage._id,
                        timestamp: newMessage.timestamp
                    }));
                }
                
                // Marcar mensagens como lidas
                if (data.type === 'mark_read' && ws.userId) {
                    const { senderId } = data;
                    
                    await InternalMessage.updateMany(
                        { 
                            senderId: senderId, 
                            recipientId: ws.userId,
                            read: false 
                        },
                        { read: true }
                    );
                    
                    // Notificar o remetente
                    wss.clients.forEach(client => {
                        if (client.readyState === 1 && client.userId === senderId) {
                            client.send(JSON.stringify({
                                type: 'messages_read',
                                recipientId: ws.userId,
                                timestamp: new Date()
                            }));
                        }
                    });
                }
                
                // Atualizar status de digitação
                if (data.type === 'typing' && ws.userId) {
                    const { recipientId, isTyping } = data;
                    
                    wss.clients.forEach(client => {
                        if (client.readyState === 1 && client.userId === recipientId) {
                            client.send(JSON.stringify({
                                type: 'typing',
                                senderId: ws.userId,
                                isTyping: isTyping,
                                timestamp: new Date()
                            }));
                        }
                    });
                }
                
            } catch (error) {
                console.error('Erro ao processar mensagem WebSocket:', error);
            }
        });
        
        // Quando desconectar
        ws.on('close', async () => {
            if (ws.userId) {
                console.log(`❌ Usuário ${ws.userId} desconectado do chat`);
                
                // Atualizar status como offline após 30 segundos
                setTimeout(async () => {
                    const userStillConnected = Array.from(wss.clients).some(
                        client => client.userId === ws.userId && client.readyState === 1
                    );
                    
                    if (!userStillConnected) {
                        await Staff.findByIdAndUpdate(ws.userId, {
                            isOnline: false,
                            lastActive: new Date()
                        });
                        
                        // Notificar outros sobre o status offline
                        wss.clients.forEach(client => {
                            if (client.readyState === 1 && client.userId !== ws.userId) {
                                client.send(JSON.stringify({
                                    type: 'staff_offline',
                                    staffId: ws.userId,
                                    timestamp: new Date()
                                }));
                            }
                        });
                    }
                }, 30000);
            }
        });
    });
}

// ==============================
// FUNÇÕES AUXILIARES
// ==============================

// Criar notificação para mensagem nova
async function createMessageNotification(messageId) {
    try {
        const message = await InternalMessage.findById(messageId)
            .populate('senderId', 'name')
            .populate('recipientId', 'name');
        
        if (!message) return;
        
        // Aqui você pode criar uma notificação no sistema
        // Por exemplo, usando seu modelo UserNotification
        console.log(`📨 Nova mensagem de ${message.senderId.name} para ${message.recipientId.name}`);
        
    } catch (error) {
        console.error('Erro ao criar notificação:', error);
    }
}

// Verificar conexões ativas
function getActiveChatUsers(wss) {
    const activeUsers = new Set();
    
    wss.clients.forEach(client => {
        if (client.readyState === 1 && client.userId) {
            activeUsers.add(client.userId);
        }
    });
    
    return Array.from(activeUsers);
}

module.exports = {
    router,
    setupWebSocketHandlers,
    getActiveChatUsers
};