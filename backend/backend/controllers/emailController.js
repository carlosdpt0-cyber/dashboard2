const Staff = require('../models/Staff');
const InternalMessage = require('../models/InternalMessage');
const UserNotification = require('../models/Notification');
const EmailLog = require('../models/EmailLog');
const User = require('../models/User');
const { createSystemLog } = require('./systemController');

class EmailController {
    
    /**
     * Renderizar página de email/chat
     */
    async renderEmailPage(req, res) {
        try {
            // Buscar todos os staff (exceto o próprio)
            const staffMembers = await Staff.find({
                _id: { $ne: req.user ? req.user._id : req.session.staff.id },
                isActive: true
            })
            .select('name email role photo isOnline lastActive')
            .sort({ isOnline: -1, name: 1 })
            .lean();
            
            // Contar mensagens não lidas
            const unreadInternalCount = await InternalMessage.countUnread(
                req.user ? req.user._id : req.session.staff.id
            );
            
            // Email logs
            const emailLogs = await EmailLog.find()
                .sort({ sentAt: -1 })
                .limit(50)
                .lean();

            // Estatísticas
            const totalPlayers = await User.countDocuments({ isActive: true });
            const playersWithEmail = await User.countDocuments({ 
                isActive: true, 
                email: { $exists: true, $ne: '' } 
            });
            const newsletterSubscribers = await User.countDocuments({ 
                isActive: true, 
                newsletter: true,
                email: { $exists: true, $ne: '' } 
            });

            // Notificações do utilizador
            const notifications = await UserNotification.find({ 
                userId: req.session.staff.id 
            })
            .sort({ createdAt: -1 })
            .limit(10)
            .lean();

            // Buscar mensagens internas
            const internalMessages = await InternalMessage.find({
                $or: [
                    { senderId: req.user ? req.user._id : req.session.staff.id },
                    { recipientId: req.user ? req.user._id : req.session.staff.id }
                ]
            })
            .sort({ timestamp: -1 })
            .limit(10)
            .populate('senderId', 'name role photo')
            .populate('recipientId', 'name role photo')
            .lean();

            res.render('email', {
                title: 'Sistema de Email',
                breadcrumb: 'Email',
                emailLogs,
                stats: {
                    totalPlayers,
                    playersWithEmail,
                    newsletterSubscribers
                },
                user: req.session.staff,
                notifications: {
                    unreadCount: await UserNotification.countDocuments({ 
                        userId: req.session.staff.id,
                        read: false 
                    }),
                    notifications: notifications
                },
                staffMembers: staffMembers,
                unreadInternalCount: unreadInternalCount || 0,
                internalMessages: internalMessages || []
            });
        } catch (error) {
            console.error('Erro ao carregar página de email:', error);
            req.flash('error', 'Erro ao carregar página de email');
            res.redirect('/dashboard');
        }
    }
    
    /**
     * Obter estatísticas de email
     */
    async getEmailStats(req, res) {
        try {
            const totalPlayers = await User.countDocuments({ isActive: true });
            const playersWithEmail = await User.countDocuments({ 
                isActive: true, 
                email: { $exists: true, $ne: '' } 
            });
            const newsletterSubscribers = await User.countDocuments({ 
                isActive: true, 
                newsletter: true,
                email: { $exists: true, $ne: '' } 
            });

            res.json({
                success: true,
                totalPlayers,
                playersWithEmail,
                newsletterSubscribers
            });
        } catch (error) {
            console.error('Erro ao buscar estatísticas de email:', error);
            res.status(500).json({ 
                success: false, 
                error: 'Erro ao buscar estatísticas' 
            });
        }
    }
    
    /**
     * Obter logs de email
     */
    async getEmailLogs(req, res) {
        try {
            const emailLogs = await EmailLog.find()
                .sort({ sentAt: -1 })
                .limit(50)
                .lean();

            res.json({
                success: true,
                logs: emailLogs
            });
        } catch (error) {
            console.error('Erro ao buscar logs de email:', error);
            res.status(500).json({ 
                success: false, 
                error: 'Erro ao buscar logs' 
            });
        }
    }
    
    /**
     * Obter destinatários por tipo
     */
    async getRecipientsByType(req, res) {
        try {
            const type = req.params.type;
            let query = { 
                isActive: true, 
                email: { $exists: true, $ne: '' } 
            };

            if (type === 'all') {
                // Todos os jogadores com email
            } else if (type === 'newsletter') {
                query.newsletter = true;
            } else if (type === 'vip') {
                query.level = { $in: ['VIP', 'Gold', 'Platinum', 'Diamond'] };
            } else if (type === 'active') {
                const thirtyDaysAgo = new Date();
                thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
                query.lastLogin = { $gte: thirtyDaysAgo };
            }

            const players = await User.find(query)
                .select('_id username email firstName lastName level lastLogin')
                .limit(500)
                .lean();

            res.json({
                success: true,
                players: players.map(player => ({
                    _id: player._id,
                    username: player.username,
                    email: player.email,
                    firstName: player.firstName,
                    lastName: player.lastName,
                    name: `${player.firstName || ''} ${player.lastName || ''}`.trim() || player.username,
                    level: player.level || 'Bronze',
                    lastLogin: player.lastLogin
                }))
            });
        } catch (error) {
            console.error('Erro ao buscar destinatários:', error);
            res.status(500).json({ 
                success: false, 
                error: 'Erro ao buscar destinatários' 
            });
        }
    }
    
    /**
     * Enviar email
     */
    async sendEmail(req, res) {
        try {
            const { recipients, subject, message } = req.body;
            const currentUser = req.session.staff;
            
            if (!recipients || !subject || !message) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Destinatários, assunto e mensagem são obrigatórios' 
                });
            }
            
            let players = [];
            
            // Determinar quais jogadores receberão o email
            if (typeof recipients === 'string' && 
                ['all', 'newsletter', 'vip', 'active'].includes(recipients)) {
                
                let query = { isActive: true, email: { $exists: true, $ne: '' } };
                
                if (recipients === 'newsletter') {
                    query.newsletter = true;
                } else if (recipients === 'vip') {
                    query.level = { $in: ['VIP', 'Gold', 'Platinum', 'Diamond'] };
                } else if (recipients === 'active') {
                    const thirtyDaysAgo = new Date();
                    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
                    query.lastLogin = { $gte: thirtyDaysAgo };
                }
                
                players = await User.find(query)
                    .select('email firstName lastName')
                    .lean();
                    
            } else if (Array.isArray(recipients)) {
                // IDs específicos
                players = await User.find({
                    _id: { $in: recipients },
                    isActive: true,
                    email: { $exists: true, $ne: '' }
                })
                .select('email firstName lastName')
                .lean();
            }
            
            // Verificar se há destinatários
            if (players.length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Nenhum destinatário válido encontrado' 
                });
            }
            
            // Criar log do email
            const emailLog = new EmailLog({
                to: players.map(p => p.email),
                subject,
                template: 'manual',
                sentBy: {
                    staffId: currentUser.id,
                    staffName: currentUser.name
                },
                sentAt: new Date(),
                status: 'sent',
                playersCount: players.length,
                message: message.substring(0, 200) // Guardar apenas os primeiros 200 caracteres
            });
            
            await emailLog.save();
            
            // Aqui implementar o envio real de email (nodemailer, SendGrid, etc.)
            console.log(`📧 Email preparado para envio:`);
            console.log(`   • Assunto: ${subject}`);
            console.log(`   • Destinatários: ${players.length} jogadores`);
            console.log(`   • Enviado por: ${currentUser.name}`);
            
            // Log do sistema
            await createSystemLog(
                currentUser.id,
                currentUser,
                'create',
                'email',
                `Email enviado: ${subject}`,
                `Enviado para ${players.length} jogadores`,
                req
            );
            
            res.json({
                success: true,
                message: `Email preparado para envio a ${players.length} jogadores`,
                logId: emailLog._id,
                playersCount: players.length
            });
            
        } catch (error) {
            console.error('Erro ao enviar email:', error);
            res.status(500).json({ 
                success: false, 
                error: 'Erro ao enviar email: ' + error.message 
            });
        }
    }
    
    /**
     * Obter staff para chat
     */
    async getChatStaff(req, res) {
        try {
            const currentUserId = req.user ? req.user._id : req.session.staff.id;
            
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
                        lastActiveFormatted: this.formatTime(staff.lastActive)
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
    }
    
    /**
     * Obter mensagens do chat
     */
    async getChatMessages(req, res) {
        try {
            const { staffId } = req.params;
            const currentUserId = req.user ? req.user._id : req.session.staff.id;
            
            if (!staffId || staffId === 'undefined') {
                return res.status(400).json({
                    success: false,
                    error: 'ID de staff inválido'
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
    }
    
    /**
     * Enviar mensagem no chat
     */
    async sendChatMessage(req, res) {
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
    async markChatMessagesAsRead(req, res) {
        try {
            const { staffId } = req.params;
            const currentUserId = req.user ? req.user._id : req.session.staff.id;
            
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
    
    // ==============================
    // MÉTODOS AUXILIARES
    // ==============================
    
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
}

module.exports = new EmailController();