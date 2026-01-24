const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const chatController = require('../controllers/chatController');
const InternalMessage = require('../models/InternalMessage');
const Staff = require('../models/Staff');

// Middleware para verificar se é staff
const isStaff = (req, res, next) => {
    if (req.user.role !== 'staff' && req.user.role !== 'admin') {
        return res.status(403).json({ 
            success: false, 
            error: 'Acesso restrito à equipa' 
        });
    }
    next();
};

// Obter todos os membros da equipa
router.get('/staff', auth, isStaff, async (req, res) => {
    try {
        const staffMembers = await Staff.find({ 
            _id: { $ne: req.user.id } // Excluir o próprio usuário
        })
        .select('name email role photo lastActive isOnline')
        .sort({ name: 1 })
        .lean();
        
        // Adicionar contagem de mensagens não lidas
        const staffWithUnread = await Promise.all(
            staffMembers.map(async (staff) => {
                const unreadCount = await InternalMessage.countDocuments({
                    senderId: staff._id,
                    recipientId: req.user.id,
                    read: false
                });
                
                return {
                    ...staff,
                    unreadCount,
                    isOnline: staff.isOnline || false
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

// Obter mensagens de conversa com um staff específico
router.get('/messages/:staffId', auth, isStaff, async (req, res) => {
    try {
        const { staffId } = req.params;
        
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
        const messages = await InternalMessage.getConversation(
            req.user.id,
            staffId,
            100
        );
        
        // Formatar mensagens
        const formattedMessages = messages.map(msg => ({
            _id: msg._id,
            senderId: msg.senderId._id,
            recipientId: msg.recipientId._id,
            message: msg.message,
            read: msg.read,
            timestamp: msg.timestamp,
            senderName: msg.senderId.name,
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

// Enviar mensagem
router.post('/send', auth, isStaff, async (req, res) => {
    try {
        const { recipientId, message } = req.body;
        
        // Validações
        if (!recipientId || !message) {
            return res.status(400).json({
                success: false,
                error: 'Destinatário e mensagem são obrigatórios'
            });
        }
        
        if (recipientId === req.user.id.toString()) {
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
            senderId: req.user.id,
            recipientId: recipientId,
            message: message.trim(),
            read: false
        });
        
        await newMessage.save();
        
        // Popular dados para resposta
        const populatedMessage = await InternalMessage.findById(newMessage._id)
            .populate('senderId', 'name role photo')
            .populate('recipientId', 'name role photo')
            .lean();
        
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

// Marcar mensagens como lidas
router.post('/mark-read/:staffId', auth, isStaff, async (req, res) => {
    try {
        const { staffId } = req.params;
        
        await InternalMessage.markAsRead(staffId, req.user.id);
        
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

// Obter contagem de mensagens não lidas
router.get('/unread-count', auth, isStaff, async (req, res) => {
    try {
        const count = await InternalMessage.countUnread(req.user.id);
        
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

// Atualizar status online
router.post('/update-status', auth, isStaff, async (req, res) => {
    try {
        const { isOnline } = req.body;
        
        await Staff.findByIdAndUpdate(req.user.id, {
            isOnline: isOnline === true,
            lastActive: new Date()
        });
        
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

module.exports = router;