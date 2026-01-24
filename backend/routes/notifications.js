const express = require('express');
const router = express.Router();
const UserNotification = require('../models/Notification'); // Notificações de usuário
const Alert = require('../models/Alert'); // Alertas do sistema
const Staff = require('../models/Staff'); // Para enviar notificações a staff

// ============ MIDDLEWARE DE AUTENTICAÇÃO ============
const requireAuth = (req, res, next) => {
    if (!req.session || !req.session.staff || !req.session.staff.loggedIn) {
        return res.status(401).json({ success: false, error: 'Não autenticado' });
    }
    req.user = req.session.staff;
    next();
};

router.use(requireAuth);

// ============ ROTAS DE NOTIFICAÇÕES ============

// 1. OBTER NOTIFICAÇÕES DO USUÁRIO
router.get('/', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        
        // Filtros
        const filter = { userId: req.user.id };
        
        if (req.query.type && req.query.type !== 'all') {
            filter.type = req.query.type;
        }
        
        if (req.query.read === 'true') {
            filter.read = true;
        } else if (req.query.read === 'false') {
            filter.read = false;
        }
        
        if (req.query.search) {
            const searchRegex = new RegExp(req.query.search, 'i');
            filter.$or = [
                { title: searchRegex },
                { message: searchRegex }
            ];
        }
        
        // Ordenação
        const sort = { createdAt: -1 }; // Mais recentes primeiro
        
        // Buscar notificações
        const notifications = await UserNotification.find(filter)
            .sort(sort)
            .skip(skip)
            .limit(limit);
        
        // Contar total
        const total = await UserNotification.countDocuments(filter);
        const totalPages = Math.ceil(total / limit);
        
        // Contar não lidas
        const unreadCount = await UserNotification.countDocuments({ 
            userId: req.user.id, 
            read: false 
        });
        
        res.json({
            success: true,
            notifications,
            total,
            totalPages,
            currentPage: page,
            unreadCount,
            stats: {
                total,
                unread: unreadCount,
                read: total - unreadCount
            }
        });
        
    } catch (error) {
        console.error('Erro ao obter notificações:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 2. OBTER ALERTAS DO SISTEMA
router.get('/alerts', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        
        // Filtros para alertas
        const filter = { isResolved: false }; // Apenas alertas não resolvidos
        
        if (req.query.severity && req.query.severity !== 'all') {
            filter.severity = req.query.severity;
        }
        
        if (req.query.type && req.query.type !== 'all') {
            filter.type = req.query.type;
        }
        
        if (req.query.search) {
            const searchRegex = new RegExp(req.query.search, 'i');
            filter.$or = [
                { title: searchRegex },
                { message: searchRegex },
                { playerName: searchRegex }
            ];
        }
        
        // Ordenação
        const sort = { 
            severity: -1, // Críticos primeiro
            createdAt: -1 // Mais recentes primeiro
        };
        
        // Buscar alertas
        const alerts = await Alert.find(filter)
            .sort(sort)
            .skip(skip)
            .limit(limit);
        
        // Contar total
        const total = await Alert.countDocuments(filter);
        const totalPages = Math.ceil(total / limit);
        
        // Estatísticas por severidade
        const criticalCount = await Alert.countDocuments({ 
            ...filter, 
            severity: 'critical' 
        });
        
        const highCount = await Alert.countDocuments({ 
            ...filter, 
            severity: 'high' 
        });
        
        const mediumCount = await Alert.countDocuments({ 
            ...filter, 
            severity: 'medium' 
        });
        
        const lowCount = await Alert.countDocuments({ 
            ...filter, 
            severity: 'low' 
        });
        
        res.json({
            success: true,
            alerts,
            total,
            totalPages,
            currentPage: page,
            stats: {
                total,
                critical: criticalCount,
                high: highCount,
                medium: mediumCount,
                low: lowCount
            }
        });
        
    } catch (error) {
        console.error('Erro ao obter alertas:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 3. MARCAR NOTIFICAÇÃO COMO LIDA
router.post('/:id/read', async (req, res) => {
    try {
        const notificationId = req.params.id;
        
        // Verificar se é um ObjectId válido
        if (!require('mongoose').Types.ObjectId.isValid(notificationId)) {
            return res.status(400).json({
                success: false,
                error: 'ID de notificação inválido'
            });
        }
        
        const notification = await UserNotification.findOneAndUpdate(
            { 
                _id: notificationId, 
                userId: req.user.id 
            },
            { read: true },
            { new: true }
        );
        
        if (!notification) {
            return res.status(404).json({
                success: false,
                error: 'Notificação não encontrada'
            });
        }
        
        res.json({
            success: true,
            message: 'Notificação marcada como lida',
            notification
        });
        
    } catch (error) {
        console.error('Erro ao marcar notificação como lida:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 4. MARCAR TODAS AS NOTIFICAÇÕES COMO LIDAS
router.post('/mark-all-read', async (req, res) => {
    try {
        const result = await UserNotification.updateMany(
            { 
                userId: req.user.id,
                read: false 
            },
            { read: true }
        );
        
        res.json({
            success: true,
            message: `Todas as notificações (${result.modifiedCount}) foram marcadas como lidas`,
            modifiedCount: result.modifiedCount
        });
        
    } catch (error) {
        console.error('Erro ao marcar todas as notificações como lidas:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 5. ELIMINAR NOTIFICAÇÃO
router.delete('/:id', async (req, res) => {
    try {
        const notificationId = req.params.id;
        
        // Verificar se é um ObjectId válido
        if (!require('mongoose').Types.ObjectId.isValid(notificationId)) {
            return res.status(400).json({
                success: false,
                error: 'ID de notificação inválido'
            });
        }
        
        const notification = await UserNotification.findOneAndDelete({
            _id: notificationId,
            userId: req.user.id
        });
        
        if (!notification) {
            return res.status(404).json({
                success: false,
                error: 'Notificação não encontrada'
            });
        }
        
        res.json({
            success: true,
            message: 'Notificação eliminada com sucesso'
        });
        
    } catch (error) {
        console.error('Erro ao eliminar notificação:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 6. ELIMINAR TODAS AS NOTIFICAÇÕES LIDAS
router.delete('/clear-read', async (req, res) => {
    try {
        const result = await UserNotification.deleteMany({
            userId: req.user.id,
            read: true
        });
        
        res.json({
            success: true,
            message: `${result.deletedCount} notificações lidas foram eliminadas`,
            deletedCount: result.deletedCount
        });
        
    } catch (error) {
        console.error('Erro ao eliminar notificações lidas:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 7. CRIAR NOVA NOTIFICAÇÃO
router.post('/create', async (req, res) => {
    try {
        const { title, message, type, userId, link } = req.body;
        
        // Validação
        if (!title || !message) {
            return res.status(400).json({
                success: false,
                error: 'Título e mensagem são obrigatórios'
            });
        }
        
        // Determinar destinatário
        const targetUserId = userId || req.user.id;
        
        // Verificar se o usuário existe (se for enviado para outro usuário)
        if (userId && userId !== req.user.id) {
            const targetUser = await Staff.findById(userId);
            if (!targetUser) {
                return res.status(404).json({
                    success: false,
                    error: 'Utilizador destinatário não encontrado'
                });
            }
        }
        
        // Criar notificação
        const notification = new UserNotification({
            userId: targetUserId,
            title,
            message,
            type: type || 'info',
            read: false,
            link: link || null,
            createdAt: new Date()
        });
        
        await notification.save();
        
        // Enviar via WebSocket se disponível (opcional)
        // broadcastNotification(notification);
        
        res.json({
            success: true,
            message: 'Notificação criada com sucesso',
            notification
        });
        
    } catch (error) {
        console.error('Erro ao criar notificação:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 8. MARCAR ALERTA COMO RESOLVIDO
router.post('/alerts/:id/resolve', async (req, res) => {
    try {
        const alertId = req.params.id;
        const { resolutionNotes } = req.body;
        
        // Verificar se é um ObjectId válido
        if (!require('mongoose').Types.ObjectId.isValid(alertId)) {
            return res.status(400).json({
                success: false,
                error: 'ID de alerta inválido'
            });
        }
        
        const alert = await Alert.findByIdAndUpdate(
            alertId,
            {
                isResolved: true,
                resolvedBy: req.user.name,
                resolvedAt: new Date(),
                metadata: {
                    ...(alert.metadata || {}),
                    resolutionNotes: resolutionNotes || 'Resolvido pelo administrador'
                }
            },
            { new: true }
        );
        
        if (!alert) {
            return res.status(404).json({
                success: false,
                error: 'Alerta não encontrado'
            });
        }
        
        // Criar notificação sobre a resolução do alerta
        const notification = new UserNotification({
            userId: req.user.id,
            title: 'Alerta Resolvido',
            message: `Alerta "${alert.title}" foi marcado como resolvido`,
            type: 'success',
            link: `/logs#alert-${alert._id}`
        });
        await notification.save();
        
        res.json({
            success: true,
            message: 'Alerta marcado como resolvido',
            alert
        });
        
    } catch (error) {
        console.error('Erro ao resolver alerta:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 9. OBTER CONTADORES DE NOTIFICAÇÕES (para badges)
router.get('/counts', async (req, res) => {
    try {
        // Contar notificações não lidas do usuário
        const userUnreadCount = await UserNotification.countDocuments({
            userId: req.user.id,
            read: false
        });
        
        // Contar alertas não resolvidos
        const unresolvedAlerts = await Alert.countDocuments({
            isResolved: false
        });
        
        // Contar alertas críticos
        const criticalAlerts = await Alert.countDocuments({
            isResolved: false,
            severity: 'critical'
        });
        
        // Contar alertas urgentes
        const urgentAlerts = await Alert.countDocuments({
            isResolved: false,
            severity: 'high'
        });
        
        res.json({
            success: true,
            counts: {
                userNotifications: userUnreadCount,
                systemAlerts: unresolvedAlerts,
                criticalAlerts: criticalAlerts,
                urgentAlerts: urgentAlerts,
                total: userUnreadCount + unresolvedAlerts
            }
        });
        
    } catch (error) {
        console.error('Erro ao obter contadores de notificações:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 10. TESTE DE NOTIFICAÇÃO (para desenvolvimento)
router.get('/test', async (req, res) => {
    try {
        // Criar uma notificação de teste
        const testNotification = new UserNotification({
            userId: req.user.id,
            title: 'Notificação de Teste',
            message: `Esta é uma notificação de teste criada em ${new Date().toLocaleString('pt-PT')}`,
            type: 'info',
            read: false
        });
        
        await testNotification.save();
        
        // Criar um alerta de teste
        const testAlert = new Alert({
            type: 'system',
            severity: 'low',
            title: 'Alerta de Teste',
            message: 'Este é um alerta de teste do sistema',
            isResolved: false
        });
        
        await testAlert.save();
        
        res.json({
            success: true,
            message: 'Notificação e alerta de teste criados com sucesso',
            notification: testNotification,
            alert: testAlert
        });
        
    } catch (error) {
        console.error('Erro ao criar notificação de teste:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 11. OBTER NOTIFICAÇÕES RECENTES (para dropdown)
router.get('/recent', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        
        // Notificações do usuário
        const userNotifications = await UserNotification.find({
            userId: req.user.id
        })
        .sort({ createdAt: -1 })
        .limit(limit)
        .lean();
        
        // Alertas do sistema
        const systemAlerts = await Alert.find({
            isResolved: false
        })
        .sort({ 
            severity: -1,
            createdAt: -1 
        })
        .limit(5)
        .lean();
        
        // Combinar e formatar
        const combined = [
            ...userNotifications.map(n => ({
                ...n,
                source: 'user',
                id: n._id.toString(),
                timeAgo: getTimeAgo(n.createdAt)
            })),
            ...systemAlerts.map(a => ({
                ...a,
                source: 'system',
                id: a._id.toString(),
                title: a.title,
                message: a.message,
                type: a.severity === 'critical' ? 'danger' : 
                       a.severity === 'high' ? 'warning' : 'info',
                read: false,
                timeAgo: getTimeAgo(a.createdAt)
            }))
        ].sort((a, b) => new Date(b.createdAt || b.createdAt) - new Date(a.createdAt || a.createdAt))
         .slice(0, limit);
        
        // Contar não lidas
        const unreadCount = await UserNotification.countDocuments({
            userId: req.user.id,
            read: false
        });
        
        res.json({
            success: true,
            notifications: combined,
            unreadCount,
            systemAlertsCount: systemAlerts.length
        });
        
    } catch (error) {
        console.error('Erro ao obter notificações recentes:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// Função auxiliar para tempo relativo
function getTimeAgo(date) {
    if (!date) return 'Agora mesmo';
    
    const now = new Date();
    const diffMs = now - new Date(date);
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHour = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHour / 24);
    
    if (diffSec < 60) return 'Agora mesmo';
    if (diffMin < 60) return `${diffMin} min atrás`;
    if (diffHour < 24) return `${diffHour} h atrás`;
    if (diffDay < 7) return `${diffDay} d atrás`;
    return new Date(date).toLocaleDateString('pt-PT');
}

module.exports = router;