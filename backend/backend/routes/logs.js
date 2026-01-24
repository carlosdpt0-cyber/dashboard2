const express = require('express');
const router = express.Router();
const Log = require('../models/Log');
const User = require('../models/User');
const { isAdmin } = require('../middleware/auth');
const { createLog } = require('../middleware/logger');

// GET /logs - Página principal
router.get('/', isAdmin, async (req, res) => {
    try {
        // Contar logs não lidos
        const unreadLogs = await Log.countDocuments({ read: false });
        
        res.render('logs', {
            title: 'Casino X | Logs do Sistema',
            user: req.user,
            breadcrumb: 'Logs do Sistema',
            unreadLogs
        });
    } catch (error) {
        console.error('Erro ao carregar página de logs:', error);
        res.status(500).render('error', { 
            message: 'Erro ao carregar logs',
            error: req.app.get('env') === 'development' ? error : {}
        });
    }
});

// GET /api/logs - API para listar logs
router.get('/api/logs', isAdmin, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        
        // Construir query de filtros
        const query = {};
        
        if (req.query.user) {
            query.userId = req.query.user;
        }
        
        if (req.query.action) {
            query.action = req.query.action;
        }
        
        if (req.query.module) {
            query.module = req.query.module;
        }
        
        if (req.query.dateFrom || req.query.dateTo) {
            query.timestamp = {};
            if (req.query.dateFrom) {
                query.timestamp.$gte = new Date(req.query.dateFrom);
            }
            if (req.query.dateTo) {
                query.timestamp.$lte = new Date(req.query.dateTo);
            }
        }
        
        if (req.query.search) {
            const searchRegex = new RegExp(req.query.search, 'i');
            query.$or = [
                { 'user.name': searchRegex },
                { 'user.email': searchRegex },
                { message: searchRegex },
                { details: searchRegex },
                { ip: searchRegex },
                { userAgent: searchRegex }
            ];
        }
        
        // Ordenação
        const sort = {};
        const sortField = req.query.sort || 'timestamp';
        const sortOrder = req.query.order === 'asc' ? 1 : -1;
        sort[sortField] = sortOrder;
        
        // Executar queries
        const [logs, total] = await Promise.all([
            Log.find(query)
                .sort(sort)
                .skip(skip)
                .limit(limit)
                .lean(),
            Log.countDocuments(query)
        ]);
        
        // Estatísticas
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const stats = {
            total,
            today: await Log.countDocuments({ 
                timestamp: { $gte: today } 
            }),
            activeAdmins: await User.countDocuments({
                role: 'admin',
                lastActive: { $gte: new Date(Date.now() - 2 * 60 * 60 * 1000) }
            }),
            activityRate: await calculateActivityRate()
        };
        
        res.json({
            success: true,
            logs,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            stats
        });
    } catch (error) {
        console.error('Erro ao buscar logs:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao carregar logs' 
        });
    }
});

// GET /api/logs/:id - Detalhes de um log específico
router.get('/api/logs/:id', isAdmin, async (req, res) => {
    try {
        const log = await Log.findById(req.params.id).lean();
        
        if (!log) {
            return res.status(404).json({ 
                success: false, 
                message: 'Log não encontrado' 
            });
        }
        
        // Marcar como lido
        await Log.findByIdAndUpdate(req.params.id, { read: true });
        
        res.json({ success: true, log });
    } catch (error) {
        console.error('Erro ao buscar log:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao carregar log' 
        });
    }
});

// POST /api/logs/mark-read - Marcar todos como lidos
router.post('/api/logs/mark-read', isAdmin, async (req, res) => {
    try {
        await Log.updateMany(
            { read: false },
            { read: true }
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Erro ao marcar logs como lidos:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao marcar logs como lidos' 
        });
    }
});

// GET /api/logs/users - Listar usuários para filtro
router.get('/api/logs/users', isAdmin, async (req, res) => {
    try {
        const users = await User.find(
            { role: { $in: ['admin', 'moderator'] } },
            'name email role'
        ).lean();
        
        res.json(users);
    } catch (error) {
        console.error('Erro ao buscar usuários:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao carregar usuários' 
        });
    }
});

// POST /api/logs/:id/flag - Reportar log
router.post('/api/logs/:id/flag', isAdmin, async (req, res) => {
    try {
        const log = await Log.findByIdAndUpdate(
            req.params.id,
            { flagged: true },
            { new: true }
        );
        
        if (!log) {
            return res.status(404).json({ 
                success: false, 
                message: 'Log não encontrado' 
            });
        }
        
        // Criar log da flag
        await createLog(
            req.user._id,
            {
                name: req.user.name,
                email: req.user.email,
                role: req.user.role
            },
            'security',
            'system',
            `Log ${req.params.id} reportado para análise`,
            `Reportado por: ${req.user.name}`,
            req
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Erro ao reportar log:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao reportar log' 
        });
    }
});

// POST /api/logs/cleanup - Limpar logs antigos
router.post('/api/logs/cleanup', isAdmin, async (req, res) => {
    try {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - 90); // 90 dias atrás
        
        const result = await Log.deleteMany({
            timestamp: { $lt: cutoffDate },
            flagged: false // Manter logs reportados
        });
        
        // Log da ação de limpeza
        await createLog(
            req.user._id,
            {
                name: req.user.name,
                email: req.user.email,
                role: req.user.role
            },
            'delete',
            'system',
            `Limpeza de logs antigos realizada`,
            `${result.deletedCount} logs removidos`,
            req
        );
        
        res.json({ 
            success: true, 
            deletedCount: result.deletedCount 
        });
    } catch (error) {
        console.error('Erro ao limpar logs:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao limpar logs' 
        });
    }
});

// GET /api/logs/export - Exportar logs
router.get('/api/logs/export', isAdmin, async (req, res) => {
    try {
        // Construir query (mesmo filtros da listagem)
        const query = {};
        
        if (req.query.user) {
            query.userId = req.query.user;
        }
        
        if (req.query.action) {
            query.action = req.query.action;
        }
        
        if (req.query.module) {
            query.module = req.query.module;
        }
        
        if (req.query.dateFrom || req.query.dateTo) {
            query.timestamp = {};
            if (req.query.dateFrom) {
                query.timestamp.$gte = new Date(req.query.dateFrom);
            }
            if (req.query.dateTo) {
                query.timestamp.$lte = new Date(req.query.dateTo);
            }
        }
        
        const logs = await Log.find(query).sort({ timestamp: -1 }).lean();
        
        switch (req.query.format) {
            case 'csv':
                exportCSV(logs, res);
                break;
            case 'json':
                exportJSON(logs, res);
                break;
            case 'pdf':
                exportPDF(logs, res);
                break;
            default:
                res.status(400).json({ 
                    success: false, 
                    message: 'Formato inválido' 
                });
        }
    } catch (error) {
        console.error('Erro ao exportar logs:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Erro ao exportar logs' 
        });
    }
});

// Funções auxiliares
async function calculateActivityRate() {
    const lastHour = new Date(Date.now() - 60 * 60 * 1000);
    const count = await Log.countDocuments({ 
        timestamp: { $gte: lastHour } 
    });
    
    return `${(count / 60).toFixed(1)}/min`;
}

function exportCSV(logs, res) {
    const headers = ['Data/Hora', 'Usuário', 'Email', 'Função', 'Ação', 'Módulo', 'Mensagem', 'IP', 'Localização', 'User Agent'];
    
    let csv = headers.join(',') + '\n';
    
    logs.forEach(log => {
        const row = [
            `"${new Date(log.timestamp).toISOString()}"`,
            `"${log.user.name}"`,
            `"${log.user.email}"`,
            `"${log.user.role}"`,
            `"${log.action}"`,
            `"${log.module}"`,
            `"${log.message.replace(/"/g, '""')}"`,
            `"${log.ip || ''}"`,
            `"${log.location || ''}"`,
            `"${log.userAgent || ''}"`
        ];
        csv += row.join(',') + '\n';
    });
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=logs-${new Date().toISOString().split('T')[0]}.csv`);
    res.send(csv);
}

function exportJSON(logs, res) {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=logs-${new Date().toISOString().split('T')[0]}.json`);
    res.send(JSON.stringify(logs, null, 2));
}

function exportPDF(logs, res) {
    // Implementar geração de PDF com pdfkit ou similar
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=logs-${new Date().toISOString().split('T')[0]}.pdf`);
    
    // Placeholder - implementar geração real de PDF
    res.send('PDF export functionality to be implemented');
}

module.exports = router;