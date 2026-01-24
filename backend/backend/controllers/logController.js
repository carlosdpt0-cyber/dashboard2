const Log = require('../models/Log');
const User = require('../models/User');
const fs = require('fs');
const path = require('path');
const { Parser } = require('json2csv');
const PDFDocument = require('pdfkit');

// Obter todos os logs
exports.getLogs = async (req, res) => {
    try {
        const { 
            page = 1, 
            limit = 20, 
            sort = 'timestamp', 
            order = 'desc',
            user,
            action,
            module,
            dateFrom,
            dateTo,
            search
        } = req.query;

        // Construir filtros
        const filter = {};
        
        if (user && user !== '') {
            filter['user._id'] = user;
        }
        
        if (action && action !== '') {
            filter.action = action;
        }
        
        if (module && module !== '') {
            filter.module = module;
        }
        
        // Filtro de data
        if (dateFrom || dateTo) {
            filter.timestamp = {};
            if (dateFrom) {
                filter.timestamp.$gte = new Date(dateFrom);
            }
            if (dateTo) {
                filter.timestamp.$lte = new Date(dateTo + 'T23:59:59.999Z');
            }
        }
        
        // Filtro de pesquisa
        if (search && search !== '') {
            filter.$or = [
                { message: { $regex: search, $options: 'i' } },
                { 'user.name': { $regex: search, $options: 'i' } },
                { ip: { $regex: search, $options: 'i' } },
                { details: { $regex: search, $options: 'i' } }
            ];
        }

        // Calcular totais para estatísticas
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const totalLogs = await Log.countDocuments(filter);
        const todayLogs = await Log.countDocuments({
            ...filter,
            timestamp: { $gte: today }
        });
        
        // Calcular administradores ativos (últimas 2 horas)
        const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);
        const activeAdmins = await Log.distinct('user._id', {
            'user.role': { $in: ['admin', 'superadmin'] },
            action: 'login',
            timestamp: { $gte: twoHoursAgo }
        });

        // Calcular taxa de atividade (logs por minuto nas últimas 2 horas)
        const lastTwoHours = await Log.countDocuments({
            timestamp: { $gte: twoHoursAgo }
        });
        const activityRate = (lastTwoHours / 120).toFixed(1); // 2 horas = 120 minutos

        // Paginação
        const skip = (page - 1) * limit;
        
        // Ordenação
        const sortOptions = {};
        sortOptions[sort] = order === 'desc' ? -1 : 1;

        // Buscar logs com paginação
        const logs = await Log.find(filter)
            .sort(sortOptions)
            .skip(skip)
            .limit(parseInt(limit))
            .lean();

        // Calcular total de páginas
        const totalPages = Math.ceil(totalLogs / limit);

        res.json({
            success: true,
            logs,
            page: parseInt(page),
            pages: totalPages,
            total: totalLogs,
            stats: {
                total: totalLogs,
                today: todayLogs,
                activeAdmins: activeAdmins.length,
                activityRate: `${activityRate}/min`
            }
        });
    } catch (error) {
        console.error('Erro ao buscar logs:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao carregar logs'
        });
    }
};

// Obter um log específico
exports.getLog = async (req, res) => {
    try {
        const log = await Log.findById(req.params.id).lean();
        
        if (!log) {
            return res.status(404).json({
                success: false,
                message: 'Log não encontrado'
            });
        }
        
        res.json({
            success: true,
            log
        });
    } catch (error) {
        console.error('Erro ao buscar log:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao buscar log'
        });
    }
};

// Obter lista de utilizadores para filtro
exports.getUsersForFilter = async (req, res) => {
    try {
        const users = await User.find({}, '_id name role')
            .sort({ name: 1 })
            .lean();
        
        res.json({
            success: true,
            users
        });
    } catch (error) {
        console.error('Erro ao buscar utilizadores:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao carregar utilizadores'
        });
    }
};

// Exportar logs
exports.exportLogs = async (req, res) => {
    try {
        const { format, user, action, module, dateFrom, dateTo, search } = req.query;

        // Construir filtros (igual ao getLogs)
        const filter = {};
        
        if (user && user !== '') {
            filter['user._id'] = user;
        }
        
        if (action && action !== '') {
            filter.action = action;
        }
        
        if (module && module !== '') {
            filter.module = module;
        }
        
        if (dateFrom || dateTo) {
            filter.timestamp = {};
            if (dateFrom) {
                filter.timestamp.$gte = new Date(dateFrom);
            }
            if (dateTo) {
                filter.timestamp.$lte = new Date(dateTo + 'T23:59:59.999Z');
            }
        }
        
        if (search && search !== '') {
            filter.$or = [
                { message: { $regex: search, $options: 'i' } },
                { 'user.name': { $regex: search, $options: 'i' } },
                { ip: { $regex: search, $options: 'i' } },
                { details: { $regex: search, $options: 'i' } }
            ];
        }

        // Buscar logs sem paginação para exportação
        const logs = await Log.find(filter)
            .sort({ timestamp: -1 })
            .lean();

        const timestamp = new Date().toISOString().split('T')[0];
        
        switch (format) {
            case 'csv':
                await exportToCSV(logs, res, timestamp);
                break;
                
            case 'json':
                await exportToJSON(logs, res, timestamp);
                break;
                
            case 'pdf':
                await exportToPDF(logs, res, timestamp);
                break;
                
            default:
                res.status(400).json({
                    success: false,
                    message: 'Formato de exportação não suportado'
                });
        }
    } catch (error) {
        console.error('Erro ao exportar logs:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao exportar logs'
        });
    }
};

// Funções auxiliares para exportação
async function exportToCSV(logs, res, timestamp) {
    try {
        // Preparar dados para CSV
        const csvData = logs.map(log => ({
            Data: new Date(log.timestamp).toLocaleString('pt-PT'),
            Utilizador: log.user?.name || 'Sistema',
            Função: log.user?.role || 'Sistema',
            Ação: getActionLabel(log.action),
            Módulo: getModuleLabel(log.module),
            Mensagem: log.message,
            Detalhes: log.details || '',
            IP: log.ip || '',
            Localização: log.location || '',
            'User Agent': log.userAgent || ''
        }));

        const fields = [
            'Data',
            'Utilizador',
            'Função',
            'Ação',
            'Módulo',
            'Mensagem',
            'Detalhes',
            'IP',
            'Localização',
            'User Agent'
        ];

        const json2csvParser = new Parser({ fields, delimiter: ';' });
        const csv = json2csvParser.parse(csvData);

        res.header('Content-Type', 'text/csv');
        res.attachment(`logs_${timestamp}.csv`);
        res.send(csv);
    } catch (error) {
        throw error;
    }
}

async function exportToJSON(logs, res, timestamp) {
    const exportData = {
        exportDate: new Date().toISOString(),
        totalLogs: logs.length,
        logs: logs.map(log => ({
            ...log,
            timestamp: new Date(log.timestamp).toISOString()
        }))
    };

    res.header('Content-Type', 'application/json');
    res.attachment(`logs_${timestamp}.json`);
    res.send(JSON.stringify(exportData, null, 2));
}

async function exportToPDF(logs, res, timestamp) {
    const doc = new PDFDocument({ margin: 50 });
    
    res.header('Content-Type', 'application/pdf');
    res.attachment(`logs_${timestamp}.pdf`);
    
    doc.pipe(res);
    
    // Cabeçalho
    doc.fontSize(20).text('B7Uno Casino - Logs do Sistema', { align: 'center' });
    doc.moveDown();
    doc.fontSize(12).text(`Data de exportação: ${new Date().toLocaleString('pt-PT')}`);
    doc.text(`Total de logs: ${logs.length}`);
    doc.moveDown();
    
    // Linha separadora
    doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
    doc.moveDown();
    
    // Conteúdo
    logs.forEach((log, index) => {
        if (index > 0) {
            doc.addPage();
        }
        
        doc.fontSize(14).text(`Log #${index + 1}`, { underline: true });
        doc.moveDown(0.5);
        
        doc.fontSize(10).text(`Data/Hora: ${new Date(log.timestamp).toLocaleString('pt-PT')}`);
        doc.text(`Utilizador: ${log.user?.name || 'Sistema'} (${log.user?.role || 'Sistema'})`);
        doc.text(`Ação: ${getActionLabel(log.action)}`);
        doc.text(`Módulo: ${getModuleLabel(log.module)}`);
        doc.text(`IP: ${log.ip || 'N/A'}`);
        
        doc.moveDown();
        doc.fontSize(11).text('Mensagem:', { underline: true });
        doc.fontSize(10).text(log.message || 'Sem mensagem');
        
        if (log.details) {
            doc.moveDown();
            doc.fontSize(11).text('Detalhes:', { underline: true });
            doc.fontSize(10).text(log.details);
        }
        
        doc.moveDown();
        doc.fontSize(9).text('---', { align: 'center' });
    });
    
    doc.end();
}

// Limpar logs antigos
exports.cleanupLogs = async (req, res) => {
    try {
        const { days = 90 } = req.body;
        
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);
        
        // Manter sempre os últimos 1000 logs, mesmo que sejam mais antigos
        const result = await Log.deleteMany({
            timestamp: { $lt: cutoffDate },
            _id: { 
                $nin: await Log.find()
                    .sort({ timestamp: -1 })
                    .limit(1000)
                    .select('_id')
                    .then(logs => logs.map(l => l._id))
            }
        });
        
        // Log da ação de limpeza
        await Log.create({
            user: req.user,
            action: 'delete',
            module: 'logs',
            message: `Limpeza automática de logs com mais de ${days} dias`,
            details: `${result.deletedCount} logs removidos`,
            ip: req.ip,
            userAgent: req.headers['user-agent']
        });
        
        res.json({
            success: true,
            message: 'Logs antigos removidos com sucesso',
            deletedCount: result.deletedCount,
            cutoffDate: cutoffDate
        });
    } catch (error) {
        console.error('Erro ao limpar logs:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao limpar logs'
        });
    }
};

// Marcar logs como lidos
exports.markLogsAsRead = async (req, res) => {
    try {
        // Aqui você pode implementar lógica para marcar logs como lidos
        // Por exemplo, atualizar um campo 'read' ou limpar notificações
        
        res.json({
            success: true,
            message: 'Logs marcados como lidos'
        });
    } catch (error) {
        console.error('Erro ao marcar logs como lidos:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao marcar logs como lidos'
        });
    }
};

// Funções auxiliares
function getActionLabel(action) {
    const actions = {
        'login': 'Login',
        'logout': 'Logout',
        'create': 'Criar',
        'update': 'Atualizar',
        'delete': 'Eliminar',
        'security': 'Segurança',
        'system': 'Sistema',
        'deposit': 'Depósito',
        'withdrawal': 'Levantamento',
        'bonus': 'Bónus',
        'game': 'Jogo'
    };
    return actions[action] || action;
}

function getModuleLabel(module) {
    const modules = {
        'auth': 'Autenticação',
        'players': 'Jogadores',
        'withdrawals': 'Levantamentos',
        'deposits': 'Depósitos',
        'payments': 'Pagamentos',
        'staff': 'Staff',
        'settings': 'Definições',
        'system': 'Sistema',
        'games': 'Jogos',
        'bonuses': 'Bónus',
        'reports': 'Relatórios'
    };
    return modules[module] || module;
}