const express = require('express');
const router = express.Router();
const Player = require('../models/Player');
const Withdrawal = require('../models/Withdrawal');
const Ticket = require('../models/Ticket');
const Email = require('../models/Email');
const Staff = require('../models/Staff');

// Middleware para verificar autenticação
const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
};

// Middleware para passar dados do usuário
router.use(requireAuth, (req, res, next) => {
    res.locals.user = req.session.user;
    next();
});

// Dashboard PRINCIPAL (para administradores)
router.get('/', async (req, res) => {
    try {
        const user = req.session.user;
        
        // Se for operador, redirecionar para dashboard de operador
        if (user.role === 'operator') {
            return res.redirect('/operator-dashboard');
        }

        // Buscar estatísticas em tempo real PARA ADMINISTRADORES
        const [
            totalPlayers,
            onlinePlayers,
            pendingWithdrawals,
            pendingWithdrawalsAmount,
            recentPlayers,
            recentWithdrawals,
            openTickets,
            recentTickets
        ] = await Promise.all([
            // 1. Total de jogadores
            Player.countDocuments(),
            
            // 2. Jogadores online (últimos 15 minutos)
            Player.countDocuments({ 
                status: 'active', 
                lastActivity: { $gt: new Date(Date.now() - 15 * 60 * 1000) } 
            }),
            
            // 3. Levantamentos pendentes
            Withdrawal.countDocuments({ status: 'pending' }),
            
            // 4. Valor total dos levantamentos pendentes
            Withdrawal.aggregate([
                { $match: { status: 'pending' } },
                { $group: { _id: null, total: { $sum: '$amount' } } }
            ]),
            
            // 5. Jogadores recentes (últimos 5)
            Player.find()
                .sort({ createdAt: -1 })
                .limit(5)
                .select('playerId username email balance status lastActivity createdAt'),
            
            // 6. Levantamentos recentes (últimos 5 pendentes)
            Withdrawal.find({ status: 'pending' })
                .sort({ createdAt: -1 })
                .limit(5)
                .populate('player', 'username email')
                .select('playerUsername amount status paymentMethod createdAt'),
            
            // 7. Tickets abertos
            Ticket.countDocuments({ status: 'open' }),
            
            // 8. Tickets recentes
            Ticket.find({ status: 'open' })
                .sort({ createdAt: -1 })
                .limit(5)
                .populate('player', 'username')
        ]);

        // Calcular valores
        const withdrawalsAmount = pendingWithdrawalsAmount[0] ? pendingWithdrawalsAmount[0].total : 0;
        const playerPercentage = totalPlayers > 0 ? Math.round((onlinePlayers / totalPlayers) * 100) : 0;

        // Buscar emails recentes (última semana)
        const recentEmails = await Email.find({
            sentAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        })
        .sort({ sentAt: -1 })
        .limit(5);

        // Estatísticas completas para administradores
        const stats = {
            totalPlayers,
            onlinePlayers,
            pendingWithdrawals,
            withdrawalsAmount,
            playerPercentage,
            unresolvedAlerts: 0, // Você pode adicionar um modelo Alert se precisar
            openTickets,
            assignedTickets: 0, // Administradores não têm tickets atribuídos
            recentEmails: recentEmails.length
        };

        res.render('dashboard', {
            title: 'Dashboard - B7Uno Casino',
            breadcrumb: 'Dashboard Principal',
            stats: stats,
            recentPlayers,
            recentWithdrawals,
            recentTickets,
            recentEmails,
            acceptedConfidentiality: user.acceptedConfidentiality || false,
            user: user
        });
    } catch (error) {
        console.error('Erro ao carregar dashboard:', error);
        res.render('dashboard', {
            title: 'Dashboard - B7Uno Casino',
            breadcrumb: 'Dashboard',
            stats: {
                totalPlayers: 0,
                onlinePlayers: 0,
                pendingWithdrawals: 0,
                withdrawalsAmount: 0,
                playerPercentage: 0,
                unresolvedAlerts: 0,
                openTickets: 0,
                assignedTickets: 0,
                recentEmails: 0
            },
            recentPlayers: [],
            recentWithdrawals: [],
            recentTickets: [],
            recentEmails: [],
            acceptedConfidentiality: false,
            user: req.session.user,
            error: 'Erro ao carregar dados'
        });
    }
});

// Dashboard do OPERADOR
router.get('/operator-dashboard', async (req, res) => {
    try {
        const user = req.session.user;
        
        // Verificar se realmente é operador
        if (user.role !== 'operator') {
            return res.redirect('/dashboard');
        }

        // Buscar estatísticas ESPECÍFICAS PARA OPERADORES
        const [
            openTickets,
            assignedTickets,
            recentTickets,
            recentEmails
        ] = await Promise.all([
            // 1. Total de tickets abertos
            Ticket.countDocuments({ status: 'open' }),
            
            // 2. Tickets atribuídos a este operador
            Ticket.countDocuments({ 
                status: { $in: ['open', 'in_progress'] },
                assignedTo: user._id
            }),
            
            // 3. Tickets recentes
            Ticket.find({ status: 'open' })
                .sort({ createdAt: -1 })
                .limit(10)
                .populate('player', 'username email')
                .select('ticketId subject priority status createdAt'),
            
            // 4. Emails recentes (última semana)
            Email.find({
                sentAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
            })
            .sort({ sentAt: -1 })
            .limit(5)
        ]);

        // Estatísticas específicas para operadores
        const stats = {
            openTickets,
            assignedTickets,
            recentEmails: recentEmails.length,
            // Operadores NÃO precisam destes campos:
            pendingWithdrawals: 0,
            onlinePlayers: 0,
            totalPlayers: 0,
            unresolvedAlerts: 0,
            withdrawalsAmount: 0,
            playerPercentage: 0
        };

        // Calcular tempo médio de resposta (exemplo)
        const responseTime = '2.4h'; // Você pode calcular isso com dados reais

        res.render('dashboard', {
            title: 'Dashboard Operador - B7Uno Casino',
            breadcrumb: 'Dashboard Operador',
            stats: stats,
            recentTickets,
            recentEmails,
            recentPlayers: [], // Operadores não veem jogadores
            recentWithdrawals: [], // Operadores não veem levantamentos
            responseTime: responseTime,
            acceptedConfidentiality: user.acceptedConfidentiality || false,
            user: user
        });
    } catch (error) {
        console.error('Erro ao carregar dashboard do operador:', error);
        res.render('dashboard', {
            title: 'Dashboard Operador - B7Uno Casino',
            breadcrumb: 'Dashboard Operador',
            stats: {
                openTickets: 0,
                assignedTickets: 0,
                recentEmails: 0,
                pendingWithdrawals: 0,
                onlinePlayers: 0,
                totalPlayers: 0,
                unresolvedAlerts: 0,
                withdrawalsAmount: 0,
                playerPercentage: 0
            },
            recentTickets: [],
            recentEmails: [],
            recentPlayers: [],
            recentWithdrawals: [],
            acceptedConfidentiality: false,
            user: req.session.user,
            error: 'Erro ao carregar dados do operador'
        });
    }
});

// Página de jogadores (apenas para administradores)
router.get('/players', async (req, res) => {
    try {
        const user = req.session.user;
        
        // Operadores não podem acessar esta página
        if (user.role === 'operator') {
            return res.redirect('/operator-dashboard');
        }

        const { page = 1, limit = 20, search = '', status = '' } = req.query;
        const skip = (page - 1) * limit;

        // Construir query
        let query = {};
        
        if (search) {
            query.$or = [
                { username: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { playerId: search }
            ];
        }

        if (status) {
            query.status = status;
        }

        // Buscar jogadores
        const [players, totalPlayers] = await Promise.all([
            Player.find(query)
                .sort({ lastActivity: -1 })
                .skip(skip)
                .limit(parseInt(limit))
                .select('playerId username email balance status kycStatus country lastActivity registrationDate'),
            Player.countDocuments(query)
        ]);

        res.render('pages/jogadores', {
            title: 'Jogadores - B7Uno Casino',
            breadcrumb: 'Jogadores',
            players,
            pagination: {
                total: totalPlayers,
                page: parseInt(page),
                limit: parseInt(limit),
                pages: Math.ceil(totalPlayers / limit)
            },
            search,
            status,
            user: user
        });
    } catch (error) {
        console.error('Erro ao carregar jogadores:', error);
        res.render('pages/jogadores', {
            title: 'Jogadores - B7Uno Casino',
            breadcrumb: 'Jogadores',
            players: [],
            pagination: {
                total: 0,
                page: 1,
                limit: 20,
                pages: 0
            },
            search: '',
            status: '',
            user: req.session.user,
            error: 'Erro ao carregar jogadores'
        });
    }
});

// Página de levantamentos (apenas para administradores)
router.get('/withdrawals', async (req, res) => {
    try {
        const user = req.session.user;
        
        // Operadores não podem acessar esta página
        if (user.role === 'operator') {
            return res.redirect('/operator-dashboard');
        }

        const { status = 'pending', page = 1, limit = 20 } = req.query;
        const skip = (page - 1) * limit;

        const [withdrawals, totalWithdrawals, summary] = await Promise.all([
            Withdrawal.find({ status })
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(parseInt(limit))
                .populate('processedBy', 'name email')
                .select('playerUsername amount status paymentMethod paymentDetails createdAt processedAt processedBy rejectionReason'),
            Withdrawal.countDocuments({ status }),
            Withdrawal.aggregate([
                { $match: { status } },
                { 
                    $group: {
                        _id: null,
                        totalAmount: { $sum: '$amount' },
                        averageAmount: { $avg: '$amount' },
                        count: { $sum: 1 }
                    }
                }
            ])
        ]);

        const summaryData = summary[0] || {
            totalAmount: 0,
            averageAmount: 0,
            count: 0
        };

        res.render('pages/levantamentos', {
            title: 'Levantamentos - B7Uno Casino',
            breadcrumb: 'Levantamentos',
            withdrawals,
            status,
            pagination: {
                total: totalWithdrawals,
                page: parseInt(page),
                limit: parseInt(limit),
                pages: Math.ceil(totalWithdrawals / limit)
            },
            summary: summaryData,
            user: user
        });
    } catch (error) {
        console.error('Erro ao carregar levantamentos:', error);
        res.render('pages/levantamentos', {
            title: 'Levantamentos - B7Uno Casino',
            breadcrumb: 'Levantamentos',
            withdrawals: [],
            status: 'pending',
            pagination: {
                total: 0,
                page: 1,
                limit: 20,
                pages: 0
            },
            summary: {
                totalAmount: 0,
                averageAmount: 0,
                count: 0
            },
            user: req.session.user,
            error: 'Erro ao carregar levantamentos'
        });
    }
});

// Detalhes do jogador (apenas para administradores)
router.get('/players/:id', async (req, res) => {
    try {
        const user = req.session.user;
        
        // Operadores não podem acessar esta página
        if (user.role === 'operator') {
            return res.redirect('/operator-dashboard');
        }

        const player = await Player.findOne({ playerId: req.params.id });
        
        if (!player) {
            return res.status(404).render('error', {
                title: 'Jogador Não Encontrado',
                message: 'O jogador não foi encontrado.',
                error: { status: 404 }
            });
        }

        // Buscar levantamentos do jogador
        const withdrawals = await Withdrawal.find({ playerId: req.params.id })
            .sort({ createdAt: -1 })
            .limit(10);

        res.render('pages/jogador-detalhes', {
            title: `${player.username} - B7Uno Casino`,
            breadcrumb: `Jogadores › ${player.username}`,
            player,
            withdrawals,
            user: user
        });
    } catch (error) {
        console.error('Erro ao carregar detalhes do jogador:', error);
        res.status(500).render('error', {
            title: 'Erro Interno',
            message: 'Erro ao carregar detalhes do jogador.',
            error: { status: 500 }
        });
    }
});

// Página de perfil do usuário (todos os roles)
router.get('/profile', (req, res) => {
    res.render('pages/profile', {
        title: 'Meu Perfil - B7Uno Casino',
        breadcrumb: 'Meu Perfil',
        user: req.session.user
    });
});

module.exports = router;