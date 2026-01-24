// backend/controllers/dashboardController.js
const Ticket = require('../models/Ticket');
const Player = require('../models/Player');
const Withdrawal = require('../models/Withdrawal');
const Email = require('../models/Email');

exports.getDashboard = async (req, res) => {
    try {
        const user = req.user;
        
        if (!user) {
            return res.redirect('/login');
        }
        
        // SE FOR OPERADOR, redireciona para dashboard do operador
        if (user.role === 'operator') {
            return exports.getOperatorDashboard(req, res);
        }
        
        // Resto do código para admin/staff...
        const recentPlayers = await Player.find()
            .sort({ createdAt: -1 })
            .limit(10)
            .select('name email balance status playerId');
        
        // ... resto do código admin
        
    } catch (error) {
        console.error('Erro no dashboard:', error);
        res.status(500).send('Erro ao carregar dashboard');
    }
};

// ADICIONAR ESTA FUNÇÃO NO MESMO ARQUIVO
exports.getOperatorDashboard = async (req, res) => {
    try {
        const user = req.user;
        
        // Dados para operador
        const stats = {
            openTickets: await Ticket.countDocuments({ status: 'open' }),
            assignedTickets: await Ticket.countDocuments({ assignedTo: user._id }),
            recentEmails: await Email.countDocuments({ sentBy: user._id }),
            totalTickets: await Ticket.countDocuments()
        };
        
        const recentTickets = await Ticket.find({ assignedTo: user._id })
            .sort({ createdAt: -1 })
            .limit(10)
            .populate('player', 'name email')
            .lean();
        
        const formattedTickets = recentTickets.map(ticket => ({
            _id: ticket._id,
            ticketId: ticket.ticketId || `TICKET${ticket._id.toString().slice(-6)}`,
            playerName: ticket.player ? ticket.player.name : 'Jogador',
            subject: ticket.subject || 'Sem assunto',
            priority: ticket.priority || 'medium',
            status: ticket.status || 'open'
        }));
        
        const recentEmails = await Email.find({ sentBy: user._id })
            .sort({ sentAt: -1 })
            .limit(5)
            .lean();
        
        res.render('dashboard', {
            title: 'Dashboard Operador',
            user: user,
            stats: stats,
            recentTickets: formattedTickets,
            recentEmails: recentEmails,
            recentPlayers: [], // ← OPERADORES NÃO VEEM JOGADORES
            recentWithdrawals: [], // ← OPERADORES NÃO VEEM LEVANTAMENTOS
            acceptedConfidentiality: user.acceptedConfidentiality || false
        });
        
    } catch (error) {
        console.error('Erro no dashboard do operador:', error);
        res.status(500).render('error', { error: 'Erro ao carregar dashboard' });
    }
};