// routes/admin/support.js
const express = require('express');
const router = express.Router();
const SupportTicket = require('../../models/SupportTicket'); // Ajuste o caminho conforme necessário

// Middleware de autenticação admin (implemente conforme sua necessidade)
const { isAdmin } = require('../../middleware/auth');

// Rota principal do suporte
router.get('/support', isAdmin, async (req, res) => {
    try {
        const { status, priority, assignedTo } = req.query;
        
        // Construir filtros
        const filter = {};
        if (status) filter.status = status;
        if (priority) filter.priority = priority;
        if (assignedTo) filter.assignedTo = assignedTo;
        
        // Buscar tickets com filtros
        const tickets = await SupportTicket.find(filter)
            .sort({ createdAt: -1 })
            .limit(50);
        
        // Estatísticas
        const ticketsStats = {
            open: await SupportTicket.countDocuments({ status: 'open' }),
            inProgress: await SupportTicket.countDocuments({ status: 'in-progress' }),
            assigned: await SupportTicket.countDocuments({ assignedTo: { $ne: null } }),
            resolved: await SupportTicket.countDocuments({ status: 'resolved' })
        };
        
        res.render('admin/support', {
            tickets,
            ticketsStats,
            filters: req.query
        });
        
    } catch (error) {
        console.error('Error fetching tickets:', error);
        res.status(500).render('error', { message: 'Erro ao carregar tickets' });
    }
});

// Rota para atribuir ticket a operador
router.post('/support/assign/:id', isAdmin, async (req, res) => {
    try {
        const { operator, message } = req.body;
        
        const ticket = await SupportTicket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ error: 'Ticket não encontrado' });
        }
        
        // Atualizar ticket
        ticket.assignedTo = operator;
        ticket.status = 'in-progress';
        
        // Adicionar mensagem de atribuição se existir
        if (message) {
            ticket.messages = ticket.messages || [];
            ticket.messages.push({
                sender: 'system',
                message: `Ticket atribuído a ${operator}: ${message}`,
                timestamp: new Date()
            });
        }
        
        await ticket.save();
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Error assigning ticket:', error);
        res.status(500).json({ error: 'Erro ao atribuir ticket' });
    }
});

// Rota para atualizar status
router.post('/support/status/:id', isAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        
        await SupportTicket.findByIdAndUpdate(req.params.id, { status });
        res.json({ success: true });
        
    } catch (error) {
        console.error('Error updating ticket status:', error);
        res.status(500).json({ error: 'Erro ao atualizar estado' });
    }
});

// Rota para ver detalhes do ticket
router.get('/support/ticket/:id', isAdmin, async (req, res) => {
    try {
        const ticket = await SupportTicket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).render('error', { message: 'Ticket não encontrado' });
        }
        
        res.render('admin/ticket-details', { ticket });
        
    } catch (error) {
        console.error('Error fetching ticket details:', error);
        res.status(500).render('error', { message: 'Erro ao carregar ticket' });
    }
});

module.exports = router;