const express = require('express');
const router = express.Router();
const axios = require('axios');
const casinoController = require('../controllers/casinoController');

// Middleware para verificar token do casino
const casinoAuth = async (req, res, next) => {
    try {
        const token = req.session.casinoToken || req.headers['x-casino-token'];
        
        if (!token) {
            return res.status(401).json({ error: 'Token do casino não fornecido' });
        }
        
        // Verificar token com API do casino
        const response = await axios.get(`${process.env.CASINO_API_URL}/auth/verify`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (response.data.valid) {
            next();
        } else {
            res.status(401).json({ error: 'Token inválido' });
        }
    } catch (error) {
        console.error('Erro na autenticação do casino:', error);
        res.status(500).json({ error: 'Erro na autenticação' });
    }
};

// Rotas protegidas
router.use(casinoAuth);

// Obter dados do casino
router.get('/stats', async (req, res) => {
    try {
        const stats = await casinoController.getCasinoStats();
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Obter jogadores
router.get('/players', async (req, res) => {
    try {
        const { page = 1, limit = 20, search = '', status = '' } = req.query;
        const players = await casinoController.getPlayers(page, limit, search, status);
        res.json(players);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Obter levantamentos
router.get('/withdrawals', async (req, res) => {
    try {
        const { status = 'pending', page = 1, limit = 20 } = req.query;
        const withdrawals = await casinoController.getWithdrawals(status, page, limit);
        res.json(withdrawals);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Obter transações
router.get('/transactions', async (req, res) => {
    try {
        const { type = 'all', startDate, endDate, userId } = req.query;
        const transactions = await casinoController.getTransactions(type, startDate, endDate, userId);
        res.json(transactions);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Obter tickets de suporte
router.get('/support/tickets', async (req, res) => {
    try {
        const { status = 'open', department = 'all', page = 1 } = req.query;
        const tickets = await casinoController.getSupportTickets(status, department, page);
        res.json(tickets);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Atualizar status do ticket
router.put('/support/tickets/:id', async (req, res) => {
    try {
        const { status, assignedTo, response } = req.body;
        const result = await casinoController.updateTicket(req.params.id, status, assignedTo, response);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Processar levantamento
router.post('/withdrawals/:id/process', async (req, res) => {
    try {
        const { action, reason } = req.body; // action: 'approve', 'reject'
        const result = await casinoController.processWithdrawal(req.params.id, action, reason);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Obter logs
router.get('/logs', async (req, res) => {
    try {
        const { type = 'all', startDate, endDate } = req.query;
        const logs = await casinoController.getLogs(type, startDate, endDate);
        res.json(logs);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// WebSocket connection endpoint
router.get('/ws/token', (req, res) => {
    // Gerar token para conexão WebSocket
    const wsToken = casinoController.generateWebSocketToken(req.session.userId);
    res.json({ token: wsToken });
});

module.exports = router;