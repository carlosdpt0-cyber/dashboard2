// backend/routes/withdrawals.js
const express = require('express');
const router = express.Router();
const Withdrawal = require('../models/Withdrawal');
const User = require('../models/User');

// GET /withdrawals - Listar levantamentos
router.get('/', async (req, res) => {
    try {
        const { page = 1, limit = 10, status, method, search, sort } = req.query;
        const skip = (page - 1) * limit;
        
        // Construir filtro
        let filter = {};
        
        if (status && status !== 'all') {
            filter.status = status;
        }
        
        if (method && method !== 'all') {
            filter.method = method;
        }
        
        if (search) {
            filter.$or = [
                { transactionId: { $regex: search, $options: 'i' } },
                { 'player.name': { $regex: search, $options: 'i' } },
                { 'player.email': { $regex: search, $options: 'i' } }
            ];
        }
        
        // Ordenação
        let sortOption = { createdAt: -1 };
        if (sort === 'oldest') sortOption = { createdAt: 1 };
        if (sort === 'amount_high') sortOption = { amount: -1 };
        if (sort === 'amount_low') sortOption = { amount: 1 };
        if (sort === 'urgent') {
            // Ordenar por mais antigos primeiro (mais urgentes)
            sortOption = { createdAt: 1 };
        }
        
        // Buscar levantamentos com populate do jogador
        const withdrawals = await Withdrawal.find(filter)
            .populate('player', 'name email username balance verificationLevel')
            .skip(skip)
            .limit(parseInt(limit))
            .sort(sortOption);
        
        // Contar total
        const total = await Withdrawal.countDocuments(filter);
        
        // Calcular estatísticas
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);
        
        const stats = {
            total: await Withdrawal.countDocuments({}),
            pending: await Withdrawal.countDocuments({ status: 'pending' }),
            approved: await Withdrawal.countDocuments({ status: 'approved' }),
            today: await Withdrawal.countDocuments({ 
                createdAt: { $gte: today } 
            }),
            urgent: await Withdrawal.countDocuments({ 
                status: 'pending',
                createdAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } // > 24h
            }),
            totalAmount: (await Withdrawal.aggregate([
                { $match: { status: 'pending' } },
                { $group: { _id: null, total: { $sum: "$amount" } } }
            ]))[0]?.total || 0,
            averageAmount: (await Withdrawal.aggregate([
                { $group: { _id: null, average: { $avg: "$amount" } } }
            ]))[0]?.average || 0,
            processedToday: (await Withdrawal.aggregate([
                { $match: { 
                    status: { $in: ['approved', 'completed'] },
                    updatedAt: { $gte: today }
                }},
                { $group: { _id: null, total: { $sum: "$amount" } } }
            ]))[0]?.total || 0,
            processedCount: await Withdrawal.countDocuments({ 
                status: { $in: ['approved', 'completed'] },
                updatedAt: { $gte: today }
            }),
            approvedToday: await Withdrawal.countDocuments({ 
                status: 'approved',
                updatedAt: { $gte: today }
            }),
            trend: 0, // Calcular tendência
            averageTrend: 0 // Calcular tendência média
        };
        
        // Calcular horas de espera para cada levantamento pendente
        withdrawals.forEach(withdrawal => {
            if (withdrawal.status === 'pending') {
                const hoursWaiting = Math.floor((new Date() - new Date(withdrawal.createdAt)) / (1000 * 60 * 60));
                withdrawal.hoursWaiting = hoursWaiting;
                withdrawal.isUrgent = hoursWaiting > 24;
            }
        });
        
        res.render('withdrawals', {
            withdrawals,
            stats,
            currentPage: parseInt(page),
            totalPages: Math.ceil(total / limit),
            limit,
            status: status || 'all',
            method: method || 'all',
            search: search || '',
            sort: sort || 'newest',
            user: req.session.user || { name: 'Daniela' }
        });
        
    } catch (error) {
        console.error('Erro ao carregar levantamentos:', error);
        res.status(500).render('error', {
            message: 'Erro ao carregar levantamentos',
            error: process.env.NODE_ENV === 'development' ? error : {}
        });
    }
});

// GET /withdrawals/:id - Detalhes do levantamento
router.get('/:id', async (req, res) => {
    try {
        const withdrawal = await Withdrawal.findById(req.params.id)
            .populate('player');
        
        if (!withdrawal) {
            return res.status(404).json({ error: 'Levantamento não encontrado' });
        }
        
        res.json(withdrawal);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar levantamento' });
    }
});

// POST /withdrawals/:id/approve - Aprovar levantamento
router.post('/:id/approve', async (req, res) => {
    try {
        const { internalNotes, notifyPlayer } = req.body;
        
        const withdrawal = await Withdrawal.findById(req.params.id);
        if (!withdrawal) {
            return res.status(404).json({ error: 'Levantamento não encontrado' });
        }
        
        // Atualizar status
        withdrawal.status = 'approved';
        withdrawal.approvedAt = new Date();
        withdrawal.processedBy = req.session.user.name;
        withdrawal.internalNotes = internalNotes;
        await withdrawal.save();
        
        // Atualizar saldo do jogador
        await User.findByIdAndUpdate(withdrawal.player, {
            $inc: { balance: -withdrawal.amount }
        });
        
        // TODO: Enviar email de notificação se notifyPlayer for true
        
        res.json({ 
            success: true, 
            message: 'Levantamento aprovado com sucesso',
            withdrawal 
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao aprovar levantamento' });
    }
});

// POST /withdrawals/:id/reject - Rejeitar levantamento
router.post('/:id/reject', async (req, res) => {
    try {
        const { rejectionReason, internalNotes, notifyPlayer } = req.body;
        
        const withdrawal = await Withdrawal.findById(req.params.id);
        if (!withdrawal) {
            return res.status(404).json({ error: 'Levantamento não encontrado' });
        }
        
        // Atualizar status
        withdrawal.status = 'rejected';
        withdrawal.rejectedAt = new Date();
        withdrawal.rejectionReason = rejectionReason;
        withdrawal.internalNotes = internalNotes;
        withdrawal.processedBy = req.session.user.name;
        await withdrawal.save();
        
        // TODO: Enviar email de notificação se notifyPlayer for true
        
        res.json({ 
            success: true, 
            message: 'Levantamento rejeitado com sucesso',
            withdrawal 
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao rejeitar levantamento' });
    }
});

// POST /withdrawals/bulk-action - Ações em massa
router.post('/bulk-action', async (req, res) => {
    try {
        const { withdrawalIds, action, data } = req.body;
        
        let result;
        
        switch(action) {
            case 'approve':
                result = await Withdrawal.updateMany(
                    { _id: { $in: withdrawalIds }, status: 'pending' },
                    { 
                        status: 'approved',
                        approvedAt: new Date(),
                        processedBy: req.session.user.name,
                        internalNotes: data.internalNotes
                    }
                );
                break;
                
            case 'reject':
                result = await Withdrawal.updateMany(
                    { _id: { $in: withdrawalIds }, status: 'pending' },
                    { 
                        status: 'rejected',
                        rejectedAt: new Date(),
                        rejectionReason: data.rejectionReason,
                        internalNotes: data.internalNotes,
                        processedBy: req.session.user.name
                    }
                );
                break;
                
            default:
                return res.status(400).json({ error: 'Ação não suportada' });
        }
        
        res.json({ 
            success: true, 
            message: `${result.modifiedCount} levantamento(s) processado(s)`,
            count: result.modifiedCount 
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao processar ações em massa' });
    }
});

module.exports = router;