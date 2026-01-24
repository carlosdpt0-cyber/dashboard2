router.get('/payments', async (req, res) => {
    try {
        // Obter dados do banco de dados
        const payments = await Payment.find().sort({ createdAt: -1 }).limit(50);
        
        // Calcular estatísticas
        const paymentsStats = {
            totalAmount: 0,
            completed: 0,
            pending: 0,
            failed: 0,
            total: payments.length
        };
        
        payments.forEach(payment => {
            paymentsStats.totalAmount += payment.amount || 0;
            
            if (payment.status === 'completed') {
                paymentsStats.completed++;
            } else if (payment.status === 'pending') {
                paymentsStats.pending++;
            } else if (payment.status === 'failed') {
                paymentsStats.failed++;
            }
        });
        
        // Renderizar a página com os dados
        res.render('payments', {
            user: req.user, // Usuário atual
            payments: payments, // Lista de pagamentos
            paymentsStats: paymentsStats, // Estatísticas
            stats: { // Outras estatísticas do sistema
                pendingWithdrawals: await Withdrawal.countDocuments({ status: 'pending' })
            }
        });
        
    } catch (error) {
        console.error('Erro ao carregar pagamentos:', error);
        res.render('payments', {
            user: req.user,
            payments: [], // Array vazio em caso de erro
            paymentsStats: { // Estatísticas padrão
                totalAmount: 0,
                completed: 0,
                pending: 0,
                failed: 0,
                total: 0
            },
            stats: { pendingWithdrawals: 0 }
        });
    }
});