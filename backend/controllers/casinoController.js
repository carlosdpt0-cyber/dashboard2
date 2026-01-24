const axios = require('axios');
const crypto = require('crypto');
const { Op } = require('sequelize');
const { CasinoStats, Player, Transaction, Withdrawal, SupportTicket, GameLog, CasinoGame, ServerStatus } = require('../models');
const logger = require('../utils/logger');
const cache = require('../utils/cache');

class CasinoController {
    constructor() {
        this.apiBaseUrl = process.env.CASINO_API_URL;
        this.apiKey = process.env.CASINO_API_KEY;
        this.apiSecret = process.env.CASINO_API_SECRET;
        this.socketConnections = new Map();
    }

    /**
     * Gerar assinatura para requisições à API do Casino
     */
    generateSignature(data) {
        const timestamp = Date.now();
        const payload = `${timestamp}${JSON.stringify(data)}${this.apiSecret}`;
        const signature = crypto
            .createHash('sha256')
            .update(payload)
            .digest('hex');
        
        return { timestamp, signature };
    }

    /**
     * Fazer requisição autenticada à API do Casino
     */
    async makeCasinoRequest(endpoint, method = 'GET', data = null) {
        try {
            const { timestamp, signature } = this.generateSignature(data || {});
            
            const config = {
                method,
                url: `${this.apiBaseUrl}${endpoint}`,
                headers: {
                    'X-API-Key': this.apiKey,
                    'X-API-Timestamp': timestamp,
                    'X-API-Signature': signature,
                    'Content-Type': 'application/json'
                },
                timeout: 10000 // 10 segundos timeout
            };

            if (data && method !== 'GET') {
                config.data = data;
            }

            const response = await axios(config);
            
            logger.info(`✅ Requisição casino ${endpoint} bem sucedida`, {
                endpoint,
                status: response.status
            });

            return response.data;
        } catch (error) {
            logger.error(`❌ Erro na requisição casino ${endpoint}:`, {
                endpoint,
                error: error.message,
                status: error.response?.status
            });
            
            throw new Error(`Falha na comunicação com o casino: ${error.message}`);
        }
    }

    /**
     * Obter estatísticas gerais do casino
     */
    async getCasinoStats() {
        try {
            // Tentar obter do cache primeiro
            const cacheKey = 'casino:stats';
            const cachedStats = await cache.get(cacheKey);
            
            if (cachedStats) {
                return cachedStats;
            }

            // Obter dados da API do casino
            const [apiStats, dbStats] = await Promise.all([
                this.makeCasinoRequest('/stats/overview'),
                this.getDatabaseStats()
            ]);

            // Combinar dados da API e banco de dados
            const stats = {
                // Dados da API do casino
                onlinePlayers: apiStats.online_players || 0,
                activeGames: apiStats.active_games || 0,
                totalRevenue: apiStats.total_revenue || 0,
                totalWithdrawals: apiStats.total_withdrawals || 0,
                serverStatus: apiStats.server_status || [],
                
                // Dados do banco de dados
                totalPlayers: dbStats.totalPlayers,
                newPlayersToday: dbStats.newPlayersToday,
                pendingWithdrawals: dbStats.pendingWithdrawals,
                totalDeposits: dbStats.totalDeposits,
                
                // Estatísticas em tempo real
                realtime: {
                    depositsLastHour: dbStats.depositsLastHour,
                    withdrawalsLastHour: dbStats.withdrawalsLastHour,
                    supportTicketsOpen: dbStats.supportTicketsOpen,
                    averageBet: apiStats.average_bet || 0
                },
                
                // Status dos serviços
                services: {
                    casinoApi: apiStats.status === 'online',
                    paymentGateway: await this.checkPaymentGateway(),
                    supportSystem: await this.checkSupportSystem(),
                    gameServers: await this.checkGameServers()
                },
                
                // Timestamps
                lastUpdated: new Date(),
                cacheDuration: 300 // 5 minutos
            };

            // Salvar no cache por 5 minutos
            await cache.set(cacheKey, stats, 300);

            logger.info('📊 Estatísticas do casino atualizadas');
            return stats;
        } catch (error) {
            logger.error('❌ Erro ao obter estatísticas do casino:', error);
            
            // Retornar dados em cache ou dados básicos em caso de erro
            return await this.getFallbackStats();
        }
    }

    /**
     * Obter estatísticas do banco de dados
     */
    async getDatabaseStats() {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const [totalPlayers, newPlayersToday, pendingWithdrawals, totalDeposits, 
               depositsLastHour, withdrawalsLastHour, supportTicketsOpen] = await Promise.all([
            Player.count(),
            Player.count({
                where: {
                    createdAt: {
                        [Op.gte]: today
                    }
                }
            }),
            Withdrawal.count({
                where: { status: 'pending' }
            }),
            Transaction.sum('amount', {
                where: { 
                    type: 'deposit',
                    status: 'completed'
                }
            }) || 0,
            Transaction.count({
                where: {
                    type: 'deposit',
                    status: 'completed',
                    createdAt: {
                        [Op.gte]: new Date(Date.now() - 60 * 60 * 1000)
                    }
                }
            }),
            Withdrawal.count({
                where: {
                    status: 'completed',
                    updatedAt: {
                        [Op.gte]: new Date(Date.now() - 60 * 60 * 1000)
                    }
                }
            }),
            SupportTicket.count({
                where: { status: 'open' }
            })
        ]);

        return {
            totalPlayers,
            newPlayersToday,
            pendingWithdrawals,
            totalDeposits,
            depositsLastHour,
            withdrawalsLastHour,
            supportTicketsOpen
        };
    }

    /**
     * Dados de fallback em caso de erro na API
     */
    async getFallbackStats() {
        const dbStats = await this.getDatabaseStats();
        
        return {
            onlinePlayers: 0,
            activeGames: 0,
            totalRevenue: 0,
            totalWithdrawals: 0,
            serverStatus: [],
            totalPlayers: dbStats.totalPlayers,
            newPlayersToday: dbStats.newPlayersToday,
            pendingWithdrawals: dbStats.pendingWithdrawals,
            totalDeposits: dbStats.totalDeposits,
            realtime: {
                depositsLastHour: dbStats.depositsLastHour,
                withdrawalsLastHour: dbStats.withdrawalsLastHour,
                supportTicketsOpen: dbStats.supportTicketsOpen,
                averageBet: 0
            },
            services: {
                casinoApi: false,
                paymentGateway: false,
                supportSystem: true,
                gameServers: false
            },
            lastUpdated: new Date(),
            cacheDuration: 60 // 1 minuto
        };
    }

    /**
     * Verificar status do gateway de pagamento
     */
    async checkPaymentGateway() {
        try {
            const response = await axios.get(`${process.env.PAYMENT_GATEWAY_URL}/health`, {
                timeout: 5000
            });
            return response.status === 200;
        } catch (error) {
            return false;
        }
    }

    /**
     * Verificar status do sistema de suporte
     */
    async checkSupportSystem() {
        try {
            // Verificar conexão com banco de dados de tickets
            const ticketCount = await SupportTicket.count();
            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * Verificar status dos servidores de jogos
     */
    async checkGameServers() {
        try {
            const servers = await ServerStatus.findAll({
                where: { online: true },
                attributes: ['server_id', 'name', 'player_count', 'last_ping']
            });
            
            return servers.length > 0;
        } catch (error) {
            return false;
        }
    }

    /**
     * Obter jogadores com paginação e filtros
     */
    async getPlayers(page = 1, limit = 20, search = '', status = '') {
        try {
            const offset = (page - 1) * limit;
            
            // Construir condições da query
            const where = {};
            
            if (search) {
                where[Op.or] = [
                    { username: { [Op.like]: `%${search}%` } },
                    { email: { [Op.like]: `%${search}%` } },
                    { player_id: search }
                ];
            }
            
            if (status) {
                where.status = status;
            }
            
            // Buscar jogadores do banco de dados
            const { count, rows } = await Player.findAndCountAll({
                where,
                limit,
                offset,
                order: [['createdAt', 'DESC']],
                attributes: [
                    'id', 'player_id', 'username', 'email', 'balance', 
                    'status', 'last_login', 'createdAt', 'country', 
                    'total_deposits', 'total_withdrawals'
                ]
            });
            
            // Enriquecer com dados da API do casino para jogadores online
            const enrichedPlayers = await Promise.all(
                rows.map(async (player) => {
                    try {
                        // Verificar se jogador está online na API do casino
                        const onlineData = await this.makeCasinoRequest(`/player/${player.player_id}/status`)
                            .catch(() => null);
                        
                        return {
                            ...player.toJSON(),
                            is_online: onlineData?.online || false,
                            current_game: onlineData?.current_game || null,
                            last_activity: onlineData?.last_activity || player.last_login
                        };
                    } catch (error) {
                        return {
                            ...player.toJSON(),
                            is_online: false,
                            current_game: null,
                            last_activity: player.last_login
                        };
                    }
                })
            );
            
            return {
                players: enrichedPlayers,
                pagination: {
                    total: count,
                    page,
                    limit,
                    totalPages: Math.ceil(count / limit)
                }
            };
        } catch (error) {
            logger.error('❌ Erro ao obter jogadores:', error);
            throw new Error(`Falha ao obter jogadores: ${error.message}`);
        }
    }

    /**
     * Obter detalhes de um jogador específico
     */
    async getPlayerDetails(playerId) {
        try {
            // Buscar jogador no banco de dados
            const player = await Player.findOne({
                where: { player_id: playerId },
                include: [
                    {
                        model: Transaction,
                        as: 'transactions',
                        limit: 10,
                        order: [['createdAt', 'DESC']]
                    },
                    {
                        model: Withdrawal,
                        as: 'withdrawals',
                        limit: 10,
                        order: [['createdAt', 'DESC']]
                    }
                ]
            });
            
            if (!player) {
                throw new Error('Jogador não encontrado');
            }
            
            // Obter dados da API do casino
            const [casinoData, gameHistory, kycStatus] = await Promise.all([
                this.makeCasinoRequest(`/player/${playerId}/details`).catch(() => null),
                this.makeCasinoRequest(`/player/${playerId}/game-history?limit=10`).catch(() => []),
                this.makeCasinoRequest(`/player/${playerId}/kyc`).catch(() => ({ status: 'unknown' }))
            ]);
            
            // Combinar dados
            return {
                ...player.toJSON(),
                casino_data: casinoData || {},
                recent_games: gameHistory || [],
                kyc_status: kycStatus,
                risk_score: await this.calculateRiskScore(playerId)
            };
        } catch (error) {
            logger.error(`❌ Erro ao obter detalhes do jogador ${playerId}:`, error);
            throw new Error(`Falha ao obter detalhes do jogador: ${error.message}`);
        }
    }

    /**
     * Calcular score de risco para jogador
     */
    async calculateRiskScore(playerId) {
        try {
            // Obter estatísticas do jogador
            const [depositCount, withdrawalCount, avgDeposit, maxDeposit] = await Promise.all([
                Transaction.count({
                    where: {
                        player_id: playerId,
                        type: 'deposit',
                        status: 'completed'
                    }
                }),
                Withdrawal.count({
                    where: {
                        player_id: playerId,
                        status: 'completed'
                    }
                }),
                Transaction.findOne({
                    where: {
                        player_id: playerId,
                        type: 'deposit',
                        status: 'completed'
                    },
                    attributes: [
                        [Sequelize.fn('AVG', Sequelize.col('amount')), 'avg_amount']
                    ],
                    raw: true
                }),
                Transaction.findOne({
                    where: {
                        player_id: playerId,
                        type: 'deposit',
                        status: 'completed'
                    },
                    attributes: [
                        [Sequelize.fn('MAX', Sequelize.col('amount')), 'max_amount']
                    ],
                    raw: true
                })
            ]);
            
            // Calcular score baseado em múltiplos fatores
            let score = 50; // Score inicial
            
            // Ajustar baseado no comportamento de depósito
            if (depositCount > 10) score -= 10;
            if (avgDeposit?.avg_amount > 1000) score += 20;
            if (maxDeposit?.max_amount > 5000) score += 30;
            
            // Ajustar baseado no comportamento de levantamento
            if (withdrawalCount / depositCount > 0.8) score += 15;
            
            // Limitar score entre 0 e 100
            score = Math.max(0, Math.min(100, score));
            
            return {
                score,
                level: score < 30 ? 'low' : score < 70 ? 'medium' : 'high',
                factors: {
                    deposit_frequency: depositCount,
                    average_deposit: avgDeposit?.avg_amount || 0,
                    max_deposit: maxDeposit?.max_amount || 0,
                    withdrawal_ratio: depositCount > 0 ? (withdrawalCount / depositCount) : 0
                }
            };
        } catch (error) {
            logger.error(`❌ Erro ao calcular risk score para ${playerId}:`, error);
            return { score: 50, level: 'medium', factors: {} };
        }
    }

    /**
     * Obter levantamentos com filtros
     */
    async getWithdrawals(status = 'pending', page = 1, limit = 20) {
        try {
            const offset = (page - 1) * limit;
            
            const where = { status };
            
            const { count, rows } = await Withdrawal.findAndCountAll({
                where,
                limit,
                offset,
                order: [['createdAt', 'DESC']],
                include: [
                    {
                        model: Player,
                        as: 'player',
                        attributes: ['username', 'email', 'player_id']
                    }
                ]
            });
            
            // Processar dados adicionais para cada levantamento
            const enrichedWithdrawals = await Promise.all(
                rows.map(async (withdrawal) => {
                    try {
                        // Verificar histórico do jogador na API do casino
                        const playerHistory = await this.makeCasinoRequest(
                            `/player/${withdrawal.player.player_id}/withdrawal-history`
                        ).catch(() => ({}));
                        
                        // Verificar se há flags de risco
                        const riskFlags = await this.checkWithdrawalRiskFlags(withdrawal);
                        
                        return {
                            ...withdrawal.toJSON(),
                            player_history: playerHistory,
                            risk_flags: riskFlags,
                            processing_time: this.calculateProcessingTime(withdrawal.createdAt),
                            can_auto_approve: await this.canAutoApproveWithdrawal(withdrawal)
                        };
                    } catch (error) {
                        return {
                            ...withdrawal.toJSON(),
                            player_history: {},
                            risk_flags: [],
                            processing_time: this.calculateProcessingTime(withdrawal.createdAt),
                            can_auto_approve: false
                        };
                    }
                })
            );
            
            return {
                withdrawals: enrichedWithdrawals,
                pagination: {
                    total: count,
                    page,
                    limit,
                    totalPages: Math.ceil(count / limit)
                },
                summary: await this.getWithdrawalSummary(status)
            };
        } catch (error) {
            logger.error('❌ Erro ao obter levantamentos:', error);
            throw new Error(`Falha ao obter levantamentos: ${error.message}`);
        }
    }

    /**
     * Verificar flags de risco para um levantamento
     */
    async checkWithdrawalRiskFlags(withdrawal) {
        const flags = [];
        
        try {
            // Verificar se é o primeiro levantamento
            const withdrawalCount = await Withdrawal.count({
                where: {
                    player_id: withdrawal.player_id,
                    status: 'completed'
                }
            });
            
            if (withdrawalCount === 0) {
                flags.push('first_withdrawal');
            }
            
            // Verificar se o valor é suspeitamente alto
            const playerStats = await Player.findOne({
                where: { player_id: withdrawal.player_id },
                attributes: ['total_deposits', 'total_withdrawals']
            });
            
            if (playerStats) {
                const totalDeposits = playerStats.total_deposits || 0;
                const totalWithdrawals = playerStats.total_withdrawals || 0;
                const netDeposit = totalDeposits - totalWithdrawals;
                
                if (withdrawal.amount > netDeposit * 0.8) {
                    flags.push('high_amount_relative_to_deposits');
                }
                
                if (withdrawal.amount > 5000) {
                    flags.push('high_absolute_amount');
                }
            }
            
            // Verificar velocidade de levantamento
            const recentDeposits = await Transaction.count({
                where: {
                    player_id: withdrawal.player_id,
                    type: 'deposit',
                    status: 'completed',
                    createdAt: {
                        [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) // Últimas 24h
                    }
                }
            });
            
            if (recentDeposits > 3) {
                flags.push('recent_high_deposit_frequency');
            }
            
            // Verificar KYC status
            const kycStatus = await this.makeCasinoRequest(
                `/player/${withdrawal.player_id}/kyc`
            ).catch(() => ({ status: 'unknown' }));
            
            if (kycStatus.status !== 'verified') {
                flags.push('kyc_not_verified');
            }
            
        } catch (error) {
            logger.error('❌ Erro ao verificar flags de risco:', error);
        }
        
        return flags;
    }

    /**
     * Calcular tempo de processamento
     */
    calculateProcessingTime(createdAt) {
        const now = new Date();
        const created = new Date(createdAt);
        const diffHours = (now - created) / (1000 * 60 * 60);
        
        if (diffHours < 1) return 'recent';
        if (diffHours < 4) return 'normal';
        if (diffHours < 12) return 'delayed';
        return 'overdue';
    }

    /**
     * Verificar se levantamento pode ser aprovado automaticamente
     */
    async canAutoApproveWithdrawal(withdrawal) {
        try {
            // Verificar flags de risco
            const riskFlags = await this.checkWithdrawalRiskFlags(withdrawal);
            
            // Condições para auto-aprovação
            const conditions = [
                riskFlags.length === 0, // Sem flags de risco
                withdrawal.amount <= 1000, // Valor baixo
                withdrawal.payment_method !== 'crypto', // Método tradicional
                await this.hasVerifiedKYC(withdrawal.player_id) // KYC verificado
            ];
            
            return conditions.every(condition => condition === true);
        } catch (error) {
            return false;
        }
    }

    /**
     * Verificar se jogador tem KYC verificado
     */
    async hasVerifiedKYC(playerId) {
        try {
            const kycStatus = await this.makeCasinoRequest(`/player/${playerId}/kyc`);
            return kycStatus.status === 'verified';
        } catch (error) {
            return false;
        }
    }

    /**
     * Obter resumo de levantamentos
     */
    async getWithdrawalSummary(status) {
        const where = { status };
        
        const [totalCount, totalAmount, avgAmount, maxAmount] = await Promise.all([
            Withdrawal.count({ where }),
            Withdrawal.sum('amount', { where }) || 0,
            Withdrawal.findOne({
                where,
                attributes: [
                    [Sequelize.fn('AVG', Sequelize.col('amount')), 'avg_amount']
                ],
                raw: true
            }),
            Withdrawal.findOne({
                where,
                attributes: [
                    [Sequelize.fn('MAX', Sequelize.col('amount')), 'max_amount']
                ],
                raw: true
            })
        ]);
        
        return {
            total_count: totalCount,
            total_amount: totalAmount,
            average_amount: avgAmount?.avg_amount || 0,
            max_amount: maxAmount?.max_amount || 0
        };
    }

    /**
     * Processar um levantamento (aprovar/rejeitar)
     */
    async processWithdrawal(withdrawalId, action, reason = '', processedBy) {
        try {
            // Buscar o levantamento
            const withdrawal = await Withdrawal.findOne({
                where: { id: withdrawalId },
                include: [{ model: Player, as: 'player' }]
            });
            
            if (!withdrawal) {
                throw new Error('Levantamento não encontrado');
            }
            
            if (withdrawal.status !== 'pending') {
                throw new Error('Levantamento já processado');
            }
            
            // Atualizar status no banco de dados
            withdrawal.status = action === 'approve' ? 'approved' : 'rejected';
            withdrawal.processed_by = processedBy;
            withdrawal.processed_at = new Date();
            withdrawal.rejection_reason = action === 'reject' ? reason : null;
            
            await withdrawal.save();
            
            // Se aprovado, processar na API do casino
            if (action === 'approve') {
                await this.makeCasinoRequest(
                    `/withdrawals/${withdrawal.casino_withdrawal_id}/approve`,
                    'POST',
                    {
                        amount: withdrawal.amount,
                        player_id: withdrawal.player.player_id,
                        reference_id: withdrawal.id
                    }
                );
                
                // Atualizar saldo do jogador no banco de dados
                await Player.update(
                    { balance: Sequelize.literal(`balance - ${withdrawal.amount}`) },
                    { where: { player_id: withdrawal.player.player_id } }
                );
            }
            
            // Registrar no log de transações
            await Transaction.create({
                player_id: withdrawal.player.player_id,
                type: 'withdrawal',
                amount: withdrawal.amount,
                status: action === 'approve' ? 'completed' : 'rejected',
                reference_id: withdrawal.id,
                metadata: {
                    action,
                    processed_by: processedBy,
                    reason: action === 'reject' ? reason : null,
                    payment_method: withdrawal.payment_method
                }
            });
            
            // Notificar jogador
            await this.notifyPlayer(
                withdrawal.player.player_id,
                action === 'approve' ? 'withdrawal_approved' : 'withdrawal_rejected',
                {
                    amount: withdrawal.amount,
                    reference: withdrawal.reference,
                    reason: action === 'reject' ? reason : null
                }
            );
            
            // Registrar log de auditoria
            logger.info(`✅ Levantamento ${action === 'approve' ? 'aprovado' : 'rejeitado'}`, {
                withdrawal_id: withdrawalId,
                amount: withdrawal.amount,
                player_id: withdrawal.player.player_id,
                processed_by: processedBy,
                reason
            });
            
            return {
                success: true,
                message: `Levantamento ${action === 'approve' ? 'aprovado' : 'rejeitado'} com sucesso`,
                withdrawal: withdrawal.toJSON()
            };
        } catch (error) {
            logger.error(`❌ Erro ao processar levantamento ${withdrawalId}:`, error);
            throw new Error(`Falha ao processar levantamento: ${error.message}`);
        }
    }

    /**
     * Notificar jogador sobre atualização
     */
    async notifyPlayer(playerId, type, data) {
        try {
            await this.makeCasinoRequest(
                `/player/${playerId}/notify`,
                'POST',
                {
                    type,
                    data,
                    timestamp: new Date().toISOString()
                }
            );
            
            // Também enviar email se configurado
            if (process.env.SEND_EMAIL_NOTIFICATIONS === 'true') {
                await this.sendEmailNotification(playerId, type, data);
            }
        } catch (error) {
            logger.error(`❌ Erro ao notificar jogador ${playerId}:`, error);
        }
    }

    /**
     * Enviar notificação por email
     */
    async sendEmailNotification(playerId, type, data) {
        // Implementação de envio de email
        // Pode usar nodemailer, SendGrid, etc.
    }

    /**
     * Obter transações com filtros
     */
    async getTransactions(type = 'all', startDate, endDate, userId = null) {
        try {
            const where = {};
            
            if (type !== 'all') {
                where.type = type;
            }
            
            if (startDate && endDate) {
                where.createdAt = {
                    [Op.between]: [new Date(startDate), new Date(endDate)]
                };
            }
            
            if (userId) {
                where.player_id = userId;
            }
            
            const transactions = await Transaction.findAll({
                where,
                limit: 100,
                order: [['createdAt', 'DESC']],
                include: [
                    {
                        model: Player,
                        as: 'player',
                        attributes: ['username', 'email']
                    }
                ]
            });
            
            // Calcular estatísticas
            const stats = await this.getTransactionStats(where);
            
            return {
                transactions: transactions.map(t => t.toJSON()),
                stats,
                filters: { type, startDate, endDate, userId }
            };
        } catch (error) {
            logger.error('❌ Erro ao obter transações:', error);
            throw new Error(`Falha ao obter transações: ${error.message}`);
        }
    }

    /**
     * Obter estatísticas de transações
     */
    async getTransactionStats(where) {
        const [totalCount, totalAmount, completedCount, failedCount] = await Promise.all([
            Transaction.count({ where }),
            Transaction.sum('amount', { where }) || 0,
            Transaction.count({
                where: { ...where, status: 'completed' }
            }),
            Transaction.count({
                where: { ...where, status: 'failed' }
            })
        ]);
        
        return {
            total_count: totalCount,
            total_amount: totalAmount,
            completed_count: completedCount,
            failed_count: failedCount,
            success_rate: totalCount > 0 ? (completedCount / totalCount) * 100 : 0
        };
    }

    /**
     * Obter tickets de suporte
     */
    async getSupportTickets(status = 'open', department = 'all', page = 1) {
        try {
            const limit = 20;
            const offset = (page - 1) * limit;
            
            const where = {};
            
            if (status !== 'all') {
                where.status = status;
            }
            
            if (department !== 'all') {
                where.department = department;
            }
            
            const { count, rows } = await SupportTicket.findAndCountAll({
                where,
                limit,
                offset,
                order: [['priority', 'DESC'], ['createdAt', 'DESC']],
                include: [
                    {
                        model: Player,
                        as: 'player',
                        attributes: ['username', 'email', 'player_id']
                    },
                    {
                        model: Staff,
                        as: 'assigned_to',
                        attributes: ['username', 'role']
                    }
                ]
            });
            
            // Enriquecer tickets com dados adicionais
            const enrichedTickets = await Promise.all(
                rows.map(async (ticket) => {
                    try {
                        // Obter histórico do jogador
                        const playerHistory = await this.makeCasinoRequest(
                            `/player/${ticket.player.player_id}/support-history`
                        ).catch(() => ({}));
                        
                        // Calcular SLA
                        const slaStatus = this.calculateSLAStatus(ticket);
                        
                        return {
                            ...ticket.toJSON(),
                            player_history: playerHistory,
                            sla_status: slaStatus,
                            can_auto_assign: await this.canAutoAssignTicket(ticket)
                        };
                    } catch (error) {
                        return {
                            ...ticket.toJSON(),
                            player_history: {},
                            sla_status: 'unknown',
                            can_auto_assign: false
                        };
                    }
                })
            );
            
            return {
                tickets: enrichedTickets,
                pagination: {
                    total: count,
                    page,
                    limit,
                    totalPages: Math.ceil(count / limit)
                },
                summary: await this.getTicketSummary(where)
            };
        } catch (error) {
            logger.error('❌ Erro ao obter tickets:', error);
            throw new Error(`Falha ao obter tickets: ${error.message}`);
        }
    }

    /**
     * Calcular status do SLA
     */
    calculateSLAStatus(ticket) {
        const now = new Date();
        const created = new Date(ticket.createdAt);
        const diffHours = (now - created) / (1000 * 60 * 60);
        
        let status = 'normal';
        let warning = false;
        
        if (ticket.priority === 'high') {
            if (diffHours > 4) status = 'critical';
            else if (diffHours > 2) status = 'warning';
        } else if (ticket.priority === 'medium') {
            if (diffHours > 12) status = 'critical';
            else if (diffHours > 6) status = 'warning';
        } else {
            if (diffHours > 24) status = 'critical';
            else if (diffHours > 12) status = 'warning';
        }
        
        return {
            status,
            hours_open: diffHours.toFixed(1),
            response_deadline: this.calculateResponseDeadline(ticket),
            warning
        };
    }

    /**
     * Calcular prazo de resposta
     */
    calculateResponseDeadline(ticket) {
        const created = new Date(ticket.createdAt);
        let deadlineHours;
        
        switch (ticket.priority) {
            case 'high':
                deadlineHours = 4;
                break;
            case 'medium':
                deadlineHours = 12;
                break;
            default:
                deadlineHours = 24;
        }
        
        const deadline = new Date(created.getTime() + deadlineHours * 60 * 60 * 1000);
        return deadline.toISOString();
    }

    /**
     * Verificar se ticket pode ser auto-atribuído
     */
    async canAutoAssignTicket(ticket) {
        try {
            // Verificar se é um problema comum
            const commonIssues = ['password_reset', 'deposit_issue', 'game_issue'];
            const isCommonIssue = commonIssues.includes(ticket.category);
            
            // Verificar se há agentes disponíveis
            const availableAgents = await Staff.count({
                where: {
                    role: 'support',
                    status: 'available',
                    department: ticket.department
                }
            });
            
            return isCommonIssue && availableAgents > 0;
        } catch (error) {
            return false;
        }
    }

    /**
     * Obter resumo de tickets
     */
    async getTicketSummary(where) {
        const [totalCount, openCount, highPriority, assignedCount] = await Promise.all([
            SupportTicket.count({ where }),
            SupportTicket.count({
                where: { ...where, status: 'open' }
            }),
            SupportTicket.count({
                where: { ...where, priority: 'high' }
            }),
            SupportTicket.count({
                where: { ...where, assigned_to: { [Op.not]: null } }
            })
        ]);
        
        return {
            total_count: totalCount,
            open_count: openCount,
            high_priority: highPriority,
            assigned_count: assignedCount,
            response_rate: totalCount > 0 ? ((totalCount - openCount) / totalCount) * 100 : 0
        };
    }

    /**
     * Atualizar ticket de suporte
     */
    async updateTicket(ticketId, updates) {
        try {
            const ticket = await SupportTicket.findOne({
                where: { id: ticketId },
                include: [{ model: Player, as: 'player' }]
            });
            
            if (!ticket) {
                throw new Error('Ticket não encontrado');
            }
            
            // Atualizar ticket
            await ticket.update(updates);
            
            // Se atribuído a um agente, notificar
            if (updates.assigned_to) {
                await this.notifyStaff(
                    updates.assigned_to,
                    'ticket_assigned',
                    {
                        ticket_id: ticketId,
                        player_username: ticket.player.username,
                        priority: ticket.priority
                    }
                );
            }
            
            // Registrar no log
            logger.info(`✅ Ticket ${ticketId} atualizado`, {
                ticket_id: ticketId,
                updates,
                updated_by: updates.updated_by
            });
            
            return {
                success: true,
                message: 'Ticket atualizado com sucesso',
                ticket: ticket.toJSON()
            };
        } catch (error) {
            logger.error(`❌ Erro ao atualizar ticket ${ticketId}:`, error);
            throw new Error(`Falha ao atualizar ticket: ${error.message}`);
        }
    }

    /**
     * Notificar staff sobre atualização
     */
    async notifyStaff(staffId, type, data) {
        try {
            // Implementar notificação para staff
            // Pode ser via WebSocket, email, etc.
        } catch (error) {
            logger.error(`❌ Erro ao notificar staff ${staffId}:`, error);
        }
    }

    /**
     * Obter logs do sistema
     */
    async getLogs(type = 'all', startDate, endDate) {
        try {
            const where = {};
            
            if (type !== 'all') {
                where.type = type;
            }
            
            if (startDate && endDate) {
                where.createdAt = {
                    [Op.between]: [new Date(startDate), new Date(endDate)]
                };
            }
            
            const logs = await SystemLog.findAll({
                where,
                limit: 100,
                order: [['createdAt', 'DESC']],
                include: [
                    {
                        model: Staff,
                        as: 'staff',
                        attributes: ['username']
                    },
                    {
                        model: Player,
                        as: 'player',
                        attributes: ['username'],
                        required: false
                    }
                ]
            });
            
            // Agrupar logs por tipo para estatísticas
            const logStats = await SystemLog.findAll({
                where,
                attributes: [
                    'type',
                    [Sequelize.fn('COUNT', Sequelize.col('id')), 'count']
                ],
                group: ['type']
            });
            
            return {
                logs: logs.map(log => log.toJSON()),
                stats: logStats,
                filters: { type, startDate, endDate }
            };
        } catch (error) {
            logger.error('❌ Erro ao obter logs:', error);
            throw new Error(`Falha ao obter logs: ${error.message}`);
        }
    }

    /**
     * Gerar token para conexão WebSocket
     */
    generateWebSocketToken(userId) {
        const tokenData = {
            userId,
            timestamp: Date.now(),
            role: 'dashboard'
        };
        
        const token = crypto
            .createHmac('sha256', process.env.WS_SECRET || 'ws-secret')
            .update(JSON.stringify(tokenData))
            .digest('hex');
        
        return {
            token,
            expiresIn: 3600, // 1 hora
            data: tokenData
        };
    }

    /**
     * Validar token WebSocket
     */
    validateWebSocketToken(token) {
        try {
            const [receivedToken, receivedData] = token.split('.');
            const tokenData = JSON.parse(Buffer.from(receivedData, 'base64').toString());
            
            const expectedToken = crypto
                .createHmac('sha256', process.env.WS_SECRET || 'ws-secret')
                .update(JSON.stringify(tokenData))
                .digest('hex');
            
            if (receivedToken !== expectedToken) {
                return false;
            }
            
            // Verificar expiração
            const now = Date.now();
            const tokenAge = now - tokenData.timestamp;
            
            if (tokenAge > 3600 * 1000) { // 1 hora
                return false;
            }
            
            return tokenData;
        } catch (error) {
            return false;
        }
    }

    /**
     * Obter jogos mais populares
     */
    async getPopularGames(limit = 10) {
        try {
            const games = await CasinoGame.findAll({
                limit,
                order: [['popularity', 'DESC']],
                attributes: [
                    'id', 'name', 'provider', 'type', 'popularity', 
                    'total_bets', 'total_wins', 'payout_percentage'
                ]
            });
            
            // Enriquecer com dados em tempo real
            const enrichedGames = await Promise.all(
                games.map(async (game) => {
                    try {
                        const realtimeData = await this.makeCasinoRequest(
                            `/game/${game.id}/realtime`
                        ).catch(() => null);
                        
                        return {
                            ...game.toJSON(),
                            current_players: realtimeData?.current_players || 0,
                            recent_wins: realtimeData?.recent_wins || []
                        };
                    } catch (error) {
                        return game.toJSON();
                    }
                })
            );
            
            return enrichedGames;
        } catch (error) {
            logger.error('❌ Erro ao obter jogos populares:', error);
            return [];
        }
    }

    /**
     * Obter relatórios financeiros
     */
    async getFinancialReports(period = 'daily') {
        try {
            let dateRange;
            const now = new Date();
            
            switch (period) {
                case 'daily':
                    dateRange = {
                        start: new Date(now.setHours(0, 0, 0, 0)),
                        end: new Date(now.setHours(23, 59, 59, 999))
                    };
                    break;
                case 'weekly':
                    const weekStart = new Date(now);
                    weekStart.setDate(now.getDate() - now.getDay());
                    weekStart.setHours(0, 0, 0, 0);
                    
                    const weekEnd = new Date(weekStart);
                    weekEnd.setDate(weekStart.getDate() + 6);
                    weekEnd.setHours(23, 59, 59, 999);
                    
                    dateRange = { start: weekStart, end: weekEnd };
                    break;
                case 'monthly':
                    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
                    const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59, 999);
                    
                    dateRange = { start: monthStart, end: monthEnd };
                    break;
                default:
                    dateRange = {
                        start: new Date(now.getFullYear(), now.getMonth(), now.getDate() - 7),
                        end: new Date()
                    };
            }
            
            // Obter dados financeiros
            const [deposits, withdrawals, gamesRevenue, bonuses] = await Promise.all([
                this.getDepositsReport(dateRange),
                this.getWithdrawalsReport(dateRange),
                this.getGamesRevenueReport(dateRange),
                this.getBonusesReport(dateRange)
            ]);
            
            // Calcular totais
            const totalRevenue = deposits.total + gamesRevenue.total;
            const totalExpenses = withdrawals.total + bonuses.total;
            const netProfit = totalRevenue - totalExpenses;
            
            return {
                period,
                date_range: dateRange,
                revenue: {
                    deposits,
                    games: gamesRevenue,
                    total: totalRevenue
                },
                expenses: {
                    withdrawals,
                    bonuses,
                    total: totalExpenses
                },
                net_profit: netProfit,
                summary: {
                    deposit_count: deposits.count,
                    withdrawal_count: withdrawals.count,
                    average_deposit: deposits.average,
                    average_withdrawal: withdrawals.average,
                    player_retention: await this.calculatePlayerRetention(dateRange)
                }
            };
        } catch (error) {
            logger.error('❌ Erro ao obter relatórios financeiros:', error);
            throw new Error(`Falha ao obter relatórios: ${error.message}`);
        }
    }

    /**
     * Obter relatório de depósitos
     */
    async getDepositsReport(dateRange) {
        const where = {
            type: 'deposit',
            status: 'completed',
            createdAt: {
                [Op.between]: [dateRange.start, dateRange.end]
            }
        };
        
        const [total, count, average, byMethod] = await Promise.all([
            Transaction.sum('amount', { where }) || 0,
            Transaction.count({ where }),
            Transaction.findOne({
                where,
                attributes: [
                    [Sequelize.fn('AVG', Sequelize.col('amount')), 'avg_amount']
                ],
                raw: true
            }),
            Transaction.findAll({
                where,
                attributes: [
                    'payment_method',
                    [Sequelize.fn('COUNT', Sequelize.col('id')), 'count'],
                    [Sequelize.fn('SUM', Sequelize.col('amount')), 'total']
                ],
                group: ['payment_method'],
                raw: true
            })
        ]);
        
        return {
            total,
            count,
            average: average?.avg_amount || 0,
            by_method: byMethod
        };
    }

    /**
     * Calcular retenção de jogadores
     */
    async calculatePlayerRetention(dateRange) {
        // Implementar cálculo de retenção
        return 0.75; // Exemplo: 75% de retenção
    }

    /**
     * Monitorar anomalias
     */
    async monitorAnomalies() {
        try {
            const anomalies = [];
            const now = new Date();
            const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
            
            // Verificar depósitos suspeitos
            const suspiciousDeposits = await Transaction.findAll({
                where: {
                    type: 'deposit',
                    status: 'completed',
                    createdAt: { [Op.gte]: oneHourAgo },
                    amount: { [Op.gt]: 5000 } // Depósitos acima de 5000
                },
                include: [{ model: Player, as: 'player' }]
            });
            
            if (suspiciousDeposits.length > 5) {
                anomalies.push({
                    type: 'high_value_deposits',
                    count: suspiciousDeposits.length,
                    message: `${suspiciousDeposits.length} depósitos de alto valor na última hora`,
                    severity: 'high',
                    data: suspiciousDeposits.map(d => ({
                        player: d.player.username,
                        amount: d.amount,
                        time: d.createdAt
                    }))
                });
            }
            
            // Verificar múltiplas contas do mesmo IP
            const duplicateIPs = await Player.findAll({
                attributes: [
                    'ip_address',
                    [Sequelize.fn('COUNT', Sequelize.col('id')), 'count']
                ],
                group: ['ip_address'],
                having: Sequelize.literal('count > 3'),
                raw: true
            });
            
            if (duplicateIPs.length > 0) {
                anomalies.push({
                    type: 'duplicate_ip_addresses',
                    count: duplicateIPs.length,
                    message: `${duplicateIPs.length} endereços IP com múltiplas contas`,
                    severity: 'medium',
                    data: duplicateIPs
                });
            }
            
            // Verificar velocidade de jogo anormal
            const fastPlayers = await GameLog.findAll({
                attributes: [
                    'player_id',
                    [Sequelize.fn('COUNT', Sequelize.col('id')), 'game_count'],
                    [Sequelize.fn('SUM', Sequelize.col('bet_amount')), 'total_bet']
                ],
                where: {
                    createdAt: { [Op.gte]: oneHourAgo }
                },
                group: ['player_id'],
                having: Sequelize.literal('game_count > 100'),
                raw: true
            });
            
            if (fastPlayers.length > 0) {
                anomalies.push({
                    type: 'abnormal_game_speed',
                    count: fastPlayers.length,
                    message: `${fastPlayers.length} jogadores com velocidade anormal de jogo`,
                    severity: 'medium',
                    data: fastPlayers
                });
            }
            
            return anomalies;
        } catch (error) {
            logger.error('❌ Erro ao monitorar anomalias:', error);
            return [];
        }
    }

    /**
     * Sincronizar dados com API do casino
     */
    async syncWithCasinoAPI() {
        try {
            logger.info('🔄 Iniciando sincronização com API do casino...');
            
            // Sincronizar jogadores
            await this.syncPlayers();
            
            // Sincronizar transações
            await this.syncTransactions();
            
            // Sincronizar jogos
            await this.syncGames();
            
            // Sincronizar servidores
            await this.syncServers();
            
            logger.info('✅ Sincronização com API do casino concluída');
            
            return {
                success: true,
                message: 'Sincronização concluída com sucesso',
                timestamp: new Date()
            };
        } catch (error) {
            logger.error('❌ Erro na sincronização com API do casino:', error);
            throw new Error(`Falha na sincronização: ${error.message}`);
        }
    }

    /**
     * Sincronizar jogadores
     */
    async syncPlayers() {
        let page = 1;
        const limit = 100;
        let hasMore = true;
        
        while (hasMore) {
            try {
                const players = await this.makeCasinoRequest(
                    `/players?page=${page}&limit=${limit}`
                );
                
                if (!players.data || players.data.length === 0) {
                    hasMore = false;
                    break;
                }
                
                // Processar jogadores
                for (const playerData of players.data) {
                    await Player.upsert({
                        player_id: playerData.id,
                        username: playerData.username,
                        email: playerData.email,
                        status: playerData.status,
                        balance: playerData.balance,
                        total_deposits: playerData.total_deposits,
                        total_withdrawals: playerData.total_withdrawals,
                        last_login: playerData.last_login,
                        country: playerData.country,
                        currency: playerData.currency,
                        registration_date: playerData.created_at
                    });
                }
                
                page++;
                
                // Pequena pausa para não sobrecarregar a API
                await new Promise(resolve => setTimeout(resolve, 100));
                
            } catch (error) {
                logger.error(`❌ Erro ao sincronizar jogadores página ${page}:`, error);
                hasMore = false;
            }
        }
        
        logger.info(`✅ ${page * limit} jogadores sincronizados`);
    }

    /**
     * Backup de dados críticos
     */
    async backupCriticalData() {
        try {
            const backupDate = new Date().toISOString().split('T')[0];
            const backupData = {
                date: backupDate,
                timestamp: new Date(),
                data: {
                    players: await Player.count(),
                    transactions: await Transaction.count(),
                    withdrawals: await Withdrawal.count(),
                    support_tickets: await SupportTicket.count(),
                    total_balance: await Player.sum('balance') || 0
                }
            };
            
            // Salvar backup no banco de dados
            await Backup.create(backupData);
            
            // Opcional: Salvar em arquivo
            if (process.env.BACKUP_TO_FILE === 'true') {
                const fs = require('fs').promises;
                const backupDir = './backups';
                
                await fs.mkdir(backupDir, { recursive: true });
                await fs.writeFile(
                    `${backupDir}/backup-${backupDate}.json`,
                    JSON.stringify(backupData, null, 2)
                );
            }
            
            logger.info('✅ Backup de dados críticos realizado');
            
            return backupData;
        } catch (error) {
            logger.error('❌ Erro ao realizar backup:', error);
            throw error;
        }
    }
}

module.exports = new CasinoController();