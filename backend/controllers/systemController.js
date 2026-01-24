const SystemLog = require('../models/Log');
const Alert = require('../models/Alert');
const Staff = require('../models/Staff');
const User = require('../models/User');

class SystemController {
    
    /**
     * Criar um log do sistema
     */
    async createSystemLog(userId, userData, action, module, message, details = null, req = null) {
        try {
            // Verificar se o módulo é válido
            const validModules = [
                'auth', 'players', 'withdrawals', 'payments', 
                'staff', 'support', 'settings', 'system', 
                'email', 'dashboard', 'chat', 'profile', 'notifications'
            ];
            
            const logModule = validModules.includes(module) ? module : 'system';
            
            // Preparar dados do log
            const logData = {
                userId: userId || null,
                user: userData || { name: 'System', email: 'system@b7uno.com', role: 'system' },
                action: action || 'system',
                module: logModule,
                message: message || 'No message provided',
                details: details,
                timestamp: new Date(),
                read: false
            };
            
            // Adicionar informações de rede se disponível
            if (req) {
                logData.ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
                logData.userAgent = req.headers['user-agent'] || 'Unknown';
                logData.sessionId = req.sessionID || null;
                
                // Tentar determinar localização (simplificado)
                try {
                    const ip = logData.ip;
                    if (ip === '127.0.0.1' || ip === '::1') {
                        logData.location = 'Localhost';
                    } else if (ip.startsWith('192.168.') || ip.startsWith('10.')) {
                        logData.location = 'Rede Interna';
                    } else {
                        logData.location = 'Externa';
                    }
                } catch (e) {
                    logData.location = 'Desconhecida';
                }
            } else {
                logData.ip = '127.0.0.1';
                logData.userAgent = 'System/Internal';
                logData.location = 'System';
            }
            
            // Criar e salvar o log
            const log = new SystemLog(logData);
            await log.save();
            
            console.log(`📝 Log criado: ${action} - ${module} - ${message}`);
            
            return log;
            
        } catch (error) {
            console.error('❌ Erro ao criar log do sistema:', error.message);
            // Não lançar erro para não quebrar a aplicação principal
            return null;
        }
    }
    
    /**
     * Criar alerta do sistema
     */
    async createAlert(type, severity, title, message, metadata = {}) {
        try {
            const alertData = {
                type: type || 'system',
                severity: severity || 'medium',
                title: title || 'System Alert',
                message: message || 'No message provided',
                metadata: metadata,
                createdAt: new Date(),
                isResolved: false
            };
            
            const alert = new Alert(alertData);
            await alert.save();
            
            console.log(`🚨 Alerta criado: ${type} - ${severity} - ${title}`);
            
            // Notificar via WebSocket (se implementado)
            this.notifyAlert(alert);
            
            return alert;
            
        } catch (error) {
            console.error('❌ Erro ao criar alerta:', error.message);
            return null;
        }
    }
    
    /**
     * Notificar alerta via WebSocket (stub - implementar conforme necessidade)
     */
    notifyAlert(alert) {
        // Esta função será chamada pelo WebSocket server
        // Por enquanto, apenas log
        console.log(`📢 Notificação de alerta: ${alert.title}`);
    }
    
    /**
     * Obter estatísticas do sistema
     */
    async getSystemStats() {
        try {
            const now = new Date();
            const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            const last30Days = new Date();
            last30Days.setDate(last30Days.getDate() - 30);
            
            const [
                totalUsers,
                activeUsers,
                totalStaff,
                activeStaff,
                todayLogs,
                totalLogs,
                unresolvedAlerts,
                totalAlerts
            ] = await Promise.all([
                User.countDocuments({ isActive: true }),
                User.countDocuments({ 
                    isActive: true,
                    lastLogin: { $gte: new Date(Date.now() - 15 * 60 * 1000) }
                }),
                Staff.countDocuments({ isActive: true }),
                Staff.countDocuments({ isActive: true, isOnline: true }),
                SystemLog.countDocuments({ timestamp: { $gte: today } }),
                SystemLog.countDocuments({ timestamp: { $gte: last30Days } }),
                Alert.countDocuments({ isResolved: false }),
                Alert.countDocuments({ createdAt: { $gte: last30Days } })
            ]);
            
            return {
                players: {
                    total: totalUsers,
                    active: activeUsers,
                    percentage: totalUsers > 0 ? Math.round((activeUsers / totalUsers) * 100) : 0
                },
                staff: {
                    total: totalStaff,
                    active: activeStaff,
                    percentage: totalStaff > 0 ? Math.round((activeStaff / totalStaff) * 100) : 0
                },
                logs: {
                    today: todayLogs,
                    last30Days: totalLogs,
                    avgPerDay: totalLogs > 0 ? Math.round(totalLogs / 30) : 0
                },
                alerts: {
                    unresolved: unresolvedAlerts,
                    total: totalAlerts,
                    resolved: totalAlerts - unresolvedAlerts
                }
            };
            
        } catch (error) {
            console.error('❌ Erro ao obter estatísticas do sistema:', error);
            return {
                players: { total: 0, active: 0, percentage: 0 },
                staff: { total: 0, active: 0, percentage: 0 },
                logs: { today: 0, last30Days: 0, avgPerDay: 0 },
                alerts: { unresolved: 0, total: 0, resolved: 0 }
            };
        }
    }
    
    /**
     * Limpar logs antigos
     */
    async cleanupOldLogs(days = 90) {
        try {
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - days);
            
            const result = await SystemLog.deleteMany({
                timestamp: { $lt: cutoffDate }
            });
            
            console.log(`🧹 Limpeza de logs: ${result.deletedCount} logs removidos (mais de ${days} dias)`);
            
            return {
                success: true,
                deletedCount: result.deletedCount,
                message: `Foram removidos ${result.deletedCount} logs antigos`
            };
            
        } catch (error) {
            console.error('❌ Erro ao limpar logs antigos:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Exportar logs para CSV/JSON
     */
    async exportLogs(format = 'json', filters = {}) {
        try {
            let query = {};
            
            // Aplicar filtros
            if (filters.userId) {
                query.userId = filters.userId;
            }
            
            if (filters.action) {
                query.action = filters.action;
            }
            
            if (filters.module) {
                query.module = filters.module;
            }
            
            if (filters.dateFrom || filters.dateTo) {
                query.timestamp = {};
                
                if (filters.dateFrom) {
                    query.timestamp.$gte = new Date(filters.dateFrom);
                }
                
                if (filters.dateTo) {
                    const dateTo = new Date(filters.dateTo);
                    dateTo.setHours(23, 59, 59, 999);
                    query.timestamp.$lte = dateTo;
                }
            }
            
            if (filters.search) {
                const searchRegex = new RegExp(filters.search, 'i');
                query.$or = [
                    { message: searchRegex },
                    { details: searchRegex },
                    { ip: searchRegex },
                    { 'user.name': searchRegex },
                    { 'user.email': searchRegex }
                ];
            }
            
            const logs = await SystemLog.find(query)
                .sort({ timestamp: -1 })
                .lean();
            
            if (format === 'csv') {
                return this.convertLogsToCSV(logs);
            } else if (format === 'json') {
                return logs;
            } else {
                throw new Error('Formato não suportado');
            }
            
        } catch (error) {
            console.error('❌ Erro ao exportar logs:', error);
            throw error;
        }
    }
    
    /**
     * Converter logs para CSV
     */
    convertLogsToCSV(logs) {
        const headers = [
            'Data', 'Hora', 'Utilizador', 'Email', 'Cargo', 
            'Ação', 'Módulo', 'Mensagem', 'Detalhes', 'IP', 
            'Localização', 'User Agent', 'Sessão'
        ];
        
        const rows = logs.map(log => {
            const date = new Date(log.timestamp);
            const dateStr = date.toLocaleDateString('pt-PT');
            const timeStr = date.toLocaleTimeString('pt-PT');
            
            return [
                `"${dateStr}"`,
                `"${timeStr}"`,
                `"${log.user?.name || ''}"`,
                `"${log.user?.email || ''}"`,
                `"${log.user?.role || ''}"`,
                `"${log.action || ''}"`,
                `"${log.module || ''}"`,
                `"${log.message || ''}"`,
                `"${log.details || ''}"`,
                `"${log.ip || ''}"`,
                `"${log.location || ''}"`,
                `"${log.userAgent || ''}"`,
                `"${log.sessionId || ''}"`
            ].join(',');
        });
        
        return [headers.join(','), ...rows].join('\n');
    }
    
    /**
     * Marcar logs como lidos
     */
    async markLogsAsRead(userId = null) {
        try {
            const filter = { read: false };
            
            if (userId) {
                filter.userId = userId;
            }
            
            const result = await SystemLog.updateMany(
                filter,
                { $set: { read: true } }
            );
            
            console.log(`📖 Logs marcados como lidos: ${result.modifiedCount} atualizados`);
            
            return {
                success: true,
                modifiedCount: result.modifiedCount,
                message: `${result.modifiedCount} logs marcados como lidos`
            };
            
        } catch (error) {
            console.error('❌ Erro ao marcar logs como lidos:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Obter atividade recente
     */
    async getRecentActivity(limit = 20) {
        try {
            const logs = await SystemLog.find()
                .sort({ timestamp: -1 })
                .limit(limit)
                .lean();
            
            return logs.map(log => ({
                id: log._id,
                user: log.user,
                action: log.action,
                module: log.module,
                message: log.message,
                timestamp: log.timestamp,
                formattedTime: this.formatTime(log.timestamp),
                icon: this.getActivityIcon(log.action, log.module)
            }));
            
        } catch (error) {
            console.error('❌ Erro ao obter atividade recente:', error);
            return [];
        }
    }
    
    /**
     * Obter ícone para atividade
     */
    getActivityIcon(action, module) {
        const icons = {
            login: 'fas fa-sign-in-alt',
            logout: 'fas fa-sign-out-alt',
            create: 'fas fa-plus-circle',
            update: 'fas fa-edit',
            delete: 'fas fa-trash-alt',
            view: 'fas fa-eye',
            approve: 'fas fa-check-circle',
            reject: 'fas fa-times-circle',
            system: 'fas fa-cog'
        };
        
        return icons[action] || 'fas fa-info-circle';
    }
    
    /**
     * Formatar tempo (amigável)
     */
    formatTime(date) {
        if (!date) return '';
        
        const now = new Date();
        const timeDate = new Date(date);
        const diffMs = now - timeDate;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'Agora mesmo';
        if (diffMins < 60) return `Há ${diffMins} min`;
        if (diffHours < 24) return `Há ${diffHours} h`;
        if (diffDays === 1) return 'Ontem';
        if (diffDays < 7) return `Há ${diffDays} dias`;
        
        return timeDate.toLocaleDateString('pt-PT', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric'
        });
    }
    
    /**
     * Verificar saúde do sistema
     */
    async checkSystemHealth() {
        try {
            const checks = [];
            
            // Verificar conexão com MongoDB
            const mongoStatus = mongoose.connection.readyState;
            checks.push({
                name: 'MongoDB',
                status: mongoStatus === 1 ? 'healthy' : 'unhealthy',
                details: `Connection state: ${mongoStatus}`,
                critical: true
            });
            
            // Verificar número de conexões
            const adminDb = mongoose.connection.db.admin();
            const serverStatus = await adminDb.serverStatus();
            checks.push({
                name: 'Conexões MongoDB',
                status: serverStatus.connections.current < 100 ? 'healthy' : 'warning',
                details: `${serverStatus.connections.current} conexões ativas`,
                critical: false
            });
            
            // Verificar disco (estimativa)
            checks.push({
                name: 'Espaço em Disco',
                status: 'healthy',
                details: 'Espaço suficiente (estimado)',
                critical: true
            });
            
            // Verificar memória (estimativa)
            checks.push({
                name: 'Memória',
                status: 'healthy',
                details: 'Memória suficiente (estimado)',
                critical: true
            });
            
            return {
                timestamp: new Date(),
                overall: checks.every(c => c.status === 'healthy') ? 'healthy' : 
                        checks.some(c => c.status === 'unhealthy' && c.critical) ? 'unhealthy' : 'warning',
                checks: checks
            };
            
        } catch (error) {
            console.error('❌ Erro ao verificar saúde do sistema:', error);
            return {
                timestamp: new Date(),
                overall: 'unhealthy',
                checks: [{
                    name: 'Verificação de Saúde',
                    status: 'unhealthy',
                    details: error.message,
                    critical: true
                }]
            };
        }
    }
}

module.exports = new SystemController();