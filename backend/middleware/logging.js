const Log = require('../models/Log');
const geoip = require('geoip-lite');

// Middleware para criar logs automáticos
exports.createLog = async (req, res, next) => {
    try {
        const originalSend = res.send;
        
        res.send = function(data) {
            // Esperar a resposta ser enviada antes de criar o log
            setTimeout(async () => {
                try {
                    // Não logar rotas de API de logs para evitar loops
                    if (req.path.startsWith('/api/logs')) {
                        return;
                    }
                    
                    // Determinar ação com base no método HTTP
                    let action = 'view';
                    if (req.method === 'POST') action = 'create';
                    if (req.method === 'PUT' || req.method === 'PATCH') action = 'update';
                    if (req.method === 'DELETE') action = 'delete';
                    
                    // Determinar módulo com base na rota
                    let module = 'system';
                    if (req.path.includes('/players')) module = 'players';
                    if (req.path.includes('/withdrawals')) module = 'withdrawals';
                    if (req.path.includes('/payments')) module = 'payments';
                    if (req.path.includes('/staff')) module = 'staff';
                    if (req.path.includes('/settings')) module = 'settings';
                    if (req.path.includes('/auth')) module = 'auth';
                    if (req.path.includes('/games')) module = 'games';
                    if (req.path.includes('/bonuses')) module = 'bonuses';
                    if (req.path.includes('/reports')) module = 'reports';
                    if (req.path.includes('/email')) module = 'email';
                    
                    // Criar mensagem
                    let message = `${req.method} ${req.path}`;
                    if (req.user) {
                        message = `${req.user.name} ${req.method} ${req.path}`;
                    }
                    
                    // Obter localização do IP
                    let location = null;
                    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
                    if (ip) {
                        const geo = geoip.lookup(ip);
                        if (geo) {
                            location = `${geo.city}, ${geo.country}`;
                        }
                    }
                    
                    // Criar log
                    await Log.create({
                        user: req.user ? {
                            _id: req.user._id,
                            name: req.user.name,
                            email: req.user.email,
                            role: req.user.role
                        } : null,
                        action,
                        module,
                        message,
                        details: JSON.stringify({
                            params: req.params,
                            query: req.query,
                            body: req.method === 'GET' ? null : req.body
                        }),
                        ip,
                        location,
                        userAgent: req.headers['user-agent'],
                        sessionId: req.sessionID
                    });
                } catch (error) {
                    console.error('Erro ao criar log:', error);
                }
            }, 100);
            
            originalSend.call(this, data);
        };
        
        next();
    } catch (error) {
        console.error('Erro no middleware de logging:', error);
        next();
    }
};

// Função para criar logs manuais
exports.createManualLog = async (user, action, module, message, details = null) => {
    try {
        await Log.create({
            user: user ? {
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            } : null,
            action,
            module,
            message,
            details,
            timestamp: new Date()
        });
    } catch (error) {
        console.error('Erro ao criar log manual:', error);
    }
};