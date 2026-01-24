const Log = require('../models/Log');
const geoip = require('geoip-lite');
const useragent = require('useragent');

// Middleware para log automático de requisições
const requestLogger = async (req, res, next) => {
    // Não logar requests de logs para evitar loops
    if (req.path.includes('/logs') || req.path.includes('/api/logs')) {
        return next();
    }

    const startTime = Date.now();
    
    // Salvar a função original de send
    const originalSend = res.send;
    
    res.send = function(data) {
        // Restaurar função original
        res.send = originalSend;
        
        // Executar depois da resposta ser enviada
        process.nextTick(async () => {
            try {
                if (req.user) {
                    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
                    const geo = geoip.lookup(ip);
                    const agent = useragent.parse(req.headers['user-agent']);
                    
                    let action = 'unknown';
                    let module = 'system';
                    let message = `${req.method} ${req.path}`;
                    
                    // Determinar ação baseada no método HTTP
                    switch (req.method) {
                        case 'POST':
                            action = 'create';
                            break;
                        case 'PUT':
                        case 'PATCH':
                            action = 'update';
                            break;
                        case 'DELETE':
                            action = 'delete';
                            break;
                        case 'GET':
                            action = req.path.includes('/login') ? 'login' : 'read';
                            break;
                    }
                    
                    // Determinar módulo baseado na rota
                    if (req.path.includes('/players')) module = 'players';
                    else if (req.path.includes('/withdrawals')) module = 'withdrawals';
                    else if (req.path.includes('/payments')) module = 'payments';
                    else if (req.path.includes('/staff')) module = 'staff';
                    else if (req.path.includes('/settings')) module = 'settings';
                    else if (req.path.includes('/dashboard')) module = 'auth';
                    
                    // Log de login/logout específico
                    if (req.path === '/api/auth/login') {
                        action = 'login';
                        module = 'auth';
                        message = 'Login realizado com sucesso';
                    } else if (req.path === '/logout') {
                        action = 'logout';
                        module = 'auth';
                        message = 'Logout realizado';
                    }
                    
                    const logData = {
                        userId: req.user._id,
                        user: {
                            name: req.user.name,
                            email: req.user.email,
                            role: req.user.role
                        },
                        action,
                        module,
                        message,
                        ip,
                        userAgent: agent.toString(),
                        location: geo ? `${geo.city}, ${geo.country}` : 'Desconhecido',
                        sessionId: req.sessionID,
                        metadata: {
                            method: req.method,
                            path: req.path,
                            statusCode: res.statusCode,
                            responseTime: Date.now() - startTime,
                            params: req.params,
                            query: req.query,
                            bodySize: JSON.stringify(req.body).length
                        }
                    };
                    
                    // Não logar detalhes sensíveis
                    if (req.body.password) {
                        logData.metadata.body = { ...req.body, password: '***' };
                    } else if (req.body.email) {
                        logData.metadata.body = { ...req.body, email: '***' };
                    } else {
                        logData.metadata.body = req.body;
                    }
                    
                    const log = new Log(logData);
                    await log.save();
                    
                    // Emitir via WebSocket se disponível
                    if (req.app.get('io')) {
                        req.app.get('io').emit('new_log', { log });
                    }
                }
            } catch (error) {
                console.error('Erro ao salvar log:', error);
            }
        });
        
        return originalSend.call(this, data);
    };
    
    next();
};

// Função para log manual
const createLog = async (userId, userData, action, module, message, details = null, req = null) => {
    try {
        let ip = '127.0.0.1';
        let userAgent = 'Unknown';
        let location = 'Localhost';
        let sessionId = null;
        
        if (req) {
            ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            const geo = geoip.lookup(ip);
            const agent = useragent.parse(req.headers['user-agent']);
            userAgent = agent.toString();
            location = geo ? `${geo.city}, ${geo.country}` : 'Desconhecido';
            sessionId = req.sessionID;
        }
        
        const logData = {
            userId,
            user: userData,
            action,
            module,
            message,
            details,
            ip,
            userAgent,
            location,
            sessionId
        };
        
        const log = new Log(logData);
        await log.save();
        
        // Emitir via WebSocket
        if (req && req.app.get('io')) {
            req.app.get('io').emit('new_log', { log });
        }
        
        return log;
    } catch (error) {
        console.error('Erro ao criar log:', error);
        return null;
    }
};

module.exports = {
    requestLogger,
    createLog
};