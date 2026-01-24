const jwt = require('jsonwebtoken');
const Staff = require('../models/Staff');

// ==============================
// FUNÇÕES PRINCIPAIS DE AUTENTICAÇÃO
// ==============================

/**
 * Verifica se o usuário está autenticado (para sessions)
 */
const requireAuth = (req, res, next) => {
    if (!req.session) {
        req.flash('error', 'Sessão expirada. Por favor faça login novamente.');
        return res.redirect('/login?error=session_expired');
    }
    
    if (req.session.staff && req.session.staff.loggedIn) {
        if (req.path === '/dashboard' || req.path === '/api/confidentiality/accept') {
            return next();
        }
        
        if (!req.session.staff.acceptedConfidentiality) {
            req.flash('warning', 'Por favor, aceite os termos de confidencialidade primeiro.');
            return res.redirect('/dashboard');
        }
        
        return next();
    }
    
    req.flash('error', 'Por favor faça login para acessar esta página.');
    res.redirect('/login');
};

/**
 * Verifica se tem uma permissão específica (para sessions)
 */
const requirePermission = (...permissions) => {
    return (req, res, next) => {
        if (!req.session || !req.session.staff) {
            req.flash('error', 'Sessão expirada. Por favor faça login novamente.');
            return res.redirect('/login?error=session_expired');
        }
        
        const staff = req.session.staff;
        
        // Admin tem acesso a tudo
        if (staff.role === 'admin') {
            return next();
        }
        
        // Se não especificar permissões, permite acesso
        if (permissions.length === 0) {
            return next();
        }
        
        // Definir permissões por role se não existirem
        if (!staff.permissions || !Array.isArray(staff.permissions) || staff.permissions.length === 0) {
            const rolePermissions = {
                'support_manager': ['view_dashboard', 'view_players', 'view_withdrawals', 'view_payments', 'view_support', 'view_staff', 'view_email', 'view_logs', 'view_settings', 'process_withdrawals', 'process_payments', 'assign_tickets', 'send_emails', 'manage_staff', 'manage_settings'],
                'support': ['view_dashboard', 'view_players', 'view_withdrawals', 'view_payments', 'view_support', 'view_email'],
                'finance': ['view_dashboard', 'view_players', 'view_withdrawals', 'view_payments', 'process_withdrawals', 'process_payments'],
                'moderator': ['view_dashboard', 'view_players', 'view_support'],
                'viewer': ['view_dashboard', 'view_players']
            };
            
            const staffPermissions = rolePermissions[staff.role] || ['view_dashboard'];
            
            req.session.staff.permissions = staffPermissions;
            
            req.session.save((err) => {
                if (err) {
                    console.error('Erro ao salvar permissões na sessão:', err);
                }
            });
            
            staff.permissions = staffPermissions;
        }
        
        // Verificar se o staff tem pelo menos uma das permissões requeridas
        const hasPermission = permissions.some(permission => 
            staff.permissions.includes(permission) || staff.permissions.includes('all')
        );
        
        if (!hasPermission) {
            if (req.headers.accept && req.headers.accept.includes('text/html')) {
                req.flash('error', `Permissão negada: Você não tem permissão para acessar esta página.`);
                return res.redirect('/dashboard');
            }
            
            return res.status(403).json({ 
                success: false, 
                error: 'Permissão negada',
                required: permissions,
                has: staff.permissions
            });
        }
        
        next();
    };
};

// ==============================
// FUNÇÕES PARA API (JWT)
// ==============================

/**
 * Verifica se o usuário está autenticado (via session ou JWT)
 */
const isAuthenticated = async (req, res, next) => {
    try {
        // Primeiro tenta verificar por session (se estiver usando sessions)
        if (req.session && req.session.staff) {
            const staff = await Staff.findById(req.session.staff._id);
            if (!staff || !staff.isActive) {
                req.session.destroy();
                return res.status(401).json({ 
                    success: false, 
                    message: 'Sessão expirada ou staff inativo' 
                });
            }
            
            // Atualizar lastActive
            staff.lastActive = new Date();
            await staff.save();
            
            req.user = staff;
            return next();
        }
        
        // Se não tem session, tenta verificar por JWT
        const token = req.header('Authorization')?.replace('Bearer ', '') || 
                     req.cookies?.token || 
                     req.query?.token;
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'Token de autenticação não fornecido' 
            });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        const staff = await Staff.findById(decoded.userId);
        
        if (!staff) {
            return res.status(401).json({ 
                success: false, 
                message: 'Staff não encontrado' 
            });
        }
        
        if (!staff.isActive) {
            return res.status(403).json({ 
                success: false, 
                message: 'Conta desativada' 
            });
        }
        
        // Verificar se conta está bloqueada
        const isLocked = await Staff.isAccountLocked(staff._id);
        if (isLocked) {
            return res.status(423).json({ 
                success: false, 
                message: 'Conta temporariamente bloqueada. Tente novamente mais tarde.' 
            });
        }
        
        // Atualizar lastActive
        staff.lastActive = new Date();
        await staff.save();
        
        req.token = token;
        req.user = staff;
        
        next();
        
    } catch (error) {
        console.error('Erro de autenticação:', error);
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Token inválido' 
            });
        }
        
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Token expirado. Faça login novamente.' 
            });
        }
        
        return res.status(500).json({ 
            success: false, 
            message: 'Erro interno do servidor' 
        });
    }
};

/**
 * Verifica se é Admin
 */
const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ 
        success: false, 
        message: 'Acesso reservado a Administradores' 
    });
};

/**
 * Verifica se tem uma role específica
 */
const hasRole = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Não autenticado' 
            });
        }
        
        if (roles.includes(req.user.role)) {
            return next();
        }
        
        return res.status(403).json({ 
            success: false, 
            message: `Acesso reservado a: ${roles.join(', ')}` 
        });
    };
};

/**
 * Verifica se tem uma permissão específica (para JWT)
 */
const hasPermission = (...permissions) => {
    return async (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Não autenticado' 
            });
        }
        
        try {
            // Admin tem acesso a tudo
            if (req.user.role === 'admin') {
                return next();
            }
            
            // Verificar cada permissão
            for (const permission of permissions) {
                if (!req.user.hasPermission(permission)) {
                    return res.status(403).json({ 
                        success: false, 
                        message: `Permissão necessária: ${permission}` 
                    });
                }
            }
            
            next();
        } catch (error) {
            console.error('Erro ao verificar permissões:', error);
            return res.status(500).json({ 
                success: false, 
                message: 'Erro ao verificar permissões' 
            });
        }
    };
};

// ==============================
// FUNÇÕES ESPECÍFICAS
// ==============================

/**
 * Verifica se tem acesso ao chat interno
 */
const hasChatAccess = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ 
            success: false, 
            message: 'Não autenticado' 
        });
    }
    
    // Verificar se o staff tem acesso ao chat
    if (!req.user.communicationPreferences?.internalChat) {
        return res.status(403).json({ 
            success: false, 
            message: 'Acesso ao chat interno não permitido' 
        });
    }
    
    next();
};

/**
 * Verifica se está online e disponível
 */
const isAvailableForChat = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ 
            success: false, 
            message: 'Não autenticado' 
        });
    }
    
    // Verificar se está online e disponível para chat
    if (!req.user.isAvailableForChat()) {
        return res.status(423).json({ 
            success: false, 
            message: 'Staff não disponível para chat no momento' 
        });
    }
    
    next();
};

/**
 * Middleware para atualizar status online
 */
const updateOnlineStatus = async (req, res, next) => {
    try {
        if (req.user) {
            // Verificar se é uma rota que indica atividade
            const activityRoutes = [
                '/api/chat',
                '/api/email',
                '/api/support',
                '/dashboard',
                '/players'
            ];
            
            const isActivityRoute = activityRoutes.some(route => 
                req.originalUrl.includes(route)
            );
            
            if (isActivityRoute) {
                // Atualizar lastActive
                req.user.lastActive = new Date();
                await req.user.save();
            }
        }
        next();
    } catch (error) {
        console.error('Erro ao atualizar status online:', error);
        next(); // Continuar mesmo com erro
    }
};

/**
 * Middleware para verificar aceitação de confidencialidade
 */
const hasAcceptedConfidentiality = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ 
            success: false, 
            message: 'Não autenticado' 
        });
    }
    
    // Admin não precisa aceitar (pode ser configurado)
    if (req.user.role === 'admin') {
        return next();
    }
    
    // Verificar se aceitou a política de confidencialidade
    if (!req.user.acceptedConfidentiality) {
        return res.status(403).json({ 
            success: false, 
            message: 'É necessário aceitar a política de confidencialidade' 
        });
    }
    
    next();
};

/**
 * Middleware para obter informações do staff para views
 */
const getStaffInfo = async (req, res, next) => {
    try {
        if (req.user) {
            // Adicionar informações do staff para as views
            res.locals.staff = {
                _id: req.user._id,
                name: req.user.name,
                email: req.user.email,
                role: req.user.role,
                photo: req.user.photo,
                department: req.user.department,
                isOnline: req.user.isOnline,
                chatStatus: req.user.chatStatus,
                settings: req.user.settings,
                permissions: req.user.permissions,
                hasPermission: (permission) => req.user.hasPermission(permission)
            };
            
            // Adicionar mensagens não lidas para o chat
            if (req.user.communicationPreferences?.internalChat) {
                const InternalMessage = require('../models/InternalMessage');
                const unreadCount = await InternalMessage.countUnread(req.user._id);
                res.locals.unreadInternalCount = unreadCount;
            }
        }
        next();
    } catch (error) {
        console.error('Erro ao obter informações do staff:', error);
        next();
    }
};

/**
 * Middleware para rate limiting específico por staff
 */
const staffRateLimit = (windowMs = 15 * 60 * 1000, max = 100) => {
    const requests = new Map();
    
    return (req, res, next) => {
        if (!req.user) {
            return next();
        }
        
        const staffId = req.user._id.toString();
        const now = Date.now();
        
        if (!requests.has(staffId)) {
            requests.set(staffId, { count: 1, startTime: now });
        } else {
            const staffRequests = requests.get(staffId);
            
            // Resetar se a janela de tempo expirou
            if (now - staffRequests.startTime > windowMs) {
                staffRequests.count = 1;
                staffRequests.startTime = now;
            } else {
                staffRequests.count++;
            }
            
            // Verificar se excedeu o limite
            if (staffRequests.count > max) {
                return res.status(429).json({
                    success: false,
                    message: 'Muitas requisições. Tente novamente mais tarde.'
                });
            }
        }
        
        // Limpar entradas antigas periodicamente
        if (Math.random() < 0.01) { // 1% chance a cada request
            for (const [id, data] of requests) {
                if (now - data.startTime > windowMs) {
                    requests.delete(id);
                }
            }
        }
        
        next();
    };
};

/**
 * Middleware para log de atividade
 */
const activityLogger = (req, res, next) => {
    const startTime = Date.now();
    
    // Registrar resposta
    const originalSend = res.send;
    res.send = function(body) {
        const duration = Date.now() - startTime;
        
        // Registrar atividade importante
        if (req.user && duration > 1000) { // Log apenas requests lentos
            console.log(`[ACTIVITY] ${req.user.email} - ${req.method} ${req.originalUrl} - ${duration}ms`);
        }
        
        originalSend.call(this, body);
    };
    
    next();
};

// ==============================
// FUNÇÕES AUXILIARES
// ==============================

/**
 * Converte permissões de session para o formato do teu emailRoutes.js
 */
const checkSessionPermissions = (req, res, next) => {
    if (req.session && req.session.staff) {
        // Garantir que as permissões estão definidas
        if (!req.session.staff.permissions || !Array.isArray(req.session.staff.permissions)) {
            const rolePermissions = {
                'admin': ['all'],
                'support_manager': ['view_dashboard', 'view_players', 'view_withdrawals', 'view_payments', 'view_support', 'view_staff', 'view_email', 'view_logs', 'view_settings', 'process_withdrawals', 'process_payments', 'assign_tickets', 'send_emails', 'manage_staff', 'manage_settings'],
                'support': ['view_dashboard', 'view_players', 'view_withdrawals', 'view_payments', 'view_support', 'view_email'],
                'finance': ['view_dashboard', 'view_players', 'view_withdrawals', 'view_payments', 'process_withdrawals', 'process_payments'],
                'moderator': ['view_dashboard', 'view_players', 'view_support'],
                'viewer': ['view_dashboard', 'view_players']
            };
            
            req.session.staff.permissions = rolePermissions[req.session.staff.role] || ['view_dashboard'];
        }
    }
    next();
};

module.exports = {
    // Para sessions (usado nas tuas rotas)
    requireAuth,
    requirePermission,
    checkSessionPermissions,
    
    // Para APIs (JWT)
    isAuthenticated,
    isAdmin,
    hasRole,
    hasPermission,
    
    // Funções específicas
    hasChatAccess,
    isAvailableForChat,
    updateOnlineStatus,
    hasAcceptedConfidentiality,
    getStaffInfo,
    staffRateLimit,
    activityLogger
};