const express = require('express');
const router = express.Router();
const Staff = require('../models/Staff'); // Modelo MongoDB para staff
const bcrypt = require('bcryptjs');
const Notification = require('../models/Notification'); // Adicione este modelo

// ============ MIDDLEWARE DE AUTENTICAÇÃO ============
// NOTA: Você precisa criar ou usar o middleware existente do seu server.js
// Se você não tem o middleware 'authenticateAdmin', use este temporariamente:
const requireAuth = (req, res, next) => {
    if (!req.session || !req.session.staff || !req.session.staff.loggedIn) {
        return res.status(401).json({ success: false, error: 'Não autenticado' });
    }
    req.user = req.session.staff;
    next();
};

router.use(requireAuth);

// ============ ROTA PRINCIPAL (Página Staff) ============
router.get('/staff', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        
        // Construir query baseada nos filtros
        let query = {};
        
        // Filtro por pesquisa
        if (req.query.search) {
            const searchRegex = new RegExp(req.query.search, 'i');
            query.$or = [
                { name: searchRegex },
                { email: searchRegex },
                { department: searchRegex }
            ];
        }
        
        // Filtro por cargo
        if (req.query.role && req.query.role !== 'all') {
            query.role = req.query.role;
        }
        
        // Filtro por estado - CORRIGIDO: usar req.query.status
        if (req.query.status && req.query.status !== 'all') {
            query.isActive = req.query.status === 'active';
        }
        
        // Ordenação
        let sort = {};
        if (req.query.sort === 'name') {
            sort.name = req.query.order === 'asc' ? 1 : -1;
        } else if (req.query.sort === 'createdAt') {
            sort.createdAt = req.query.order === 'asc' ? 1 : -1;
        } else if (req.query.sort === 'lastLogin') {
            sort.lastLogin = req.query.order === 'asc' ? 1 : -1;
        } else {
            sort.createdAt = -1; // Default: mais recentes primeiro
        }
        
        // Buscar staff
        const staffMembers = await Staff.find(query)
            .select('-password -resetPasswordToken -resetPasswordExpires')
            .sort(sort)
            .skip(skip)
            .limit(limit);
        
        // Contar total
        const total = await Staff.countDocuments(query);
        const totalPages = Math.ceil(total / limit);
        
        // Obter estatísticas
        const totalStats = await Staff.countDocuments();
        const activeStats = await Staff.countDocuments({ isActive: true });
        const adminsStats = await Staff.countDocuments({ role: 'admin', isActive: true });
        const supportStats = await Staff.countDocuments({ 
            $or: [
                { role: 'support' },
                { role: 'support_manager' }
            ],
            isActive: true 
        });
        
        // Obter notificações
        let notifications = [];
        let unreadCount = 0;
        try {
            notifications = await Notification.find({ userId: req.user.id })
                .sort({ createdAt: -1 })
                .limit(20);
            
            unreadCount = await Notification.countDocuments({ 
                userId: req.user.id, 
                read: false 
            });
        } catch (notifError) {
            console.log('Aviso: Modelo Notification não encontrado, usando notificações mockadas');
            // Se o modelo Notification não existir, usar dados mockados
            notifications = [
                {
                    title: 'Sistema de Notificações',
                    message: 'Configure o modelo Notification para usar notificações reais',
                    type: 'info',
                    read: false,
                    createdAt: new Date()
                }
            ];
            unreadCount = 1;
        }
        
        // Opções de cargos para o filtro
        const roleOptions = [
            { value: 'admin', label: 'Administrador' },
            { value: 'support_manager', label: 'Gestor de Suporte' },
            { value: 'support', label: 'Suporte' },
            { value: 'finance', label: 'Financeiro' },
            { value: 'moderator', label: 'Moderador' },
            { value: 'viewer', label: 'Visualizador' }
        ];
        
        res.render('staff', {
            title: 'Gestão de Staff | B7Uno Casino',
            breadcrumb: 'Gestão de Staff',
            user: req.user,
            staffMembers,
            stats: {
                total: totalStats,
                active: activeStats,
                inactive: totalStats - activeStats,
                admins: adminsStats,
                support: supportStats,
                others: totalStats - adminsStats - supportStats
            },
            currentPage: page,
            totalPages,
            totalItems: total,
            roleOptions,
            
            // Filtros atuais para manter estado na UI
            search: req.query.search || '',
            role: req.query.role || 'all',
            status: req.query.status || 'all', // ← ESTA LINHA É ESSENCIAL!
            sort: req.query.sort || 'name',
            order: req.query.order || 'desc',
            
            // Notificações
            notifications: {
                unreadCount,
                notifications: notifications.map(n => ({
                    ...n.toObject ? n.toObject() : n,
                    _id: n._id ? n._id.toString() : Math.random().toString(36).substr(2, 9)
                }))
            },
            
            // Aceitação de confidencialidade
            acceptedConfidentiality: req.user.acceptedConfidentiality || false
        });
        
    } catch (error) {
        console.error('Erro ao carregar página staff:', error);
        res.status(500).send('Erro no servidor: ' + error.message);
    }
});

// ============ ROTAS DA API STAFF ============

// 1. LISTAR STAFF (com paginação e filtros) - API
router.get('/api/staff/list', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        
        // Construir query baseada nos filtros
        let query = {};
        
        // Filtro por pesquisa
        if (req.query.search) {
            const searchRegex = new RegExp(req.query.search, 'i');
            query.$or = [
                { name: searchRegex },
                { email: searchRegex },
                { department: searchRegex }
            ];
        }
        
        // Filtro por cargo
        if (req.query.role && req.query.role !== 'all') {
            query.role = req.query.role;
        }
        
        // Filtro por estado
        if (req.query.status && req.query.status !== 'all') {
            query.isActive = req.query.status === 'active';
        }
        
        // Ordenação
        let sort = {};
        if (req.query.sort === 'name') {
            sort.name = req.query.order === 'asc' ? 1 : -1;
        } else if (req.query.sort === 'createdAt') {
            sort.createdAt = req.query.order === 'asc' ? 1 : -1;
        } else if (req.query.sort === 'lastLogin') {
            sort.lastLogin = req.query.order === 'asc' ? 1 : -1;
        } else {
            sort.createdAt = -1; // Default: mais recentes primeiro
        }
        
        // Buscar staff
        const staffMembers = await Staff.find(query)
            .select('-password -resetPasswordToken -resetPasswordExpires')
            .sort(sort)
            .skip(skip)
            .limit(limit);
        
        // Contar total
        const total = await Staff.countDocuments(query);
        
        res.json({
            success: true,
            staffMembers,
            total,
            totalPages: Math.ceil(total / limit),
            currentPage: page
        });
        
    } catch (error) {
        console.error('Erro ao listar staff:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 2. CRIAR NOVO STAFF
router.post('/api/staff/create', async (req, res) => {
    try {
        const { name, email, password, role, department, isActive } = req.body;
        
        // Validar dados
        if (!name || !email || !password || !role) {
            return res.status(400).json({
                success: false,
                error: 'Todos os campos obrigatórios devem ser preenchidos'
            });
        }
        
        // Verificar se email já existe
        const existingStaff = await Staff.findOne({ email: email.toLowerCase() });
        if (existingStaff) {
            return res.status(400).json({
                success: false,
                error: 'Este email já está registado'
            });
        }
        
        // Verificar força da password
        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                error: 'A password deve ter pelo menos 8 caracteres'
            });
        }
        
        // Hash da password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Criar novo staff
        const newStaff = new Staff({
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            role,
            department: department || 'Staff',
            isActive: isActive !== false,
            createdBy: req.user.id
        });
        
        await newStaff.save();
        
        // Criar notificação de novo staff
        try {
            const notification = new Notification({
                userId: req.user.id,
                title: 'Novo Staff Criado',
                message: `Staff "${name}" foi criado com sucesso.`,
                type: 'success'
            });
            await notification.save();
        } catch (notifError) {
            console.log('Aviso: Não foi possível criar notificação');
        }
        
        // Remover password da resposta
        const staffResponse = newStaff.toObject();
        delete staffResponse.password;
        delete staffResponse.resetPasswordToken;
        delete staffResponse.resetPasswordExpires;
        
        res.json({
            success: true,
            message: 'Staff criado com sucesso',
            staff: staffResponse
        });
        
    } catch (error) {
        console.error('Erro ao criar staff:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 3. EDITAR STAFF
router.post('/api/staff/:id/update', async (req, res) => {
    try {
        const staffId = req.params.id;
        const { name, email, role, department, isActive, password } = req.body;
        
        // Validar dados básicos
        if (!name || !email || !role) {
            return res.status(400).json({
                success: false,
                error: 'Nome, email e cargo são obrigatórios'
            });
        }
        
        // Buscar staff
        const staff = await Staff.findById(staffId);
        if (!staff) {
            return res.status(404).json({
                success: false,
                error: 'Staff não encontrado'
            });
        }
        
        // Verificar se é o próprio usuário (não pode editar a si mesmo algumas coisas)
        if (staff._id.toString() === req.user.id && req.body.role && req.body.role !== staff.role) {
            return res.status(403).json({
                success: false,
                error: 'Não pode alterar o seu próprio cargo'
            });
        }
        
        // Verificar se email já existe (se mudou)
        if (email.toLowerCase() !== staff.email.toLowerCase()) {
            const existingStaff = await Staff.findOne({ 
                email: email.toLowerCase(),
                _id: { $ne: staffId }
            });
            
            if (existingStaff) {
                return res.status(400).json({
                    success: false,
                    error: 'Este email já está registado'
                });
            }
        }
        
        // Atualizar staff
        staff.name = name;
        staff.email = email.toLowerCase();
        staff.role = role;
        staff.department = department || 'Staff';
        staff.isActive = isActive !== false;
        staff.updatedBy = req.user.id;
        staff.updatedAt = new Date();
        
        // Atualizar password se fornecida
        if (password && password.length >= 8) {
            const salt = await bcrypt.genSalt(10);
            staff.password = await bcrypt.hash(password, salt);
        }
        
        await staff.save();
        
        // Criar notificação
        try {
            const notification = new Notification({
                userId: req.user.id,
                title: 'Staff Atualizado',
                message: `Staff "${name}" foi atualizado.`,
                type: 'info'
            });
            await notification.save();
        } catch (notifError) {
            console.log('Aviso: Não foi possível criar notificação');
        }
        
        // Remover password da resposta
        const staffResponse = staff.toObject();
        delete staffResponse.password;
        delete staffResponse.resetPasswordToken;
        delete staffResponse.resetPasswordExpires;
        
        res.json({
            success: true,
            message: 'Staff atualizado com sucesso',
            staff: staffResponse
        });
        
    } catch (error) {
        console.error('Erro ao atualizar staff:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 4. ATIVAR STAFF
router.post('/api/staff/:id/activate', async (req, res) => {
    try {
        const staffId = req.params.id;
        
        // Buscar staff
        const staff = await Staff.findById(staffId);
        if (!staff) {
            return res.status(404).json({
                success: false,
                error: 'Staff não encontrado'
            });
        }
        
        // Verificar se já está ativo
        if (staff.isActive) {
            return res.status(400).json({
                success: false,
                error: 'Este staff já está ativo'
            });
        }
        
        // Verificar se é o próprio usuário
        if (staff._id.toString() === req.user.id) {
            return res.status(403).json({
                success: false,
                error: 'Não pode ativar a sua própria conta'
            });
        }
        
        // Ativar conta
        staff.isActive = true;
        staff.updatedBy = req.user.id;
        staff.updatedAt = new Date();
        
        await staff.save();
        
        // Criar notificação
        try {
            const notification = new Notification({
                userId: req.user.id,
                title: 'Conta Ativada',
                message: `Conta de "${staff.name}" foi ativada.`,
                type: 'success'
            });
            await notification.save();
        } catch (notifError) {
            console.log('Aviso: Não foi possível criar notificação');
        }
        
        res.json({
            success: true,
            message: 'Conta ativada com sucesso'
        });
        
    } catch (error) {
        console.error('Erro ao ativar staff:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 5. DESATIVAR STAFF
router.post('/api/staff/:id/deactivate', async (req, res) => {
    try {
        const staffId = req.params.id;
        
        // Buscar staff
        const staff = await Staff.findById(staffId);
        if (!staff) {
            return res.status(404).json({
                success: false,
                error: 'Staff não encontrado'
            });
        }
        
        // Verificar se já está inativo
        if (!staff.isActive) {
            return res.status(400).json({
                success: false,
                error: 'Este staff já está inativo'
            });
        }
        
        // Verificar se é o próprio usuário
        if (staff._id.toString() === req.user.id) {
            return res.status(403).json({
                success: false,
                error: 'Não pode desativar a sua própria conta'
            });
        }
        
        // Desativar conta
        staff.isActive = false;
        staff.updatedBy = req.user.id;
        staff.updatedAt = new Date();
        
        await staff.save();
        
        // Criar notificação
        try {
            const notification = new Notification({
                userId: req.user.id,
                title: 'Conta Desativada',
                message: `Conta de "${staff.name}" foi desativada.`,
                type: 'warning'
            });
            await notification.save();
        } catch (notifError) {
            console.log('Aviso: Não foi possível criar notificação');
        }
        
        res.json({
            success: true,
            message: 'Conta desativada com sucesso'
        });
        
    } catch (error) {
        console.error('Erro ao desativar staff:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 6. ELIMINAR STAFF PERMANENTEMENTE
router.delete('/api/staff/:id/delete', async (req, res) => {
    try {
        const staffId = req.params.id;
        
        // Buscar staff
        const staff = await Staff.findById(staffId);
        if (!staff) {
            return res.status(404).json({
                success: false,
                error: 'Staff não encontrado'
            });
        }
        
        // Verificar se é o próprio usuário
        if (staff._id.toString() === req.user.id) {
            return res.status(403).json({
                success: false,
                error: 'Não pode eliminar a sua própria conta'
            });
        }
        
        // Verificar se é o único administrador
        if (staff.role === 'admin') {
            const adminCount = await Staff.countDocuments({ 
                role: 'admin',
                isActive: true,
                _id: { $ne: staffId }
            });
            
            if (adminCount === 0) {
                return res.status(400).json({
                    success: false,
                    error: 'Não pode eliminar o único administrador ativo'
                });
            }
        }
        
        const staffName = staff.name;
        
        // Eliminar staff
        await Staff.findByIdAndDelete(staffId);
        
        // Criar notificação
        try {
            const notification = new Notification({
                userId: req.user.id,
                title: 'Staff Eliminado',
                message: `Staff "${staffName}" foi eliminado permanentemente.`,
                type: 'danger'
            });
            await notification.save();
        } catch (notifError) {
            console.log('Aviso: Não foi possível criar notificação');
        }
        
        res.json({
            success: true,
            message: 'Staff eliminado permanentemente com sucesso'
        });
        
    } catch (error) {
        console.error('Erro ao eliminar staff:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 7. OBTER ESTATÍSTICAS DE STAFF
router.get('/api/staff/stats', async (req, res) => {
    try {
        const total = await Staff.countDocuments();
        const active = await Staff.countDocuments({ isActive: true });
        const admins = await Staff.countDocuments({ role: 'admin', isActive: true });
        const support = await Staff.countDocuments({ 
            $or: [
                { role: 'support' },
                { role: 'support_manager' }
            ],
            isActive: true 
        });
        
        res.json({
            success: true,
            stats: {
                total,
                active,
                inactive: total - active,
                admins,
                support,
                others: total - admins - support
            }
        });
        
    } catch (error) {
        console.error('Erro ao obter estatísticas de staff:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 8. RESET PASSWORD DO STAFF
router.post('/api/staff/:id/reset-password', async (req, res) => {
    try {
        const staffId = req.params.id;
        const { newPassword } = req.body;
        
        if (!newPassword || newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                error: 'A nova password deve ter pelo menos 8 caracteres'
            });
        }
        
        // Buscar staff
        const staff = await Staff.findById(staffId);
        if (!staff) {
            return res.status(404).json({
                success: false,
                error: 'Staff não encontrado'
            });
        }
        
        // Hash da nova password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        
        // Atualizar password
        staff.password = hashedPassword;
        staff.updatedBy = req.user.id;
        staff.updatedAt = new Date();
        
        await staff.save();
        
        // Criar notificação
        try {
            const notification = new Notification({
                userId: req.user.id,
                title: 'Password Resetada',
                message: `Password de "${staff.name}" foi resetada.`,
                type: 'info'
            });
            await notification.save();
        } catch (notifError) {
            console.log('Aviso: Não foi possível criar notificação');
        }
        
        res.json({
            success: true,
            message: 'Password alterada com sucesso'
        });
        
    } catch (error) {
        console.error('Erro ao resetar password:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// 9. OBTER DETALHES DE UM STAFF
router.get('/api/staff/:id', async (req, res) => {
    try {
        const staffId = req.params.id;
        
        const staff = await Staff.findById(staffId)
            .select('-password -resetPasswordToken -resetPasswordExpires');
        
        if (!staff) {
            return res.status(404).json({
                success: false,
                error: 'Staff não encontrado'
            });
        }
        
        res.json({
            success: true,
            staff
        });
        
    } catch (error) {
        console.error('Erro ao obter detalhes do staff:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

// ============ ROTA PARA ACEITAR CONFIDENCIALIDADE ============
router.post('/api/confidentiality/accept', async (req, res) => {
    try {
        // Atualizar usuário para marcar que aceitou os termos
        await Staff.findByIdAndUpdate(req.user.id, {
            acceptedConfidentiality: true,
            confidentialityAcceptedAt: new Date()
        });
        
        res.json({
            success: true,
            message: 'Termos de confidencialidade aceitos'
        });
        
    } catch (error) {
        console.error('Erro ao aceitar confidencialidade:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno do servidor'
        });
    }
});

module.exports = router;