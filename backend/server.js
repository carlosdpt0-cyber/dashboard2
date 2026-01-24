const express = require('express');
const mysql = require('mysql2/promise');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const http = require('http');
const flash = require('connect-flash');
const multer = require('multer');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

dotenv.config();

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// ==============================
// CONFIGURAÇÃO CRÍTICA PARA HOSTINGER
// ==============================
app.set('trust proxy', 1);

// ==============================
// CONFIGURAÇÃO DO MySQL (phpMyAdmin)
// ==============================

const decodedPassword = decodeURIComponent(process.env.DB_PASSWORD || '');

const dbConfig = {
    host: process.env.DB_HOST || '193.203.168.151',
    user: process.env.DB_USER || 'u920267475_dashboard',
    password: process.env.DB_PASSWORD || 'Zy@jtldui@_sy1@',
    database: process.env.DB_NAME || 'u920267475_dashboard',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    charset: 'utf8mb4',
    timezone: 'local'
};

console.log('🔄 Tentando conectar ao MySQL...');

// Criar pool de conexões
const pool = mysql.createPool(dbConfig);

// Testar conexão
(async () => {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Conectado ao MySQL - Base: velvetwin');
        
        // Verificar/criar tabelas necessárias
        await createTablesIfNotExist(connection);
        connection.release();
    } catch (err) {
        console.error('❌ ERRO CRÍTICO ao conectar ao MySQL:', err.message);
        process.exit(1);
    }
})();

// ==============================
// FUNÇÃO PARA CRIAR TABELAS
// ==============================

async function createTablesIfNotExist(connection) {
    const tables = [
        `CREATE TABLE IF NOT EXISTS staffs (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role ENUM('admin', 'support_manager', 'support', 'finance', 'moderator', 'viewer') DEFAULT 'support',
            department VARCHAR(100),
            photo VARCHAR(255),
            isActive BOOLEAN DEFAULT TRUE,
            isOnline BOOLEAN DEFAULT FALSE,
            lastActive DATETIME,
            lastLogin DATETIME,
            acceptedConfidentiality BOOLEAN DEFAULT FALSE,
            confidentialityAcceptedAt DATETIME,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_email (email),
            INDEX idx_role (role),
            INDEX idx_isActive (isActive)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

        `CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            username VARCHAR(50),
            email VARCHAR(100),
            firstName VARCHAR(50),
            lastName VARCHAR(50),
            password VARCHAR(255),
            balance DECIMAL(15,2) DEFAULT 0,
            bonusBalance DECIMAL(15,2) DEFAULT 0,
            level VARCHAR(20) DEFAULT 'Bronze',
            country VARCHAR(50),
            newsletter BOOLEAN DEFAULT FALSE,
            totalWagered DECIMAL(15,2) DEFAULT 0,
            totalWins DECIMAL(15,2) DEFAULT 0,
            gamesPlayed INT DEFAULT 0,
            isActive BOOLEAN DEFAULT TRUE,
            lastLogin DATETIME,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            ipAddress VARCHAR(45),
            kycStatus VARCHAR(20) DEFAULT 'pending',
            depositLimit DECIMAL(15,2) DEFAULT 1000,
            withdrawalLimit DECIMAL(15,2) DEFAULT 1000,
            INDEX idx_email (email),
            INDEX idx_isActive (isActive),
            INDEX idx_lastLogin (lastLogin)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

        `CREATE TABLE IF NOT EXISTS user_notifications (
            id INT PRIMARY KEY AUTO_INCREMENT,
            userId INT,
            title VARCHAR(255),
            message TEXT,
            type ENUM('info', 'warning', 'danger', 'success', 'system') DEFAULT 'info',
            \`read\` BOOLEAN DEFAULT FALSE,
            relatedTo VARCHAR(50),
            relatedId INT,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            metadata JSON,
            FOREIGN KEY (userId) REFERENCES staffs(id) ON DELETE CASCADE,
            INDEX idx_userId (userId),
            INDEX idx_read (\`read\`),
            INDEX idx_createdAt (createdAt)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

        `CREATE TABLE IF NOT EXISTS email_logs (
            id INT PRIMARY KEY AUTO_INCREMENT,
            \`to\` JSON,
            subject VARCHAR(255),
            template VARCHAR(50),
            sentByStaffId INT,
            sentByStaffName VARCHAR(100),
            sentAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            status ENUM('sent', 'failed', 'pending') DEFAULT 'pending',
            error TEXT,
            playersCount INT DEFAULT 0,
            message TEXT,
            FOREIGN KEY (sentByStaffId) REFERENCES staffs(id) ON DELETE SET NULL,
            INDEX idx_sentAt (sentAt),
            INDEX idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

        `CREATE TABLE IF NOT EXISTS withdrawals (
            id INT PRIMARY KEY AUTO_INCREMENT,
            playerId INT,
            playerName VARCHAR(100),
            playerEmail VARCHAR(100),
            amount DECIMAL(15,2),
            currency VARCHAR(10) DEFAULT 'EUR',
            method VARCHAR(50),
            status ENUM('pending', 'approved', 'rejected', 'processing', 'cancelled') DEFAULT 'pending',
            accountDetails JSON,
            requestedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            processedAt DATETIME,
            processedBy VARCHAR(100),
            processorId INT,
            notes TEXT,
            transactionId VARCHAR(100),
            fee DECIMAL(15,2) DEFAULT 0,
            netAmount DECIMAL(15,2),
            playerBalanceBefore DECIMAL(15,2),
            playerBalanceAfter DECIMAL(15,2),
            FOREIGN KEY (playerId) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_status (status),
            INDEX idx_requestedAt (requestedAt),
            INDEX idx_playerId (playerId)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

        `CREATE TABLE IF NOT EXISTS payments (
            id INT PRIMARY KEY AUTO_INCREMENT,
            playerId INT,
            playerName VARCHAR(100),
            playerEmail VARCHAR(100),
            amount DECIMAL(15,2),
            currency VARCHAR(10) DEFAULT 'EUR',
            method VARCHAR(50),
            status ENUM('pending', 'approved', 'rejected', 'processing', 'cancelled') DEFAULT 'pending',
            transactionId VARCHAR(100),
            paymentDetails JSON,
            requestedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            processedAt DATETIME,
            processedBy VARCHAR(100),
            processorId INT,
            notes TEXT,
            bonusGiven DECIMAL(15,2) DEFAULT 0,
            playerBalanceBefore DECIMAL(15,2),
            playerBalanceAfter DECIMAL(15,2),
            FOREIGN KEY (playerId) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_status (status),
            INDEX idx_requestedAt (requestedAt),
            INDEX idx_playerId (playerId)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

        `CREATE TABLE IF NOT EXISTS support_tickets (
            id INT PRIMARY KEY AUTO_INCREMENT,
            ticketId VARCHAR(20) UNIQUE,
            playerId INT,
            playerName VARCHAR(100),
            playerEmail VARCHAR(100),
            subject VARCHAR(255),
            category ENUM('deposit', 'withdrawal', 'account', 'technical', 'game', 'bonus', 'other') DEFAULT 'other',
            priority ENUM('low', 'medium', 'high', 'urgent') DEFAULT 'medium',
            status ENUM('open', 'in_progress', 'resolved', 'closed') DEFAULT 'open',
            assignedToStaffId INT,
            assignedToStaffName VARCHAR(100),
            lastMessageAt DATETIME,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            resolvedAt DATETIME,
            closedAt DATETIME,
            FOREIGN KEY (playerId) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (assignedToStaffId) REFERENCES staffs(id) ON DELETE SET NULL,
            INDEX idx_status (status),
            INDEX idx_ticketId (ticketId),
            INDEX idx_createdAt (createdAt)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

        `CREATE TABLE IF NOT EXISTS ticket_messages (
            id INT PRIMARY KEY AUTO_INCREMENT,
            ticketId INT,
            senderType ENUM('player', 'staff'),
            senderId INT,
            senderName VARCHAR(100),
            message TEXT,
            attachments JSON,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            \`read\` BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (ticketId) REFERENCES support_tickets(id) ON DELETE CASCADE,
            INDEX idx_ticketId (ticketId),
            INDEX idx_senderType (senderType),
            INDEX idx_timestamp (timestamp)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

        `CREATE TABLE IF NOT EXISTS alerts (
            id INT PRIMARY KEY AUTO_INCREMENT,
            type ENUM('security', 'fraud', 'withdrawal', 'payment', 'player', 'system', 'warning') DEFAULT 'system',
            severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
            title VARCHAR(255),
            message TEXT,
            playerId INT,
            playerName VARCHAR(100),
            relatedTo VARCHAR(50),
            isResolved BOOLEAN DEFAULT FALSE,
            resolvedBy VARCHAR(100),
            resolvedAt DATETIME,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            metadata JSON,
            INDEX idx_isResolved (isResolved),
            INDEX idx_type (type),
            INDEX idx_severity (severity)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

        `CREATE TABLE IF NOT EXISTS system_logs (
            id INT PRIMARY KEY AUTO_INCREMENT,
            userId INT,
            user JSON,
            action ENUM('login', 'logout', 'create', 'update', 'delete', 'view', 'approve', 'reject', 'system') NOT NULL,
            module ENUM('auth', 'players', 'withdrawals', 'payments', 'staff', 'support', 'settings', 'system', 'email', 'dashboard') NOT NULL,
            message TEXT,
            details TEXT,
            ip VARCHAR(45),
            userAgent TEXT,
            location VARCHAR(100),
            sessionId VARCHAR(100),
            metadata JSON,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            \`read\` BOOLEAN DEFAULT FALSE,
            INDEX idx_userId (userId),
            INDEX idx_action (action),
            INDEX idx_module (module),
            INDEX idx_timestamp (timestamp)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

        `CREATE TABLE IF NOT EXISTS system_settings (
            id INT PRIMARY KEY AUTO_INCREMENT,
            \`key\` VARCHAR(100) UNIQUE,
            value JSON,
            category VARCHAR(50),
            description TEXT,
            updatedBy INT,
            updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_key (\`key\`),
            INDEX idx_category (category)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

        `CREATE TABLE IF NOT EXISTS internal_messages (
            id INT PRIMARY KEY AUTO_INCREMENT,
            senderId INT NOT NULL,
            recipientId INT NOT NULL,
            message TEXT NOT NULL,
            \`read\` BOOLEAN DEFAULT FALSE,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            messageHash VARCHAR(100) UNIQUE,
            FOREIGN KEY (senderId) REFERENCES staffs(id) ON DELETE CASCADE,
            FOREIGN KEY (recipientId) REFERENCES staffs(id) ON DELETE CASCADE,
            INDEX idx_senderId (senderId),
            INDEX idx_recipientId (recipientId),
            INDEX idx_read (\`read\`),
            INDEX idx_messageHash (messageHash)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`
    ];

    for (const tableSql of tables) {
        try {
            await connection.execute(tableSql);
            console.log(`✅ Tabela verificada/criada: ${tableSql.split('IF NOT EXISTS')[1]?.split('(')[0]?.trim()}`);
        } catch (error) {
            console.error(`❌ Erro ao criar tabela:`, error.message);
        }
    }
}

// ==============================
// CONFIGURAÇÃO DE ARMAZENAMENTO DE SESSÕES
// ==============================

const sessionStore = new MySQLStore({
    ...dbConfig,
    clearExpired: true,
    checkExpirationInterval: 900000,
    expiration: 86400000,
    createDatabaseTable: true,
    schema: {
        tableName: 'sessions',
        columnNames: {
            session_id: 'session_id',
            expires: 'expires',
            data: 'data'
        }
    }
});

// ==============================
// CONFIGURAÇÃO DO MULTER (UPLOADS)
// ==============================

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'public', 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, 'profile-' + uniqueSuffix + ext);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
        return cb(null, true);
    } else {
        cb(new Error('Apenas imagens são permitidas (JPG, PNG, GIF)'));
    }
};

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: fileFilter
});

// ==============================
// CONFIGURAÇÃO DO EMAIL
// ==============================

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'seu-email@gmail.com',
        pass: process.env.EMAIL_PASS || 'sua-password'
    }
});

// ==============================
// MIDDLEWARES (ORDEM CORRETA PARA HOSTINGER)
// ==============================

// 1. Helmet com configuração simplificada
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"]
        }
    }
}));

// 2. CORS configurado para Hostinger
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://seusite.com', 'http://localhost:3000'] 
        : 'http://localhost:3000',
    credentials: true
}));

// 3. Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// 4. Session com configuração para Hostinger
app.use(session({
    key: 'velvetwin.sid',
    secret: process.env.SESSION_SECRET || 'velvetwin-admin-secret-2024-' + Math.random().toString(36).substring(7),
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    },
    proxy: true
}));

app.use(flash());

// 5. Static files
app.use(express.static(path.join(__dirname, 'public')));

// 6. Logging
app.use(morgan('dev'));

// 7. View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ==============================
// FUNÇÕES AUXILIARES DO BANCO DE DADOS
// ==============================

async function query(sql, params = []) {
    try {
        const [rows] = await pool.execute(sql, params);
        return rows;
    } catch (error) {
        console.error('Erro na query:', error.message);
        console.error('SQL:', sql);
        console.error('Params:', params);
        throw error;
    }
}

async function execute(sql, params = []) {
    try {
        const [result] = await pool.execute(sql, params);
        return result;
    } catch (error) {
        console.error('Erro na execução:', error.message);
        console.error('SQL:', sql);
        console.error('Params:', params);
        throw error;
    }
}

// ==============================
// FUNÇÕES AUXILIARES
// ==============================

function generateTicketId() {
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    let ticketId = '';
    
    for (let i = 0; i < 3; i++) {
        ticketId += letters.charAt(Math.floor(Math.random() * letters.length));
    }
    
    for (let i = 0; i < 6; i++) {
        ticketId += numbers.charAt(Math.floor(Math.random() * numbers.length));
    }
    
    return ticketId;
}

function getPlayerStatus(lastLogin) {
    if (!lastLogin) return 'offline';
    
    const lastLoginTime = new Date(lastLogin).getTime();
    const now = Date.now();
    const fifteenMinutes = 15 * 60 * 1000;
    
    if ((now - lastLoginTime) < fifteenMinutes) {
        return 'online';
    }
    return 'offline';
}

async function createSystemLog(userId, userData, action, module, message, details = null, req = null) {
    try {
        let ip = '127.0.0.1';
        let userAgent = 'Unknown';
        let location = 'Localhost';
        let sessionId = null;
        
        if (req) {
            ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            userAgent = req.headers['user-agent'] || 'Unknown';
            sessionId = req.sessionID;
        }
        
        const validModules = ['auth', 'players', 'withdrawals', 'payments', 'staff', 'support', 'settings', 'system', 'email', 'dashboard'];
        const logModule = validModules.includes(module) ? module : 'system';
        
        const logData = {
            userId,
            user: JSON.stringify(userData),
            action,
            module: logModule,
            message,
            details,
            ip,
            userAgent,
            location,
            sessionId,
            timestamp: new Date()
        };
        
        const sql = `
            INSERT INTO system_logs 
            (userId, user, action, module, message, details, ip, userAgent, location, sessionId, timestamp, \`read\`)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        await execute(sql, [
            userId,
            logData.user,
            logData.action,
            logData.module,
            logData.message,
            logData.details,
            logData.ip,
            logData.userAgent,
            logData.location,
            logData.sessionId,
            logData.timestamp,
            0
        ]);
        
        return logData;
    } catch (error) {
        console.error('Erro ao criar log:', error.message);
        return null;
    }
}

// ==============================
// WEBSOCKET (CONFIGURAÇÃO SEGURA)
// ==============================

const wss = new WebSocket.Server({ server });
const activeConnections = new Map();

function broadcastNotification(notification) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN && client.subscribed) {
            client.send(JSON.stringify({
                type: 'notification',
                data: notification
            }));
        }
    });
}

wss.on('connection', (ws, req) => {
    console.log('✅ Novo cliente WebSocket conectado');
    
    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            
            if (data.type === 'heartbeat') {
                ws.send(JSON.stringify({ type: 'heartbeat', timestamp: Date.now() }));
            }
            
            if (data.type === 'subscribe_notifications') {
                ws.subscribed = true;
                ws.send(JSON.stringify({
                    type: 'subscription_confirmed',
                    message: 'Inscrito em notificações'
                }));
            }
            
        } catch (error) {
            console.error('Erro ao processar mensagem WebSocket:', error);
        }
    });
    
    ws.on('close', () => {
        console.log('❌ Cliente WebSocket desconectado');
    });
    
    ws.on('error', (error) => {
        console.error('💥 Erro no WebSocket:', error);
    });
});

// ==============================
// MIDDLEWARES DE AUTENTICAÇÃO
// ==============================

const requireAuth = (req, res, next) => {
    if (!req.session) {
        req.flash('error', 'Sessão expirada. Por favor faça login novamente.');
        return res.redirect('/login?error=session_expired');
    }
    
    if (req.session.staff && req.session.staff.loggedIn) {
        return next();
    }
    
    req.flash('error', 'Por favor faça login para acessar esta página.');
    res.redirect('/login');
};

const requirePermission = (...permissions) => {
    return (req, res, next) => {
        if (!req.session || !req.session.staff) {
            req.flash('error', 'Sessão expirada. Por favor faça login novamente.');
            return res.redirect('/login?error=session_expired');
        }
        
        const staff = req.session.staff;
        
        if (staff.role === 'admin') {
            return next();
        }
        
        if (permissions.length === 0) {
            return next();
        }
        
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
                if (err) console.error('Erro ao salvar permissões na sessão:', err);
            });
            
            staff.permissions = staffPermissions;
        }
        
        const hasPermission = permissions.some(permission => 
            staff.permissions.includes(permission)
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

// Middleware para carregar dados do usuário
app.use(async (req, res, next) => {
    if (req.session && req.session.staff) {
        try {
            const staffs = await query(
                'SELECT id, name, email, role, photo, isOnline, lastActive FROM staffs WHERE id = ? AND isActive = 1',
                [req.session.staff.id]
            );
            
            if (staffs && staffs.length > 0) {
                const staffData = staffs[0];
                req.user = staffData;
                res.locals.user = {
                    id: staffData.id,
                    name: staffData.name,
                    email: staffData.email,
                    role: staffData.role,
                    photo: staffData.photo,
                    isOnline: staffData.isOnline || false
                };
                
                await execute(
                    'UPDATE staffs SET lastActive = ? WHERE id = ?',
                    [new Date(), staffData.id]
                );
            }
        } catch (error) {
            console.error('Erro ao carregar staff:', error);
        }
    }
    
    const sessionUser = (req.session && req.session.staff) ? req.session.staff : null;
    res.locals.staff = sessionUser;
    res.locals.currentPath = req.path;
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    next();
});

// ==============================
// ROTA RAIZ (CORRIGIDA)
// ==============================

app.get('/', (req, res) => {
    if (req.session && req.session.staff && req.session.staff.loggedIn) {
        return res.redirect('/dashboard');
    }
    res.redirect('/login');
});

// ==============================
// ROTAS DE TESTE CRÍTICAS
// ==============================

// Health check - ESSENCIAL PARA HOSTINGER
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        service: 'velvetwin-admin',
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        uptime: process.uptime()
    });
});

// Teste de conexão com database
app.get('/test-db', async (req, res) => {
    try {
        const connection = await pool.getConnection();
        const [rows] = await connection.execute('SELECT 1 as result');
        connection.release();
        
        res.json({
            status: 'success',
            message: '✅ Conexão com MySQL bem-sucedida!',
            database: dbConfig.database,
            result: rows
        });
    } catch (error) {
        res.status(500).json({
            status: 'error',
            message: '❌ Erro na conexão MySQL',
            error: error.message
        });
    }
});

// ==============================
// ROTAS DE CONFIDENCIALIDADE
// ==============================

app.post('/api/confidentiality/accept', requireAuth, async (req, res) => {
    try {
        req.session.staff.acceptedConfidentiality = true;
        req.session.staff.confidentialityAcceptedAt = new Date();
        
        await execute(
            'UPDATE staffs SET acceptedConfidentiality = 1, confidentialityAcceptedAt = ? WHERE id = ?',
            [new Date(), req.session.staff.id]
        );
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'update',
            'auth',
            'Termos de confidencialidade aceitos',
            `Aceitos em ${new Date().toISOString()}`,
            req
        );
        
        res.json({ 
            success: true, 
            message: 'Termos aceitos com sucesso!',
            accepted: true,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('💥 Erro ao aceitar termos:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro interno ao processar aceitação' 
        });
    }
});

app.get('/api/confidentiality/status', requireAuth, async (req, res) => {
    try {
        const staffs = await query(
            'SELECT acceptedConfidentiality, confidentialityAcceptedAt FROM staffs WHERE id = ?',
            [req.session.staff.id]
        );
            
        res.json({
            success: true,
            accepted: staffs[0]?.acceptedConfidentiality || false,
            acceptedAt: staffs[0]?.confidentialityAcceptedAt || null
        });
    } catch (error) {
        console.error('Erro ao verificar status:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao verificar status'
        });
    }
});

// ==============================
// ROTAS DE NOTIFICAÇÕES
// ==============================

app.post('/api/notifications/read-all', requireAuth, async (req, res) => {
    try {
        await execute(
            'UPDATE user_notifications SET \`read\` = 1 WHERE userId = ? AND \`read\` = 0',
            [req.session.staff.id]
        );
        
        await execute(
            'UPDATE alerts SET isResolved = 1 WHERE isResolved = 0'
        );
        
        res.json({ 
            success: true, 
            message: 'Todas as notificações foram marcadas como lidas'
        });
    } catch (error) {
        console.error('Erro ao marcar notificações como lidas:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro interno ao marcar notificações como lidas' 
        });
    }
});

app.get('/api/notifications', requireAuth, async (req, res) => {
    try {
        const alerts = await query(
            'SELECT id, title, message, type, severity, createdAt FROM alerts WHERE isResolved = 0 ORDER BY createdAt DESC LIMIT 20'
        );
            
        const userNotifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [req.session.staff.id]
        );
        
        const notifications = [
            ...alerts.map((alert, index) => ({
                id: alert.id.toString(),
                title: alert.title,
                message: alert.message,
                type: alert.severity === 'critical' ? 'danger' : 
                      alert.severity === 'high' ? 'warning' : 'info',
                read: false,
                createdAt: alert.createdAt,
                source: 'system'
            })),
            ...userNotifications.map(notification => ({
                id: notification.id.toString(),
                title: notification.title,
                message: notification.message,
                type: notification.type,
                read: notification.read,
                createdAt: notification.createdAt,
                source: 'user'
            }))
        ].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        
        const unreadCount = userNotifications.filter(n => !n.read).length;
        
        res.json({ 
            success: true, 
            notifications,
            unreadCount: unreadCount
        });
    } catch (error) {
        console.error('Erro ao buscar notificações:', error);
        res.json({ 
            success: false, 
            notifications: [],
            unreadCount: 0
        });
    }
});

// ==============================
// ROTAS DO CHAT INTERNO (SIMPLIFICADAS)
// ==============================

app.get('/api/chat/staff', requireAuth, async (req, res) => {
    try {
        const currentUserId = req.session.staff.id;
        
        const staffMembers = await query(
            `SELECT id, name, email, role, photo, isOnline, lastActive 
             FROM staffs 
             WHERE id != ? AND isActive = 1 
             ORDER BY isOnline DESC, name ASC`,
            [currentUserId]
        );
        
        res.json({
            success: true,
            staffMembers
        });
        
    } catch (error) {
        console.error('Erro ao obter staff:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao carregar membros da equipa'
        });
    }
});

// ==============================
// ROTA DE LOGIN (MANTIDA IGUAL)
// ==============================

app.get('/login', (req, res) => {
    if (req.session && req.session.staff && req.session.staff.loggedIn) {
        return res.redirect('/dashboard');
    }
    
    res.render('login', {
        title: 'Login - VelvetWin Admin',
        error: req.query.error || (req.flash('error') || []).join(', '),
        email: req.query.email || '',
        user: null
    });
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            req.flash('error', 'Email e password são obrigatórios');
            return res.render('login', {
                title: 'Login - VelvetWin Admin',
                error: 'Email e password são obrigatórios',
                email,
                user: null
            });
        }

        const staff = await query(
            'SELECT id, name, email, password, role, department, photo, acceptedConfidentiality, confidentialityAcceptedAt, isActive FROM staffs WHERE email = ? AND isActive = 1',
            [email.trim()]
        );
        
        if (!staff || staff.length === 0) {
            req.flash('error', 'Credenciais inválidas');
            return res.render('login', {
                title: 'Login - VelvetWin Admin',
                error: 'Credenciais inválidas',
                email,
                user: null
            });
        }

        const staffData = staff[0];
        let isValid = false;

        // Verificação de senha
        if (staffData.password) {
            try {
                isValid = await bcrypt.compare(password, staffData.password);
                
                // Fallback para comparação direta se bcrypt falhar
                if (!isValid) {
                    isValid = (password === staffData.password);
                }
            } catch (bcryptError) {
                isValid = (password === staffData.password);
            }
        }
        
        if (!isValid) {
            req.flash('error', 'Credenciais inválidas');
            return res.render('login', {
                title: 'Login - VelvetWin Admin',
                error: 'Credenciais inválidas',
                email,
                user: null
            });
        }

        let permissions = [];
        switch (staffData.role) {
            case 'admin':
                permissions = ['all'];
                break;
            case 'support_manager':
                permissions = ['view_dashboard', 'view_players', 'view_withdrawals', 'view_payments', 'view_support', 'view_staff', 'view_email', 'view_logs', 'view_settings', 'process_withdrawals', 'process_payments', 'assign_tickets', 'send_emails', 'manage_staff', 'manage_settings'];
                break;
            case 'support':
                permissions = ['view_dashboard', 'view_players', 'view_withdrawals', 'view_payments', 'view_support', 'view_email'];
                break;
            case 'finance':
                permissions = ['view_dashboard', 'view_players', 'view_withdrawals', 'view_payments', 'process_withdrawals', 'process_payments'];
                break;
            case 'moderator':
                permissions = ['view_dashboard', 'view_players', 'view_support'];
                break;
            case 'viewer':
                permissions = ['view_dashboard', 'view_players'];
                break;
            default:
                permissions = ['view_dashboard'];
        }

        await execute(
            'UPDATE staffs SET isOnline = 1, lastLogin = ?, lastActive = ? WHERE id = ?',
            [new Date(), new Date(), staffData.id]
        );

        req.session.staff = {
            id: staffData.id,
            name: staffData.name,
            email: staffData.email,
            role: staffData.role || 'support',
            department: staffData.department || 'Staff',
            photo: staffData.photo || null,
            acceptedConfidentiality: staffData.acceptedConfidentiality || false,
            confidentialityAcceptedAt: staffData.confidentialityAcceptedAt || null,
            loggedIn: true,
            loginTime: new Date(),
            permissions: permissions
        };

        req.session.save(async (err) => {
            if (err) {
                req.flash('error', 'Erro ao iniciar sessão');
                return res.render('login', {
                    title: 'Login - VelvetWin Admin',
                    error: 'Erro ao iniciar sessão',
                    email,
                    user: null
                });
            }

            await createSystemLog(
                staffData.id,
                {
                    name: staffData.name,
                    email: staffData.email,
                    role: staffData.role
                },
                'login',
                'auth',
                'Login realizado no sistema',
                null,
                req
            );

            await execute(
                'INSERT INTO user_notifications (userId, title, message, type, \`read\`, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
                [staffData.id, 'Bem-vindo ao VelvetWin Admin!', `Login realizado com sucesso em ${new Date().toLocaleString('pt-PT')}`, 'success', 0, new Date()]
            );

            req.flash('success', `Bem-vindo, ${staffData.name}!`);
            res.redirect('/dashboard');
        });
        
    } catch (error) {
        console.error('💥 Erro no login:', error);
        req.flash('error', 'Erro interno do servidor');
        res.render('login', {
            title: 'Login - VelvetWin Admin',
            error: 'Erro interno do servidor',
            email: req.body.email || '',
            user: null
        });
    }
});

// ==============================
// LOGOUT
// ==============================

app.get('/logout', async (req, res) => {
    const staffName = req.session?.staff?.name || 'Utilizador';
    
    if (req.user) {
        try {
            await execute(
                'UPDATE staffs SET isOnline = 0 WHERE id = ?',
                [req.user.id]
            );
        } catch (error) {
            console.error('Erro ao atualizar status offline:', error);
        }
    }
    
    if (!req.session) {
        return res.render('logout', {
            title: 'Logout - VelvetWin Admin',
            logoutMessage: 'Sessão já terminada',
            redirectTime: 3,
            redirectUrl: '/login'
        });
    }
    
    req.session.destroy((err) => {
        if (err) {
            console.error('❌ Erro no logout:', err);
            return res.render('logout', {
                title: 'Logout - VelvetWin Admin',
                logoutMessage: 'Erro ao terminar sessão',
                redirectTime: 3,
                redirectUrl: '/login'
            });
        }
        
        res.clearCookie('velvetwin.sid');
        
        res.render('logout', {
            title: 'Logout - VelvetWin Admin',
            logoutMessage: `Sessão terminada com sucesso. Adeus, ${staffName}!`,
            redirectTime: 5,
            redirectUrl: '/login',
            homeUrl: '/',
            logoText: 'VELVETWIN',
            systemName: 'Sistema de Gestão Interno'
        });
    });
});

// ==============================
// DASHBOARD (VERSÃO ESTÁVEL)
// ==============================

app.get('/dashboard', requireAuth, async (req, res) => {
    try {
        const totalUsersResult = await query('SELECT COUNT(*) as count FROM users WHERE isActive = 1');
        const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
        const onlineUsersResult = await query(
            'SELECT COUNT(*) as count FROM users WHERE lastLogin >= ? AND isActive = 1',
            [fifteenMinutesAgo]
        );

        const stats = {
            totalPlayers: totalUsersResult[0].count,
            onlinePlayers: onlineUsersResult[0].count,
            pendingWithdrawals: (await query('SELECT COUNT(*) as count FROM withdrawals WHERE status = "pending"'))[0].count,
            pendingPayments: (await query('SELECT COUNT(*) as count FROM payments WHERE status = "pending"'))[0].count,
            openTickets: (await query('SELECT COUNT(*) as count FROM support_tickets WHERE status = "open"'))[0].count,
            unresolvedAlerts: (await query('SELECT COUNT(*) as count FROM alerts WHERE isResolved = 0'))[0].count
        };

        const withdrawalsResult = await query(
            'SELECT SUM(amount) as total FROM withdrawals WHERE status = "pending"'
        );
        
        stats.withdrawalsAmount = withdrawalsResult[0].total || 0;
        stats.playerPercentage = stats.totalPlayers > 0 ? 
            Math.round((stats.onlinePlayers / stats.totalPlayers) * 100) : 0;

        const recentUsers = await query(
            'SELECT id, username, email, firstName, lastName, balance, lastLogin FROM users WHERE isActive = 1 ORDER BY lastLogin DESC LIMIT 5'
        );

        const recentPlayers = recentUsers.map(user => ({
            playerId: user.id,
            name: `${user.firstName || ''} ${user.lastName || ''}`.trim() || user.username,
            email: user.email,
            status: getPlayerStatus(user.lastLogin),
            balance: user.balance || 0,
            lastActivity: user.lastLogin
        }));

        const recentWithdrawals = await query(
            'SELECT playerName, amount, currency, method, requestedAt FROM withdrawals WHERE status = "pending" ORDER BY requestedAt DESC LIMIT 5'
        );

        const recentPayments = await query(
            'SELECT playerName, amount, currency, method, requestedAt FROM payments WHERE status = "pending" ORDER BY requestedAt DESC LIMIT 5'
        );

        const recentTickets = await query(
            'SELECT ticketId, playerName, subject, category, priority, createdAt FROM support_tickets WHERE status = "open" ORDER BY createdAt DESC LIMIT 5'
        );

        const recentAlerts = await query(
            'SELECT title, message, type, severity, createdAt FROM alerts WHERE isResolved = 0 ORDER BY createdAt DESC LIMIT 5'
        );

        const staff = await query(
            'SELECT acceptedConfidentiality, confidentialityAcceptedAt FROM staffs WHERE id = ?',
            [req.session.staff.id]
        );
        
        const acceptedConfidentiality = staff[0]?.acceptedConfidentiality || false;

        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [req.session.staff.id]
        );

        res.render('dashboard', {
            title: 'Dashboard - VelvetWin Admin',
            breadcrumb: 'Dashboard',
            stats,
            recentPlayers,
            recentWithdrawals,
            recentPayments,
            recentTickets,
            recentAlerts,
            user: req.session.staff,
            acceptedConfidentiality: acceptedConfidentiality,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [req.session.staff.id]
                ))[0].count,
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar dashboard:', error);
        req.flash('error', 'Erro ao carregar dashboard');
        
        // Fallback seguro
        res.render('dashboard', {
            title: 'Dashboard - VelvetWin Admin',
            breadcrumb: 'Dashboard',
            stats: {
                totalPlayers: 0,
                onlinePlayers: 0,
                pendingWithdrawals: 0,
                pendingPayments: 0,
                openTickets: 0,
                withdrawalsAmount: 0,
                unresolvedAlerts: 0,
                playerPercentage: 0
            },
            recentPlayers: [],
            recentWithdrawals: [],
            recentPayments: [],
            recentTickets: [],
            recentAlerts: [],
            user: req.session.staff,
            acceptedConfidentiality: false,
            notifications: {
                unreadCount: 0,
                notifications: []
            }
        });
    }
});

// ==============================
// ROTAS PRINCIPAIS (VERSÕES ESTÁVEIS)
// ==============================

// Jogadores (versão simplificada)
app.get('/players', requireAuth, requirePermission('view_players'), async (req, res) => {
    try {
        const players = await query('SELECT id, username, email, balance, lastLogin FROM users LIMIT 50');
        
        res.render('players', {
            title: 'Gestão de Jogadores - VelvetWin',
            breadcrumb: 'Jogadores',
            players: players.map(player => ({
                _id: player.id,
                username: player.username,
                email: player.email,
                balance: player.balance || 0,
                status: getPlayerStatus(player.lastLogin)
            })),
            user: req.session.staff
        });
    } catch (error) {
        console.error('Erro ao carregar jogadores:', error);
        res.render('players', {
            title: 'Gestão de Jogadores - VelvetWin',
            breadcrumb: 'Jogadores',
            players: [],
            user: req.session.staff
        });
    }
});

// Staff
app.get('/staff', requireAuth, requirePermission('view_staff'), async (req, res) => {
    try {
        const staffMembers = await query('SELECT id, name, email, role, isOnline FROM staffs WHERE isActive = 1');
        
        res.render('staff', {
            title: 'Gestão de Staff - VelvetWin',
            breadcrumb: 'Staff',
            staffMembers,
            user: req.session.staff
        });
    } catch (error) {
        console.error('Erro ao carregar staff:', error);
        res.render('staff', {
            title: 'Gestão de Staff - VelvetWin',
            breadcrumb: 'Staff',
            staffMembers: [],
            user: req.session.staff
        });
    }
});

// Suporte
app.get('/support', requireAuth, requirePermission('view_support'), async (req, res) => {
    try {
        const tickets = await query('SELECT ticketId, playerName, subject, status, createdAt FROM support_tickets LIMIT 20');
        
        res.render('suporte', {
            title: 'Suporte Técnico - VelvetWin',
            breadcrumb: 'Suporte',
            tickets,
            user: req.session.staff
        });
    } catch (error) {
        console.error('Erro ao carregar tickets:', error);
        res.render('suporte', {
            title: 'Suporte Técnico - VelvetWin',
            breadcrumb: 'Suporte',
            tickets: [],
            user: req.session.staff
        });
    }
});

// ==============================
// ROTAS DE API BÁSICAS
// ==============================

app.get('/api/dashboard/stats', requireAuth, async (req, res) => {
    try {
        const totalUsersResult = await query('SELECT COUNT(*) as count FROM users WHERE isActive = 1');
        const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
        const onlineUsersResult = await query(
            'SELECT COUNT(*) as count FROM users WHERE lastLogin >= ? AND isActive = 1',
            [fifteenMinutesAgo]
        );

        const stats = {
            totalPlayers: totalUsersResult[0].count,
            onlinePlayers: onlineUsersResult[0].count,
            pendingWithdrawals: (await query('SELECT COUNT(*) as count FROM withdrawals WHERE status = "pending"'))[0].count,
            pendingPayments: (await query('SELECT COUNT(*) as count FROM payments WHERE status = "pending"'))[0].count,
            unresolvedAlerts: (await query('SELECT COUNT(*) as count FROM alerts WHERE isResolved = 0'))[0].count,
            playerPercentage: totalUsersResult[0].count > 0 ? Math.round((onlineUsersResult[0].count / totalUsersResult[0].count) * 100) : 0
        };

        const withdrawalsResult = await query('SELECT SUM(amount) as total FROM withdrawals WHERE status = "pending"');
        stats.withdrawalsAmount = withdrawalsResult[0].total || 0;

        res.json({ success: true, stats });
    } catch (error) {
        console.error('Erro ao buscar stats:', error);
        res.json({ 
            success: false, 
            stats: {
                totalPlayers: 0,
                onlinePlayers: 0,
                pendingWithdrawals: 0,
                pendingPayments: 0,
                unresolvedAlerts: 0,
                withdrawalsAmount: 0,
                playerPercentage: 0
            }
        });
    }
});

// ==============================
// ROTAS DE PERFIL
// ==============================

app.get('/profile', requireAuth, async (req, res) => {
    try {
        const staff = await query(
            'SELECT id, name, email, role, department, photo, acceptedConfidentiality, confidentialityAcceptedAt, lastLogin FROM staffs WHERE id = ?',
            [req.session.staff.id]
        );
        
        if (!staff || staff.length === 0) {
            req.flash('error', 'Utilizador não encontrado');
            return res.redirect('/logout');
        }
        
        const staffData = staff[0];
        
        res.render('profile', {
            title: 'Meu Perfil - VelvetWin',
            breadcrumb: 'Perfil',
            staff: staffData,
            user: req.session.staff
        });
    } catch (error) {
        console.error('Erro ao carregar perfil:', error);
        req.flash('error', 'Erro ao carregar perfil');
        res.redirect('/dashboard');
    }
});

// ==============================
// HANDLERS DE ERRO (CRÍTICOS PARA EVITAR 503)
// ==============================

// 404 Handler
app.use((req, res) => {
    res.status(404).render('error', {
        title: 'Página Não Encontrada - VelvetWin',
        message: 'A página que procura não existe.',
        error: { status: 404 },
        user: req.session?.staff || null
    });
});

// 500 Handler
app.use((err, req, res, next) => {
    console.error('❌ Erro no servidor:', err.message || err);
    
    const errorMessage = process.env.NODE_ENV === 'development' ? 
        (err.message || 'Erro desconhecido') : 
        'Erro interno do servidor';
    
    res.status(500).render('error', {
        title: 'Erro Interno - VelvetWin',
        message: 'Ocorreu um erro no servidor.',
        error: { message: errorMessage },
        user: req.session?.staff || null
    });
});

// ==============================
// INICIAR SERVIDOR (CONFIGURAÇÃO FINAL)
// ==============================

// Garantir que os diretórios existem
const ensureDirectory = (dir) => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`✅ Diretório criado: ${dir}`);
    }
};

ensureDirectory(path.join(__dirname, 'public', 'uploads'));
ensureDirectory(path.join(__dirname, 'views'));

// Criar arquivo de teste se não existir views
const testView = path.join(__dirname, 'views', 'login.ejs');
if (!fs.existsSync(testView)) {
    const basicLogin = `
<!DOCTYPE html>
<html>
<head>
    <title><%= title %></title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 50px; }
        .login-box { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); width: 350px; margin: 0 auto; }
        h2 { text-align: center; color: #333; margin-bottom: 30px; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { width: 100%; padding: 12px; background: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .error { color: red; text-align: center; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔐 VelvetWin Login</h2>
        <% if (error) { %>
            <div class="error"><%= error %></div>
        <% } %>
        <form method="POST">
            <input type="email" name="email" placeholder="Email" value="<%= email %>" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Entrar</button>
        </form>
    </div>
</body>
</html>`;
    fs.writeFileSync(testView, basicLogin);
    console.log('✅ View de login criada automaticamente');
}

server.listen(PORT, '0.0.0.0', () => {
    console.log(`
╔═══════════════════════════════════════════════════╗
║          🎰 VELVETWIN ADMIN ONLINE                ║
╠═══════════════════════════════════════════════════╣
║ ✅ Servidor iniciado na porta: ${PORT}             
║ ✅ URL: http://localhost:${PORT}                   
║ ✅ Database: ${dbConfig.database}                  
║ ✅ Health Check: http://localhost:${PORT}/health   
║ ✅ Teste DB: http://localhost:${PORT}/test-db      
╠═══════════════════════════════════════════════════╣
║ 🔧 ROTAS PRINCIPAIS:                              
║   • Login: http://localhost:${PORT}/login         
║   • Dashboard: http://localhost:${PORT}/dashboard 
║   • Jogadores: http://localhost:${PORT}/players   
║   • Staff: http://localhost:${PORT}/staff         
║   • Suporte: http://localhost:${PORT}/support     
║   • Perfil: http://localhost:${PORT}/profile      
╚═══════════════════════════════════════════════════╝
    `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🔄 Encerrando servidor...');
    server.close(() => {
        console.log('✅ Servidor encerrado com sucesso.');
        pool.end();
        process.exit(0);
    });
});
