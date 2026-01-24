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

app.get('/', (req, res) => {
 res.send('OK from Hostinger');
});
// ==============================
// CONFIGURAÇÃO DO MySQL (phpMyAdmin)
// ==============================

// Decodificar senha se tiver @
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
// MIDDLEWARES
// ==============================

app.use(helmet({ 
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdnjs.cloudflare.com"],
            scriptSrcElem: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "data:"],
            imgSrc: ["'self'", "data:", "https:", "http:", "blob:"],
            connectSrc: ["'self'", "ws://localhost:" + PORT, "http://localhost:" + PORT],
            frameSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameAncestors: ["'self'"]
        },
        reportOnly: false
    }
}));

app.use(cors({ origin: 'http://localhost:' + PORT, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(morgan('dev'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

app.use(session({
    key: 'velvetwin.sid',
    secret: process.env.SESSION_SECRET || 'velvetwin-admin-secret-2024-' + Math.random().toString(36).substring(7),
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    }
}));

app.use(flash());

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
// WEBSOCKET
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
            
            if (data.type === 'subscribe_notifications') {
                ws.subscribed = true;
                ws.send(JSON.stringify({
                    type: 'subscription_confirmed',
                    message: 'Inscrito em notificações'
                }));
            }
            
            if (data.type === 'chat_connect') {
                const userId = data.userId;
                
                wss.clients.forEach(client => {
                    if (client !== ws && client.userId === userId && client.readyState === WebSocket.OPEN) {
                        console.log(`🔌 Fechando conexão duplicada para usuário ${userId}`);
                        client.close();
                    }
                });
                
                ws.userId = userId;
                activeConnections.set(userId, ws);
                
                console.log(`💬 Usuário ${userId} conectado ao chat`);
                
                await execute(
                    'UPDATE staffs SET isOnline = 1, lastActive = ? WHERE id = ?',
                    [new Date(), userId]
                );
                
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN && client.userId && client.userId !== userId) {
                        client.send(JSON.stringify({
                            type: 'staff_online',
                            staffId: userId,
                            timestamp: new Date()
                        }));
                    }
                });
            }
            
            if (data.type === 'chat_message' && ws.userId) {
                const { recipientId, message: msgContent, messageId } = data;
                const messageHash = `${ws.userId}-${recipientId}-${Date.now()}-${msgContent.substring(0, 20).replace(/\s/g, '')}`;
                
                try {
                    const sql = `
                        INSERT INTO internal_messages 
                        (senderId, recipientId, message, \`read\`, timestamp, messageHash)
                        VALUES (?, ?, ?, ?, ?, ?)
                    `;
                    
                    const result = await execute(sql, [
                        ws.userId,
                        recipientId,
                        msgContent,
                        0,
                        new Date(),
                        messageHash
                    ]);
                    
                    wss.clients.forEach(client => {
                        if (client.readyState === WebSocket.OPEN && client.userId == recipientId) {
                            client.send(JSON.stringify({
                                type: 'chat_message',
                                messageId: result.insertId,
                                senderId: ws.userId,
                                message: msgContent,
                                timestamp: new Date(),
                                originalMessageId: messageId
                            }));
                        }
                    });
                    
                    ws.send(JSON.stringify({
                        type: 'chat_sent',
                        messageId: result.insertId,
                        originalMessageId: messageId,
                        timestamp: new Date()
                    }));
                    
                } catch (error) {
                    if (error.code === 'ER_DUP_ENTRY') {
                        console.log('⚠️ Mensagem duplicada ignorada:', messageHash);
                        ws.send(JSON.stringify({
                            type: 'chat_duplicate',
                            originalMessageId: messageId,
                            message: 'Mensagem já foi enviada'
                        }));
                    } else {
                        throw error;
                    }
                }
            }
            
            if (data.type === 'mark_read' && ws.userId) {
                const { senderId } = data;
                
                await execute(
                    'UPDATE internal_messages SET \`read\` = 1 WHERE senderId = ? AND recipientId = ? AND \`read\` = 0',
                    [senderId, ws.userId]
                );
                
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN && client.userId == senderId) {
                        client.send(JSON.stringify({
                            type: 'messages_read',
                            readerId: ws.userId,
                            timestamp: new Date()
                        }));
                    }
                });
            }
            
            if (data.type === 'typing' && ws.userId) {
                const { recipientId, isTyping } = data;
                
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN && client.userId == recipientId) {
                        client.send(JSON.stringify({
                            type: 'typing',
                            senderId: ws.userId,
                            isTyping: isTyping,
                            timestamp: new Date()
                        }));
                    }
                });
            }
            
            if (data.type === 'user_status') {
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN && client.userId) {
                        client.send(JSON.stringify({
                            type: 'user_status',
                            userId: data.userId,
                            status: data.status
                        }));
                    }
                });
            }
        } catch (error) {
            console.error('Erro ao processar mensagem WebSocket:', error);
        }
    });
    
    ws.on('close', async () => {
        if (ws.userId) {
            console.log(`❌ Usuário ${ws.userId} desconectado do chat`);
            activeConnections.delete(ws.userId);
            
            const userStillConnected = Array.from(wss.clients).some(
                client => client.userId == ws.userId && client.readyState === WebSocket.OPEN
            );
            
            if (!userStillConnected) {
                await execute(
                    'UPDATE staffs SET isOnline = 0, lastActive = ? WHERE id = ?',
                    [new Date(), ws.userId]
                );
                
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN && client.userId && client.userId != ws.userId) {
                        client.send(JSON.stringify({
                            type: 'staff_offline',
                            staffId: ws.userId,
                            timestamp: new Date()
                        }));
                    }
                });
            }
        }
    });
    
    ws.on('error', (error) => {
        console.error('💥 Erro no WebSocket:', error);
        if (ws.userId) {
            activeConnections.delete(ws.userId);
        }
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
// ROTA TEMPORÁRIA PARA CORRIGIR SENHAS
// ==============================

app.get('/fix-passwords', async (req, res) => {
    try {
        console.log('🔧 Iniciando correção de senhas...');
        
        const staffs = await query('SELECT id, email, password FROM staffs');
        console.log(`📊 Encontrados ${staffs.length} staffs`);
        
        let updatedCount = 0;
        let alreadyHashed = 0;
        
        for (const staff of staffs) {
            console.log(`📝 Verificando: ${staff.email}`);
            
            const isBcryptHash = staff.password && 
                (staff.password.startsWith('$2b$') || 
                 staff.password.startsWith('$2a$') || 
                 staff.password.startsWith('$2y$'));
            
            if (!isBcryptHash && staff.password) {
                console.log(`🔐 Hashando senha de: ${staff.email}`);
                const salt = await bcrypt.genSalt(10);
                const hashedPassword = await bcrypt.hash(staff.password, salt);
                
                await execute(
                    'UPDATE staffs SET password = ? WHERE id = ?',
                    [hashedPassword, staff.id]
                );
                
                updatedCount++;
                console.log(`✅ Senha atualizada: ${staff.email}`);
            } else if (isBcryptHash) {
                alreadyHashed++;
                console.log(`✓ Senha já hashada: ${staff.email}`);
            } else {
                console.log(`⚠️ Senha vazia para: ${staff.email}`);
            }
        }
        
        console.log('🎯 Correção de senhas concluída!');
        
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Correção de Senhas - VelvetWin</title>
                <style>
                    body { 
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        padding: 40px;
                        background: #f5f5f5;
                    }
                    .container {
                        max-width: 600px;
                        margin: 0 auto;
                        background: white;
                        padding: 30px;
                        border-radius: 10px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                    }
                    .success { 
                        color: #059669;
                        font-size: 24px;
                        margin-bottom: 20px;
                    }
                    .stats {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 15px;
                        margin: 20px 0;
                    }
                    .stat {
                        background: #f8fafc;
                        padding: 15px;
                        border-radius: 6px;
                        text-align: center;
                    }
                    .stat-number {
                        font-size: 28px;
                        font-weight: bold;
                        color: #2563eb;
                    }
                    .stat-label {
                        font-size: 14px;
                        color: #64748b;
                    }
                    .btn {
                        display: inline-block;
                        background: #2563eb;
                        color: white;
                        padding: 12px 24px;
                        text-decoration: none;
                        border-radius: 6px;
                        margin-top: 20px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="success">✅ Correção de Senhas Concluída!</div>
                    <div class="stats">
                        <div class="stat">
                            <div class="stat-number">${staffs.length}</div>
                            <div class="stat-label">Total de Staffs</div>
                        </div>
                        <div class="stat">
                            <div class="stat-number">${updatedCount}</div>
                            <div class="stat-label">Senhas Corrigidas</div>
                        </div>
                        <div class="stat">
                            <div class="stat-number">${alreadyHashed}</div>
                            <div class="stat-label">Já Hashadas</div>
                        </div>
                    </div>
                    <a href="/login" class="btn">Ir para Login</a>
                </div>
            </body>
            </html>
        `);
    } catch (error) {
        console.error('💥 Erro ao corrigir senhas:', error);
        res.status(500).send(`
            <h1>❌ Erro</h1>
            <p>Erro ao corrigir senhas: ${error.message}</p>
        `);
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

app.delete('/api/notifications/clear-all', requireAuth, async (req, res) => {
    try {
        if (req.method !== 'DELETE') {
            return res.status(400).json({
                success: false,
                error: 'Método não permitido. Use DELETE.'
            });
        }
        
        const { confirm } = req.body;
        
        if (confirm !== 'true') {
            return res.status(400).json({
                success: false,
                error: 'Confirmação necessária. Envie confirm: true no corpo da requisição.',
                required: 'confirm: true'
            });
        }
        
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        
        const result = await execute(
            'DELETE FROM user_notifications WHERE userId = ? AND (\`read\` = 1 OR createdAt < ?)',
            [req.session.staff.id, thirtyDaysAgo]
        );
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'delete',
            'system',
            'Notificações limpas',
            `Foram eliminadas ${result.affectedRows} notificações`,
            req
        );
        
        res.json({ 
            success: true, 
            message: `Foram eliminadas ${result.affectedRows} notificações`,
            deletedCount: result.affectedRows
        });
    } catch (error) {
        console.error('Erro ao limpar notificações:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro interno ao limpar notificações' 
        });
    }
});

app.post('/api/notifications/clear-all', requireAuth, async (req, res) => {
    try {
        const { confirm } = req.body;
        
        if (confirm !== 'true') {
            return res.status(400).json({
                success: false,
                error: 'Confirmação necessária. Envie confirm: true no corpo da requisição.',
                required: 'confirm: true'
            });
        }
        
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        
        const result = await execute(
            'DELETE FROM user_notifications WHERE userId = ? AND (\`read\` = 1 OR createdAt < ?)',
            [req.session.staff.id, thirtyDaysAgo]
        );
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'delete',
            'system',
            'Notificações limpas',
            `Foram eliminadas ${result.affectedRows} notificações`,
            req
        );
        
        res.json({ 
            success: true, 
            message: `Foram eliminadas ${result.affectedRows} notificações`,
            deletedCount: result.affectedRows
        });
    } catch (error) {
        console.error('Erro ao limpar notificações:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro interno ao limpar notificações' 
        });
    }
});

app.get('/api/notifications/stats', requireAuth, async (req, res) => {
    try {
        const userId = req.session.staff.id;
        
        const totalResult = await query('SELECT COUNT(*) as count FROM user_notifications WHERE userId = ?', [userId]);
        const unreadResult = await query('SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0', [userId]);
        const readResult = await query('SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 1', [userId]);
        const byTypeResult = await query('SELECT type, COUNT(*) as count, SUM(CASE WHEN \`read\` = 0 THEN 1 ELSE 0 END) as unread FROM user_notifications WHERE userId = ? GROUP BY type ORDER BY count DESC', [userId]);
        const recentResult = await query('SELECT title, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 5', [userId]);
        
        const stats = {
            total: totalResult[0].count,
            unread: unreadResult[0].count,
            read: readResult[0].count,
            byType: byTypeResult,
            recent: recentResult
        };
        
        res.json({ success: true, stats });
    } catch (error) {
        console.error('Erro ao buscar estatísticas de notificações:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro interno ao buscar estatísticas' 
        });
    }
});

app.delete('/api/notifications/:id', requireAuth, async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) {
            return res.status(400).json({
                success: false,
                error: 'ID de notificação inválido'
            });
        }
        
        const result = await execute(
            'DELETE FROM user_notifications WHERE id = ? AND userId = ?',
            [id, req.session.staff.id]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                error: 'Notificação não encontrada ou não pertence ao utilizador'
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Notificação eliminada com sucesso',
            deletedId: id
        });
    } catch (error) {
        console.error('Erro ao eliminar notificação:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro interno ao eliminar notificação' 
        });
    }
});

app.post('/api/notifications/:id/delete', requireAuth, async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) {
            return res.status(400).json({
                success: false,
                error: 'ID de notificação inválido'
            });
        }
        
        const result = await execute(
            'DELETE FROM user_notifications WHERE id = ? AND userId = ?',
            [id, req.session.staff.id]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                error: 'Notificação não encontrada ou não pertence ao utilizador'
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Notificação eliminada com sucesso',
            deletedId: id
        });
    } catch (error) {
        console.error('Erro ao eliminar notificação:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro interno ao eliminar notificação' 
        });
    }
});

// ==============================
// ROTAS DO CHAT INTERNO
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
        
        const staffWithUnread = await Promise.all(
            staffMembers.map(async (staff) => {
                const unreadResult = await query(
                    'SELECT COUNT(*) as count FROM internal_messages WHERE senderId = ? AND recipientId = ? AND \`read\` = 0',
                    [staff.id, currentUserId]
                );
                
                return {
                    ...staff,
                    unreadCount: unreadResult[0].count,
                    lastActiveFormatted: staff.lastActive ? 
                        new Date(staff.lastActive).toLocaleTimeString('pt-PT', {
                            hour: '2-digit',
                            minute: '2-digit'
                        }) : 'Nunca'
                };
            })
        );
        
        res.json({
            success: true,
            staffMembers: staffWithUnread
        });
        
    } catch (error) {
        console.error('Erro ao obter staff:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao carregar membros da equipa'
        });
    }
});

app.get('/api/chat/messages/:staffId', requireAuth, async (req, res) => {
    try {
        const staffId = parseInt(req.params.staffId);
        const currentUserId = req.session.staff.id;
        
        if (isNaN(staffId)) {
            return res.status(400).json({
                success: false,
                error: 'ID inválido'
            });
        }
        
        const staffExists = await query('SELECT id, name FROM staffs WHERE id = ?', [staffId]);
        if (!staffExists || staffExists.length === 0) {
            return res.status(404).json({
                success: false,
                error: 'Membro da equipa não encontrado'
            });
        }
        
        const messages = await query(
            `SELECT m.*, 
                    s1.name as senderName, 
                    s1.photo as senderPhoto,
                    s2.name as recipientName
             FROM internal_messages m
             LEFT JOIN staffs s1 ON m.senderId = s1.id
             LEFT JOIN staffs s2 ON m.recipientId = s2.id
             WHERE (m.senderId = ? AND m.recipientId = ?) 
                OR (m.senderId = ? AND m.recipientId = ?)
             ORDER BY m.timestamp ASC
             LIMIT 100`,
            [currentUserId, staffId, staffId, currentUserId]
        );
        
        await execute(
            'UPDATE internal_messages SET \`read\` = 1 WHERE senderId = ? AND recipientId = ? AND \`read\` = 0',
            [staffId, currentUserId]
        );
        
        res.json({
            success: true,
            messages: messages.map(msg => ({
                _id: msg.id,
                senderId: msg.senderId,
                recipientId: msg.recipientId,
                message: msg.message,
                read: msg.read,
                timestamp: msg.timestamp,
                senderName: msg.senderName,
                senderPhoto: msg.senderPhoto,
                recipientName: msg.recipientName
            }))
        });
        
    } catch (error) {
        console.error('Erro ao obter mensagens:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao carregar mensagens'
        });
    }
});

app.post('/api/chat/send', requireAuth, async (req, res) => {
    try {
        const { recipientId, message, clientMessageId } = req.body;
        const currentUserId = req.session.staff.id;
        
        if (!recipientId || !message || !message.trim()) {
            return res.status(400).json({
                success: false,
                error: 'Destinatário e mensagem são obrigatórios'
            });
        }
        
        const recipientIdNum = parseInt(recipientId);
        if (recipientIdNum === currentUserId) {
            return res.status(400).json({
                success: false,
                error: 'Não pode enviar mensagens para si mesmo'
            });
        }
        
        const recipient = await query('SELECT id, name FROM staffs WHERE id = ?', [recipientIdNum]);
        if (!recipient || recipient.length === 0) {
            return res.status(404).json({
                success: false,
                error: 'Destinatário não encontrado'
            });
        }
        
        const messageHash = `${currentUserId}-${recipientIdNum}-${Date.now()}-${message.substring(0, 20).replace(/\s/g, '')}`;
        
        try {
            const result = await execute(
                'INSERT INTO internal_messages (senderId, recipientId, message, \`read\`, timestamp, messageHash) VALUES (?, ?, ?, ?, ?, ?)',
                [currentUserId, recipientIdNum, message.trim(), 0, new Date(), messageHash]
            );
            
            const populatedMessage = await query(
                `SELECT m.*, 
                        s1.name as senderName, 
                        s1.photo as senderPhoto,
                        s2.name as recipientName
                 FROM internal_messages m
                 LEFT JOIN staffs s1 ON m.senderId = s1.id
                 LEFT JOIN staffs s2 ON m.recipientId = s2.id
                 WHERE m.id = ?`,
                [result.insertId]
            );
            
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN && client.userId == recipientIdNum) {
                    client.send(JSON.stringify({
                        type: 'chat_message',
                        messageId: result.insertId,
                        senderId: currentUserId,
                        senderName: populatedMessage[0].senderName,
                        message: message.trim(),
                        timestamp: new Date(),
                        clientMessageId: clientMessageId
                    }));
                }
            });
            
            await execute(
                'UPDATE staffs SET lastActive = ? WHERE id = ?',
                [new Date(), currentUserId]
            );
            
            res.json({
                success: true,
                message: 'Mensagem enviada com sucesso',
                data: {
                    _id: populatedMessage[0].id,
                    senderId: populatedMessage[0].senderId,
                    recipientId: populatedMessage[0].recipientId,
                    message: populatedMessage[0].message,
                    timestamp: populatedMessage[0].timestamp,
                    senderName: populatedMessage[0].senderName,
                    recipientName: populatedMessage[0].recipientName
                }
            });
            
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') {
                console.log('⚠️ Mensagem duplicada, retornando existente');
                
                const existingMessage = await query('SELECT id FROM internal_messages WHERE messageHash = ?', [messageHash]);
                if (existingMessage && existingMessage.length > 0) {
                    const populatedMessage = await query(
                        `SELECT m.*, 
                                s1.name as senderName, 
                                s1.photo as senderPhoto,
                                s2.name as recipientName
                         FROM internal_messages m
                         LEFT JOIN staffs s1 ON m.senderId = s1.id
                         LEFT JOIN staffs s2 ON m.recipientId = s2.id
                         WHERE m.id = ?`,
                        [existingMessage[0].id]
                    );
                    
                    return res.json({
                        success: true,
                        message: 'Mensagem já enviada anteriormente',
                        data: {
                            _id: populatedMessage[0].id,
                            senderId: populatedMessage[0].senderId,
                            recipientId: populatedMessage[0].recipientId,
                            message: populatedMessage[0].message,
                            timestamp: populatedMessage[0].timestamp,
                            senderName: populatedMessage[0].senderName,
                            recipientName: populatedMessage[0].recipientName
                        }
                    });
                }
            }
            throw error;
        }
        
    } catch (error) {
        console.error('Erro ao enviar mensagem:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao enviar mensagem: ' + error.message
        });
    }
});

app.post('/api/chat/mark-read/:staffId', requireAuth, async (req, res) => {
    try {
        const staffId = parseInt(req.params.staffId);
        const currentUserId = req.session.staff.id;
        
        await execute(
            'UPDATE internal_messages SET \`read\` = 1 WHERE senderId = ? AND recipientId = ? AND \`read\` = 0',
            [staffId, currentUserId]
        );
        
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN && client.userId == staffId) {
                client.send(JSON.stringify({
                    type: 'messages_read',
                    readerId: currentUserId,
                    timestamp: new Date()
                }));
            }
        });
        
        res.json({
            success: true,
            message: 'Mensagens marcadas como lidas'
        });
        
    } catch (error) {
        console.error('Erro ao marcar mensagens como lidas:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao atualizar status das mensagens'
        });
    }
});

app.get('/api/chat/unread-count', requireAuth, async (req, res) => {
    try {
        const currentUserId = req.session.staff.id;
        const result = await query(
            'SELECT COUNT(*) as count FROM internal_messages WHERE recipientId = ? AND \`read\` = 0',
            [currentUserId]
        );
        
        res.json({
            success: true,
            count: result[0].count
        });
        
    } catch (error) {
        console.error('Erro ao contar mensagens não lidas:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao contar mensagens não lidas'
        });
    }
});

app.post('/api/chat/update-status', requireAuth, async (req, res) => {
    try {
        const { isOnline } = req.body;
        const currentUserId = req.session.staff.id;
        
        await execute(
            'UPDATE staffs SET isOnline = ?, lastActive = ? WHERE id = ?',
            [isOnline === true ? 1 : 0, new Date(), currentUserId]
        );
        
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN && client.userId && client.userId != currentUserId) {
                client.send(JSON.stringify({
                    type: 'staff_status',
                    staffId: currentUserId,
                    isOnline: isOnline === true,
                    lastActive: new Date()
                }));
            }
        });
        
        res.json({
            success: true,
            message: 'Status atualizado'
        });
        
    } catch (error) {
        console.error('Erro ao atualizar status:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao atualizar status'
        });
    }
});

app.get('/api/chat/recent-conversations', requireAuth, async (req, res) => {
    try {
        const currentUserId = req.session.staff.id;
        
        const recentConversations = await query(
            `SELECT 
                CASE 
                    WHEN m.senderId = ? THEN m.recipientId
                    ELSE m.senderId
                END as otherStaffId,
                MAX(m.id) as lastMessageId,
                SUM(CASE WHEN m.recipientId = ? AND m.\`read\` = 0 THEN 1 ELSE 0 END) as unreadCount
             FROM internal_messages m
             WHERE m.senderId = ? OR m.recipientId = ?
             GROUP BY otherStaffId
             ORDER BY MAX(m.timestamp) DESC
             LIMIT 10`,
            [currentUserId, currentUserId, currentUserId, currentUserId]
        );
        
        const conversationsWithDetails = await Promise.all(
            recentConversations.map(async (conv) => {
                const staff = await query(
                    'SELECT id, name, role, photo, isOnline, lastActive FROM staffs WHERE id = ?',
                    [conv.otherStaffId]
                );
                
                const lastMessage = await query(
                    'SELECT id, message, timestamp, senderId FROM internal_messages WHERE id = ?',
                    [conv.lastMessageId]
                );
                
                return {
                    _id: conv.otherStaffId,
                    staff: staff[0] || {},
                    lastMessage: lastMessage[0] || {},
                    unreadCount: conv.unreadCount
                };
            })
        );
        
        res.json({
            success: true,
            conversations: conversationsWithDetails
        });
        
    } catch (error) {
        console.error('Erro ao buscar conversas recentes:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao carregar conversas'
        });
    }
});

// ==============================
// ROTA DE LOGIN
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

console.log('🔐 DEBUG LOGIN:');
console.log('Email fornecido:', email);
console.log('Senha fornecida:', password);
console.log('Hash no banco:', staffData.password ? staffData.password.substring(0, 30) + '...' : 'NULL');
console.log('Comprimento hash:', staffData.password ? staffData.password.length : 0);

// Método 1: Primeiro tenta bcrypt
if (staffData.password) {
    try {
        console.log('Tentando bcrypt.compare...');
        isValid = await bcrypt.compare(password, staffData.password);
        console.log('Resultado bcrypt:', isValid);
        
        // Se bcrypt falhar, tenta comparação direta
        if (!isValid) {
            console.log('bcrypt falhou, tentando comparação direta...');
            isValid = (password === staffData.password);
            console.log('Resultado comparação direta:', isValid);
        }
    } catch (bcryptError) {
        console.log('Erro no bcrypt:', bcryptError.message);
        // Fallback para comparação direta
        isValid = (password === staffData.password);
        console.log('Fallback para comparação direta:', isValid);
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

app.get('/logout-simple', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('velvetwin.sid');
        res.redirect('/login?message=logout_success');
    });
});

app.post('/api/auth/logout', (req, res) => {
    try {
        const staffName = req.session?.staff?.name;
        
        req.session.destroy((err) => {
            if (err) {
                console.error('Erro no logout via API:', err);
                return res.status(500).json({ 
                    success: false, 
                    error: 'Erro ao fazer logout' 
                });
            }
            
            res.clearCookie('velvetwin.sid');
            
            res.json({ 
                success: true, 
                message: 'Logout realizado com sucesso',
                redirect: '/login'
            });
        });
    } catch (error) {
        console.error('Erro no logout via API:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro interno no servidor' 
        });
    }
});

// ==============================
// ROTAS DE PERFIL API
// ==============================

app.get('/api/auth/profile', requireAuth, async (req, res) => {
    try {
        if (!req.session.staff) {
            return res.status(401).json({ 
                success: false, 
                error: 'Não autenticado' 
            });
        }
        
        const staff = await query(
            'SELECT id, name, email, role, department, photo, lastLogin, isOnline, lastActive FROM staffs WHERE id = ?',
            [req.session.staff.id]
        );
        
        if (!staff || staff.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Utilizador não encontrado' 
            });
        }
        
        res.json({
            success: true,
            user: {
                id: staff[0].id,
                name: staff[0].name,
                email: staff[0].email,
                role: staff[0].role,
                department: staff[0].department,
                photo: staff[0].photo,
                lastLogin: staff[0].lastLogin,
                isOnline: staff[0].isOnline,
                lastActive: staff[0].lastActive,
                loggedIn: true
            }
        });
    } catch (error) {
        console.error('Erro ao buscar perfil:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro interno do servidor' 
        });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email e password são obrigatórios' 
            });
        }

        const staff = await query(
            'SELECT id, name, email, password, role, department, photo, acceptedConfidentiality, confidentialityAcceptedAt, isActive FROM staffs WHERE email = ? AND isActive = 1',
            [email.trim()]
        );
        
        if (!staff || staff.length === 0) {
            return res.status(401).json({ 
                success: false, 
                error: 'Credenciais inválidas' 
            });
        }

        const staffData = staff[0];
        let isValid = false;
        
        if (staffData.password) {
            try {
                isValid = await bcrypt.compare(password, staffData.password);
            } catch (bcryptError) {
                isValid = (password === staffData.password);
            }
        }
        
        if (!isValid) {
            return res.status(401).json({ 
                success: false, 
                error: 'Credenciais inválidas' 
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
                return res.status(500).json({ 
                    success: false, 
                    error: 'Erro ao iniciar sessão' 
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

            res.json({ 
                success: true, 
                message: `Bem-vindo, ${staffData.name}!`,
                user: {
                    id: staffData.id,
                    name: staffData.name,
                    email: staffData.email,
                    role: staffData.role,
                    photo: staffData.photo,
                    isOnline: true,
                    lastActive: new Date(),
                    loggedIn: true
                },
                redirect: '/dashboard'
            });
        });
        
    } catch (error) {
        console.error('💥 Erro no login via API:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro interno do servidor' 
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
        
        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [staffData.id]
        );
        
        const userLogs = await query(
            'SELECT * FROM system_logs WHERE userId = ? ORDER BY timestamp DESC LIMIT 20',
            [staffData.id]
        );
        
        const userWithPhoto = {
            ...req.session.staff,
            photo: staffData.photo || null
        };
        
        res.render('profile', {
            title: 'Meu Perfil - VelvetWin',
            breadcrumb: 'Perfil',
            staff: staffData,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [staffData.id]
                ))[0].count,
                notifications: notifications
            },
            userLogs,
            user: userWithPhoto
        });
    } catch (error) {
        console.error('Erro ao carregar perfil:', error);
        req.flash('error', 'Erro ao carregar perfil');
        res.redirect('/dashboard');
    }
});

app.post('/profile/update', requireAuth, upload.single('photo'), async (req, res) => {
    try {
        console.log('📤 Recebendo atualização de perfil...');
        
        const { name, username } = req.body;
        
        console.log('📝 Dados recebidos:', { name, username });
        console.log('📁 Ficheiro recebido:', req.file ? req.file.filename : 'Nenhum');
        
        let updateFields = 'name = ?';
        let params = [name || req.session.staff.name];
        
        if (req.file) {
            try {
                const currentStaff = await query(
                    'SELECT photo FROM staffs WHERE id = ?',
                    [req.session.staff.id]
                );
                
                if (currentStaff && currentStaff[0] && currentStaff[0].photo) {
                    const oldPhotoPath = path.join(__dirname, 'public', 'uploads', currentStaff[0].photo);
                    if (fs.existsSync(oldPhotoPath)) {
                        fs.unlinkSync(oldPhotoPath);
                        console.log(`🗑️ Foto antiga removida: ${currentStaff[0].photo}`);
                    }
                }
                
                updateFields += ', photo = ?';
                params.push(req.file.filename);
                
                req.session.staff.photo = req.file.filename;
                
                console.log(`✅ Foto carregada: ${req.file.filename}`);
                
            } catch (fileError) {
                console.error('❌ Erro ao processar foto:', fileError);
                return res.status(500).json({
                    success: false,
                    message: 'Erro ao processar a foto'
                });
            }
        }
        
        await execute(
            `UPDATE staffs SET ${updateFields} WHERE id = ?`,
            [...params, req.session.staff.id]
        );
        
        req.session.staff.name = name || req.session.staff.name;
        req.session.save();
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'update',
            'auth',
            'Perfil atualizado',
            JSON.stringify({
                name: req.session.staff.name,
                photo: req.file ? 'atualizada' : 'mantida'
            }),
            req
        );
        
        console.log(`✅ Perfil atualizado para ${req.session.staff.name}`);
        
        res.json({
            success: true,
            message: 'Perfil atualizado com sucesso!',
            photo: req.session.staff.photo,
            user: {
                name: req.session.staff.name,
                email: req.session.staff.email,
                photo: req.session.staff.photo
            }
        });
        
    } catch (error) {
        console.error('💥 Erro ao atualizar perfil:', error);
        
        res.status(500).json({
            success: false,
            message: error.message || 'Erro ao atualizar perfil',
            error: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// ==============================
// DASHBOARD
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

app.post('/api/notifications/:id/read', requireAuth, async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) {
            return res.status(400).json({
                success: false,
                message: 'ID inválido'
            });
        }
        
        const result = await execute(
            'UPDATE user_notifications SET \`read\` = 1 WHERE id = ? AND userId = ?',
            [id, req.session.staff.id]
        );
        
        if (result.affectedRows > 0) {
            res.json({ success: true, message: 'Notificação marcada como lida' });
        } else {
            res.json({ 
                success: true, 
                message: 'Notificação tratada (alertas do sistema não são marcados como lidos individualmente)' 
            });
        }
    } catch (error) {
        console.error('Erro ao marcar notificação:', error);
        res.json({ success: false, error: 'Erro interno' });
    }
});

app.post('/api/notifications/mark-all-read', requireAuth, async (req, res) => {
    try {
        await execute(
            'UPDATE user_notifications SET \`read\` = 1 WHERE userId = ? AND \`read\` = 0',
            [req.session.staff.id]
        );
        
        res.json({ success: true, message: 'Todas as notificações foram marcadas como lidas' });
    } catch (error) {
        console.error('Erro ao marcar notificações:', error);
        res.json({ success: false, error: 'Erro interno' });
    }
});

app.get('/api/test-notification', requireAuth, async (req, res) => {
    try {
        const result = await execute(
            'INSERT INTO user_notifications (userId, title, message, type, \`read\`, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
            [req.session.staff.id, 'Notificação de Teste', `Esta é uma notificação de teste criada em ${new Date().toLocaleTimeString('pt-PT')}`, 'info', 0, new Date()]
        );
        
        const notification = {
            id: result.insertId.toString(),
            title: 'Notificação de Teste',
            message: `Esta é uma notificação de teste criada em ${new Date().toLocaleTimeString('pt-PT')}`,
            type: 'info',
            createdAt: new Date()
        };
        
        broadcastNotification(notification);
        
        res.json({ 
            success: true, 
            message: 'Notificação de teste criada e enviada',
            notification 
        });
    } catch (error) {
        console.error('Erro ao criar notificação de teste:', error);
        res.json({ success: false, error: 'Erro interno' });
    }
});

// ==============================
// ROTAS DE JOGADORES
// ==============================

app.get('/players', requireAuth, requirePermission('view_players'), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;
        const status = req.query.status || 'all';
        const search = req.query.search || '';
        const sort = req.query.sort || 'lastLogin';
        const order = req.query.order === 'asc' ? 'ASC' : 'DESC';

        let whereClause = 'WHERE isActive = 1';
        let params = [];
        
        if (status === 'online') {
            const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
            whereClause += ' AND lastLogin >= ?';
            params.push(fifteenMinutesAgo);
        } else if (status === 'offline') {
            const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
            whereClause += ' AND (lastLogin < ? OR lastLogin IS NULL)';
            params.push(fifteenMinutesAgo);
        } else if (status === 'active') {
            whereClause += ' AND isActive = 1';
        } else if (status === 'inactive') {
            whereClause += ' AND isActive = 0';
        }

        if (search) {
            whereClause += ' AND (username LIKE ? OR email LIKE ? OR firstName LIKE ? OR lastName LIKE ?)';
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm, searchTerm);
        }

        const users = await query(
            `SELECT id, username, email, firstName, lastName, balance, \`level\`, country, lastLogin, createdAt, isActive, totalWagered, totalWins, gamesPlayed, newsletter, kycStatus 
             FROM users 
             ${whereClause} 
             ORDER BY ${sort} ${order} 
             LIMIT ? OFFSET ?`,
            [...params, limit, offset]
        );

        const totalUsersResult = await query(`SELECT COUNT(*) as count FROM users ${whereClause}`, params);
        const totalUsers = totalUsersResult[0].count;
        const totalPages = Math.ceil(totalUsers / limit);

        const players = users.map(user => {
            const status = getPlayerStatus(user.lastLogin);
            
            return {
                _id: user.id,
                username: user.username,
                email: user.email,
                name: `${user.firstName || ''} ${user.lastName || ''}`.trim() || user.username,
                balance: user.balance || 0,
                level: user.level || 'Bronze',
                country: user.country || 'N/A',
                status: status,
                statusClass: status === 'online' ? 'online' : 'offline',
                lastLogin: user.lastLogin ? new Date(user.lastLogin).toLocaleString('pt-PT') : 'Nunca',
                registered: new Date(user.createdAt).toLocaleDateString('pt-PT'),
                isActive: user.isActive,
                gamesPlayed: user.gamesPlayed || 0,
                totalWagered: user.totalWagered || 0,
                totalWins: user.totalWins || 0,
                newsletter: user.newsletter || false,
                kycStatus: user.kycStatus || 'pending'
            };
        });

        const stats = {
            total: totalUsers,
            online: (await query(
                'SELECT COUNT(*) as count FROM users WHERE lastLogin >= ? AND isActive = 1',
                [new Date(Date.now() - 15 * 60 * 1000)]
            ))[0].count,
            active: (await query('SELECT COUNT(*) as count FROM users WHERE isActive = 1'))[0].count,
            withNewsletter: (await query('SELECT COUNT(*) as count FROM users WHERE newsletter = 1'))[0].count,
            kycVerified: (await query('SELECT COUNT(*) as count FROM users WHERE kycStatus = "verified"'))[0].count
        };

        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [req.session.staff.id]
        );

        res.render('players', {
            title: 'Gestão de Jogadores - VelvetWin',
            breadcrumb: 'Jogadores',
            players,
            stats,
            currentPage: page,
            totalPages,
            limit,
            status,
            search,
            sort,
            order,
            user: req.session.staff,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [req.session.staff.id]
                ))[0].count,
                notifications: notifications
            }
        });
        
    } catch (error) {
        console.error('Erro ao carregar jogadores:', error);
        req.flash('error', 'Erro ao carregar jogadores');
        
        res.render('players', {
            title: 'Gestão de Jogadores - VelvetWin',
            breadcrumb: 'Jogadores',
            players: [],
            stats: { total: 0, online: 0, active: 0, withNewsletter: 0, kycVerified: 0 },
            currentPage: 1,
            totalPages: 1,
            limit: 20,
            status: 'all',
            search: '',
            user: req.session.staff,
            notifications: {
                unreadCount: 0,
                notifications: []
            }
        });
    }
});

app.get('/player/:id', requireAuth, requirePermission('view_players'), async (req, res) => {
    try {
        const playerId = parseInt(req.params.id);
        if (isNaN(playerId)) {
            req.flash('error', 'ID de jogador inválido');
            return res.status(404).render('error', {
                title: 'Jogador não encontrado',
                message: 'O jogador não existe ou foi removido.',
                user: req.session.staff
            });
        }
        
        const player = await query(
            'SELECT * FROM users WHERE id = ?',
            [playerId]
        );
        
        if (!player || player.length === 0) {
            req.flash('error', 'Jogador não encontrado');
            return res.status(404).render('error', {
                title: 'Jogador não encontrado',
                message: 'O jogador não existe ou foi removido.',
                user: req.session.staff
            });
        }

        const playerData = player[0];

        const deposits = await query(
            'SELECT * FROM payments WHERE playerId = ? ORDER BY requestedAt DESC LIMIT 10',
            [playerId]
        );

        const withdrawals = await query(
            'SELECT * FROM withdrawals WHERE playerId = ? ORDER BY requestedAt DESC LIMIT 10',
            [playerId]
        );

        const tickets = await query(
            'SELECT * FROM support_tickets WHERE playerId = ? ORDER BY createdAt DESC LIMIT 10',
            [playerId]
        );

        const totalDepositsResult = await query(
            'SELECT SUM(amount) as total FROM payments WHERE playerId = ? AND status = "approved"',
            [playerId]
        );

        const totalWithdrawalsResult = await query(
            'SELECT SUM(amount) as total FROM withdrawals WHERE playerId = ? AND status = "approved"',
            [playerId]
        );

        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [req.session.staff.id]
        );

        res.render('player-details', {
            title: `Detalhes do Jogador - ${playerData.username}`,
            breadcrumb: 'Jogadores / Detalhes',
            player: playerData,
            deposits,
            withdrawals,
            tickets,
            stats: {
                totalDeposits: totalDepositsResult[0].total || 0,
                totalWithdrawals: totalWithdrawalsResult[0].total || 0,
                netProfit: (totalDepositsResult[0].total || 0) - (totalWithdrawalsResult[0].total || 0)
            },
            user: req.session.staff,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [req.session.staff.id]
                ))[0].count,
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar detalhes do jogador:', error);
        req.flash('error', 'Erro ao carregar detalhes do jogador');
        res.status(500).render('error', {
            title: 'Erro',
            message: 'Erro ao carregar detalhes do jogador',
            user: req.session.staff
        });
    }
});

app.post('/api/players/:id/update', requireAuth, requirePermission('view_players'), async (req, res) => {
    try {
        const playerId = parseInt(req.params.id);
        if (isNaN(playerId)) {
            return res.status(400).json({ success: false, error: 'ID de jogador inválido' });
        }
        
        const { balance, isActive, kycStatus, notes } = req.body;
        
        const updateData = {};
        if (balance !== undefined) updateData.balance = parseFloat(balance);
        if (isActive !== undefined) updateData.isActive = isActive === 'true' ? 1 : 0;
        if (kycStatus !== undefined) updateData.kycStatus = kycStatus;
        
        const setClause = Object.keys(updateData).map(key => `${key} = ?`).join(', ');
        const values = Object.values(updateData);
        
        if (setClause) {
            await execute(
                `UPDATE users SET ${setClause} WHERE id = ?`,
                [...values, playerId]
            );
        }
        
        const player = await query('SELECT * FROM users WHERE id = ?', [playerId]);
        
        if (!player || player.length === 0) {
            return res.status(404).json({ success: false, error: 'Jogador não encontrado' });
        }
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'update',
            'players',
            `Jogador atualizado: ${player[0].username}`,
            JSON.stringify(updateData),
            req
        );
        
        res.json({ success: true, player: player[0] });
    } catch (error) {
        console.error('Erro ao atualizar jogador:', error);
        res.status(500).json({ success: false, error: 'Erro ao atualizar jogador' });
    }
});

// ==============================
// ROTAS DE LEVANTAMENTOS
// ==============================

app.get('/withdrawals', requireAuth, requirePermission('view_withdrawals'), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;
        const status = req.query.status || 'all';
        const method = req.query.method || 'all';
        const search = req.query.search || '';
        const sort = req.query.sort || 'requestedAt';
        const order = req.query.order === 'asc' ? 'ASC' : 'DESC';

        let whereClause = '';
        let params = [];
        
        if (status !== 'all') {
            whereClause += ' AND status = ?';
            params.push(status);
        }
        
        if (method !== 'all') {
            whereClause += ' AND method = ?';
            params.push(method);
        }
        
        if (search) {
            whereClause += ' AND (playerName LIKE ? OR playerEmail LIKE ? OR transactionId LIKE ?)';
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm);
        }
        
        const where = whereClause ? `WHERE 1=1 ${whereClause}` : '';

        const withdrawals = await query(
            `SELECT w.*, 
                    u.username as playerUsername, 
                    u.firstName as playerFirstName,
                    u.lastName as playerLastName
             FROM withdrawals w
             LEFT JOIN users u ON w.playerId = u.id
             ${where}
             ORDER BY ${sort} ${order} 
             LIMIT ? OFFSET ?`,
            [...params, limit, offset]
        );

        const totalWithdrawalsResult = await query(`SELECT COUNT(*) as count FROM withdrawals ${where}`, params);
        const totalWithdrawals = totalWithdrawalsResult[0].count;
        const totalPages = Math.ceil(totalWithdrawals / limit);

        const stats = {
            total: totalWithdrawals,
            pending: (await query('SELECT COUNT(*) as count FROM withdrawals WHERE status = "pending"'))[0].count,
            approved: (await query('SELECT COUNT(*) as count FROM withdrawals WHERE status = "approved"'))[0].count,
            rejected: (await query('SELECT COUNT(*) as count FROM withdrawals WHERE status = "rejected"'))[0].count,
            processing: (await query('SELECT COUNT(*) as count FROM withdrawals WHERE status = "processing"'))[0].count
        };

        const pendingTotalResult = await query('SELECT SUM(amount) as total FROM withdrawals WHERE status = "pending"');
        const approvedTotalResult = await query('SELECT SUM(amount) as total FROM withdrawals WHERE status = "approved"');

        stats.pendingAmount = pendingTotalResult[0].total || 0;
        stats.approvedAmount = approvedTotalResult[0].total || 0;

        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [req.session.staff.id]
        );

        res.render('withdrawals', {
            title: 'Gestão de Levantamentos - VelvetWin',
            breadcrumb: 'Levantamentos',
            withdrawals,
            stats,
            currentPage: page,
            totalPages,
            limit,
            status,
            method,
            search,
            sort,
            order,
            user: req.session.staff,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [req.session.staff.id]
                ))[0].count,
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar levantamentos:', error);
        req.flash('error', 'Erro ao carregar levantamentos');
        
        res.render('withdrawals', {
            title: 'Gestão de Levantamentos - VelvetWin',
            breadcrumb: 'Levantamentos',
            withdrawals: [],
            stats: {
                total: 0,
                pending: 0,
                approved: 0,
                rejected: 0,
                processing: 0,
                pendingAmount: 0,
                approvedAmount: 0
            },
            currentPage: 1,
            totalPages: 1,
            limit: 20,
            status: 'all',
            method: 'all',
            search: '',
            sort: 'requestedAt',
            order: 'desc',
            user: req.session.staff,
            notifications: {
                unreadCount: 0,
                notifications: []
            }
        });
    }
});

app.get('/withdrawal/:id', requireAuth, requirePermission('view_withdrawals'), async (req, res) => {
    try {
        const withdrawalId = parseInt(req.params.id);
        if (isNaN(withdrawalId)) {
            req.flash('error', 'ID de levantamento inválido');
            return res.status(404).render('error', {
                title: 'Levantamento não encontrado',
                message: 'O levantamento não existe ou foi removido.',
                user: req.session.staff
            });
        }
        
        const withdrawal = await query(
            `SELECT w.*, 
                    u.username, 
                    u.email, 
                    u.firstName, 
                    u.lastName, 
                    u.balance
             FROM withdrawals w
             LEFT JOIN users u ON w.playerId = u.id
             WHERE w.id = ?`,
            [withdrawalId]
        );
        
        if (!withdrawal || withdrawal.length === 0) {
            req.flash('error', 'Levantamento não encontrado');
            return res.status(404).render('error', {
                title: 'Levantamento não encontrado',
                message: 'O levantamento não existe ou foi removido.',
                user: req.session.staff
            });
        }

        const withdrawalData = withdrawal[0];

        const logs = await query(
            `SELECT * FROM system_logs 
             WHERE metadata LIKE ? OR details LIKE ?
             ORDER BY timestamp DESC LIMIT 20`,
            [`%${withdrawalId}%`, `%${withdrawalId}%`]
        );

        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [req.session.staff.id]
        );

        res.render('withdrawal-details', {
            title: `Levantamento #${withdrawalData.id.toString().slice(-6)}`,
            breadcrumb: 'Levantamentos / Detalhes',
            withdrawal: withdrawalData,
            logs,
            user: req.session.staff,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [req.session.staff.id]
                ))[0].count,
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar detalhes do levantamento:', error);
        req.flash('error', 'Erro ao carregar detalhes do levantamento');
        res.status(500).render('error', {
            title: 'Erro',
            message: 'Erro ao carregar detalhes do levantamento',
            user: req.session.staff
        });
    }
});

app.post('/api/withdrawals/:id/process', requireAuth, requirePermission('process_withdrawals'), async (req, res) => {
    try {
        const withdrawalId = parseInt(req.params.id);
        if (isNaN(withdrawalId)) {
            return res.status(400).json({ success: false, error: 'ID de levantamento inválido' });
        }
        
        const { action, notes } = req.body;
        const withdrawalResult = await query('SELECT * FROM withdrawals WHERE id = ?', [withdrawalId]);
        
        if (!withdrawalResult || withdrawalResult.length === 0) {
            return res.status(404).json({ success: false, error: 'Levantamento não encontrado' });
        }
        
        const withdrawal = withdrawalResult[0];
        
        if (!['approved', 'rejected', 'processing'].includes(action)) {
            return res.status(400).json({ success: false, error: 'Ação inválida' });
        }
        
        const playerResult = await query('SELECT * FROM users WHERE id = ?', [withdrawal.playerId]);
        
        if (!playerResult || playerResult.length === 0) {
            return res.status(404).json({ success: false, error: 'Jogador não encontrado' });
        }
        
        const player = playerResult[0];
        const playerBalanceBefore = player.balance;
        
        if (action === 'approved') {
            if (player.balance < withdrawal.amount) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Saldo insuficiente do jogador' 
                });
            }
            
            await execute(
                'UPDATE users SET balance = balance - ? WHERE id = ?',
                [withdrawal.amount, player.id]
            );
            
            const updatedPlayer = await query('SELECT balance FROM users WHERE id = ?', [player.id]);
            withdrawal.playerBalanceBefore = playerBalanceBefore;
            withdrawal.playerBalanceAfter = updatedPlayer[0].balance;
        }
        
        await execute(
            'UPDATE withdrawals SET status = ?, processedAt = ?, processedBy = ?, processorId = ?, notes = ?, playerBalanceBefore = ?, playerBalanceAfter = ? WHERE id = ?',
            [action, new Date(), req.session.staff.name, req.session.staff.id, notes || withdrawal.notes, 
             withdrawal.playerBalanceBefore, withdrawal.playerBalanceAfter, withdrawalId]
        );
        
        await execute(
            'INSERT INTO alerts (type, severity, title, message, playerId, playerName, relatedTo, isResolved, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            ['withdrawal', action === 'rejected' ? 'medium' : 'low', 
             `Levantamento ${action === 'approved' ? 'Aprovado' : 'Rejeitado'}`, 
             `Levantamento de €${withdrawal.amount} ${action === 'approved' ? 'aprovado' : 'rejeitado'} para ${withdrawal.playerName}`,
             withdrawal.playerId, withdrawal.playerName, withdrawalId, 0, new Date()]
        );
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            action === 'approved' ? 'approve' : 'reject',
            'withdrawals',
            `Levantamento ${action === 'approved' ? 'aprovado' : 'rejeitado'}: €${withdrawal.amount} - ${withdrawal.playerName}`,
            JSON.stringify({
                withdrawalId: withdrawalId,
                amount: withdrawal.amount,
                playerBalanceBefore,
                playerBalanceAfter: withdrawal.playerBalanceAfter,
                notes
            }),
            req
        );
        
        res.json({ 
            success: true, 
            message: `Levantamento ${action === 'approved' ? 'aprovado' : 'rejeitado'} com sucesso`,
            withdrawal: { ...withdrawal, status: action }
        });
    } catch (error) {
        console.error('Erro ao processar levantamento:', error);
        res.status(500).json({ success: false, error: 'Erro ao processar levantamento' });
    }
});

// ==============================
// ROTAS DE PAGAMENTOS
// ==============================

app.get('/payments', requireAuth, requirePermission('view_payments'), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;
        const status = req.query.status || 'all';
        const method = req.query.method || 'all';
        const search = req.query.search || '';
        const sort = req.query.sort || 'requestedAt';
        const order = req.query.order === 'asc' ? 'ASC' : 'DESC';

        let whereClause = '';
        let params = [];
        
        if (status !== 'all') {
            whereClause += ' AND status = ?';
            params.push(status);
        }
        
        if (method !== 'all') {
            whereClause += ' AND method = ?';
            params.push(method);
        }
        
        if (search) {
            whereClause += ' AND (playerName LIKE ? OR playerEmail LIKE ? OR transactionId LIKE ?)';
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm);
        }
        
        const where = whereClause ? `WHERE 1=1 ${whereClause}` : '';

        const payments = await query(
            `SELECT p.*, 
                    u.username as playerUsername, 
                    u.firstName as playerFirstName,
                    u.lastName as playerLastName
             FROM payments p
             LEFT JOIN users u ON p.playerId = u.id
             ${where}
             ORDER BY ${sort} ${order} 
             LIMIT ? OFFSET ?`,
            [...params, limit, offset]
        );

        const totalPaymentsResult = await query(`SELECT COUNT(*) as count FROM payments ${where}`, params);
        const totalPayments = totalPaymentsResult[0].count;
        const totalPages = Math.ceil(totalPayments / limit);

        const stats = {
            total: totalPayments,
            pending: (await query('SELECT COUNT(*) as count FROM payments WHERE status = "pending"'))[0].count,
            approved: (await query('SELECT COUNT(*) as count FROM payments WHERE status = "approved"'))[0].count,
            rejected: (await query('SELECT COUNT(*) as count FROM payments WHERE status = "rejected"'))[0].count,
            processing: (await query('SELECT COUNT(*) as count FROM payments WHERE status = "processing"'))[0].count
        };

        const pendingTotalResult = await query('SELECT SUM(amount) as total FROM payments WHERE status = "pending"');
        const approvedTotalResult = await query('SELECT SUM(amount) as total FROM payments WHERE status = "approved"');

        stats.pendingAmount = pendingTotalResult[0].total || 0;
        stats.approvedAmount = approvedTotalResult[0].total || 0;

        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [req.session.staff.id]
        );

        res.render('payments', {
            title: 'Gestão de Pagamentos - VelvetWin',
            breadcrumb: 'Pagamentos',
            payments,
            stats,
            currentPage: page,
            totalPages,
            limit,
            status,
            method,
            search,
            sort,
            order,
            user: req.session.staff,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [req.session.staff.id]
                ))[0].count,
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar pagamentos:', error);
        req.flash('error', 'Erro ao carregar pagamentos');
        
        res.render('payments', {
            title: 'Gestão de Pagamentos - VelvetWin',
            breadcrumb: 'Pagamentos',
            payments: [],
            stats: {
                total: 0,
                pending: 0,
                approved: 0,
                rejected: 0,
                processing: 0,
                pendingAmount: 0,
                approvedAmount: 0
            },
            currentPage: 1,
            totalPages: 1,
            limit: 20,
            status: 'all',
            method: 'all',
            search: '',
            sort: 'requestedAt',
            order: 'desc',
            user: req.session.staff,
            notifications: {
                unreadCount: 0,
                notifications: []
            }
        });
    }
});

app.get('/payment/:id', requireAuth, requirePermission('view_payments'), async (req, res) => {
    try {
        const paymentId = parseInt(req.params.id);
        if (isNaN(paymentId)) {
            req.flash('error', 'ID de pagamento inválido');
            return res.status(404).render('error', {
                title: 'Pagamento não encontrado',
                message: 'O pagamento não existe ou foi removido.',
                user: req.session.staff
            });
        }
        
        const payment = await query(
            `SELECT p.*, 
                    u.username, 
                    u.email, 
                    u.firstName, 
                    u.lastName, 
                    u.balance,
                    u.bonusBalance
             FROM payments p
             LEFT JOIN users u ON p.playerId = u.id
             WHERE p.id = ?`,
            [paymentId]
        );
        
        if (!payment || payment.length === 0) {
            req.flash('error', 'Pagamento não encontrado');
            return res.status(404).render('error', {
                title: 'Pagamento não encontrado',
                message: 'O pagamento não existe ou foi removido.',
                user: req.session.staff
            });
        }

        const paymentData = payment[0];

        const logs = await query(
            `SELECT * FROM system_logs 
             WHERE metadata LIKE ? OR details LIKE ?
             ORDER BY timestamp DESC LIMIT 20`,
            [`%${paymentId}%`, `%${paymentId}%`]
        );

        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [req.session.staff.id]
        );

        res.render('payment-details', {
            title: `Pagamento #${paymentData.id.toString().slice(-6)}`,
            breadcrumb: 'Pagamentos / Detalhes',
            payment: paymentData,
            logs,
            user: req.session.staff,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [req.session.staff.id]
                ))[0].count,
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar detalhes do pagamento:', error);
        req.flash('error', 'Erro ao carregar detalhes do pagamento');
        res.status(500).render('error', {
            title: 'Erro',
            message: 'Erro ao carregar detalhes do pagamento',
            user: req.session.staff
        });
    }
});

app.post('/api/payments/:id/process', requireAuth, requirePermission('process_payments'), async (req, res) => {
    try {
        const paymentId = parseInt(req.params.id);
        if (isNaN(paymentId)) {
            return res.status(400).json({ success: false, error: 'ID de pagamento inválido' });
        }
        
        const { action, notes, bonusAmount } = req.body;
        const paymentResult = await query('SELECT * FROM payments WHERE id = ?', [paymentId]);
        
        if (!paymentResult || paymentResult.length === 0) {
            return res.status(404).json({ success: false, error: 'Pagamento não encontrado' });
        }
        
        const payment = paymentResult[0];
        
        if (!['approved', 'rejected', 'processing'].includes(action)) {
            return res.status(400).json({ success: false, error: 'Ação inválida' });
        }
        
        const playerResult = await query('SELECT * FROM users WHERE id = ?', [payment.playerId]);
        
        if (!playerResult || playerResult.length === 0) {
            return res.status(404).json({ success: false, error: 'Jogador não encontrado' });
        }
        
        const player = playerResult[0];
        const playerBalanceBefore = player.balance;
        
        if (action === 'approved') {
            await execute(
                'UPDATE users SET balance = balance + ? WHERE id = ?',
                [payment.amount, player.id]
            );
            
            const bonus = parseFloat(bonusAmount) || 0;
            if (bonus > 0) {
                await execute(
                    'UPDATE users SET bonusBalance = bonusBalance + ? WHERE id = ?',
                    [bonus, player.id]
                );
                payment.bonusGiven = bonus;
            }
            
            const updatedPlayer = await query('SELECT balance, bonusBalance FROM users WHERE id = ?', [player.id]);
            payment.playerBalanceBefore = playerBalanceBefore;
            payment.playerBalanceAfter = updatedPlayer[0].balance;
        }
        
        await execute(
            'UPDATE payments SET status = ?, processedAt = ?, processedBy = ?, processorId = ?, notes = ?, bonusGiven = ?, playerBalanceBefore = ?, playerBalanceAfter = ? WHERE id = ?',
            [action, new Date(), req.session.staff.name, req.session.staff.id, notes || payment.notes, 
             payment.bonusGiven, payment.playerBalanceBefore, payment.playerBalanceAfter, paymentId]
        );
        
        await execute(
            'INSERT INTO alerts (type, severity, title, message, playerId, playerName, relatedTo, isResolved, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            ['payment', 'low', 
             `Pagamento ${action === 'approved' ? 'Aprovado' : 'Rejeitado'}`, 
             `Pagamento de €${payment.amount} ${action === 'approved' ? 'aprovado' : 'rejeitado'} para ${payment.playerName}`,
             payment.playerId, payment.playerName, paymentId, 0, new Date()]
        );
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            action === 'approved' ? 'approve' : 'reject',
            'payments',
            `Pagamento ${action === 'approved' ? 'aprovado' : 'rejeitado'}: €${payment.amount} - ${payment.playerName}`,
            JSON.stringify({
                paymentId: paymentId,
                amount: payment.amount,
                bonus: bonusAmount || 0,
                playerBalanceBefore,
                playerBalanceAfter: payment.playerBalanceAfter,
                notes
            }),
            req
        );
        
        res.json({ 
            success: true, 
            message: `Pagamento ${action === 'approved' ? 'aprovado' : 'rejeitado'} com sucesso`,
            payment: { ...payment, status: action, bonusGiven: payment.bonusGiven }
        });
    } catch (error) {
        console.error('Erro ao processar pagamento:', error);
        res.status(500).json({ success: false, error: 'Erro ao processar pagamento' });
    }
});

// ==============================
// ROTAS DE STAFF
// ==============================

app.get('/staff', requireAuth, requirePermission('view_staff'), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;
        const role = req.query.role || 'all';
        const status = req.query.status || 'all';
        const search = req.query.search || '';
        const sort = req.query.sort || 'name';
        const order = req.query.order === 'asc' ? 'ASC' : 'DESC';

        let whereClause = 'WHERE isActive = 1';
        let params = [];
        
        if (role !== 'all') {
            whereClause += ' AND role = ?';
            params.push(role);
        }
        
        if (status !== 'all') {
            whereClause += ' AND isActive = ?';
            params.push(status === 'active' ? 1 : 0);
        }
        
        if (search) {
            whereClause += ' AND (name LIKE ? OR email LIKE ? OR department LIKE ?)';
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm);
        }

        const staffMembers = await query(
            `SELECT id, name, email, role, department, photo, isActive, isOnline, lastActive, lastLogin, createdAt 
             FROM staffs 
             ${whereClause} 
             ORDER BY ${sort} ${order} 
             LIMIT ? OFFSET ?`,
            [...params, limit, offset]
        );

        const totalStaffResult = await query(`SELECT COUNT(*) as count FROM staffs ${whereClause}`, params);
        const totalStaff = totalStaffResult[0].count;
        const totalPages = Math.ceil(totalStaff / limit);

        const stats = {
            total: totalStaff,
            active: (await query('SELECT COUNT(*) as count FROM staffs WHERE isActive = 1'))[0].count,
            admins: (await query('SELECT COUNT(*) as count FROM staffs WHERE role = "admin"'))[0].count,
            support: (await query('SELECT COUNT(*) as count FROM staffs WHERE role IN ("support", "support_manager")'))[0].count,
            finance: (await query('SELECT COUNT(*) as count FROM staffs WHERE role = "finance"'))[0].count,
            moderator: (await query('SELECT COUNT(*) as count FROM staffs WHERE role = "moderator"'))[0].count,
            viewer: (await query('SELECT COUNT(*) as count FROM staffs WHERE role = "viewer"'))[0].count
        };

        const roleOptions = [
            { value: 'admin', label: 'Administrador' },
            { value: 'support_manager', label: 'Gestor de Suporte' },
            { value: 'support', label: 'Suporte' },
            { value: 'finance', label: 'Financeiro' },
            { value: 'moderator', label: 'Moderador' },
            { value: 'viewer', label: 'Visualizador' }
        ];

        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [req.session.staff.id]
        );

        res.render('staff', {
            title: 'Gestão de Staff - VelvetWin',
            breadcrumb: 'Staff',
            staffMembers,
            stats,
            roleOptions,
            currentPage: page,
            totalPages,
            limit,
            role,
            status: status || 'all',
            search,
            sort,
            order,
            user: req.session.staff,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [req.session.staff.id]
                ))[0].count,
                notifications: notifications
            },
            staff: req.session.staff,
            total: totalStaff,
            currentPage: page,
            totalPages: totalPages,
            acceptedConfidentiality: req.session.staff.acceptedConfidentiality || false
        });
    } catch (error) {
        console.error('Erro ao carregar staff:', error);
        req.flash('error', 'Erro ao carregar staff');
        
        res.render('staff', {
            title: 'Gestão de Staff - VelvetWin',
            breadcrumb: 'Staff',
            staffMembers: [],
            stats: { total: 0, active: 0, admins: 0, support: 0, finance: 0, moderator: 0, viewer: 0 },
            roleOptions: [],
            currentPage: 1,
            totalPages: 1,
            limit: 20,
            role: 'all',
            status: 'all',
            search: '',
            user: req.session.staff,
            notifications: {
                unreadCount: 0,
                notifications: []
            },
            staff: req.session.staff,
            total: 0,
            currentPage: 1,
            totalPages: 1,
            acceptedConfidentiality: false
        });
    }
});

app.get('/staff/:id', requireAuth, requirePermission('view_staff'), async (req, res) => {
    try {
        const staffId = parseInt(req.params.id);
        if (isNaN(staffId)) {
            req.flash('error', 'ID de staff inválido');
            return res.status(404).render('error', {
                title: 'Staff não encontrado',
                message: 'O membro da equipe não existe ou foi removido.',
                user: req.session.staff
            });
        }
        
        const staffMember = await query(
            'SELECT id, name, email, role, department, photo, isActive, isOnline, lastActive, lastLogin, createdAt, acceptedConfidentiality, confidentialityAcceptedAt FROM staffs WHERE id = ?',
            [staffId]
        );
        
        if (!staffMember || staffMember.length === 0) {
            req.flash('error', 'Membro da equipe não encontrado');
            return res.status(404).render('error', {
                title: 'Staff não encontrado',
                message: 'O membro da equipe não existe ou foi removido.',
                user: req.session.staff
            });
        }

        const staffData = staffMember[0];

        const staffLogs = await query(
            'SELECT * FROM system_logs WHERE userId = ? ORDER BY timestamp DESC LIMIT 20',
            [staffId]
        );

        const assignedTicketsResult = await query(
            'SELECT COUNT(*) as count FROM support_tickets WHERE assignedToStaffId = ?',
            [staffId]
        );

        const processedWithdrawalsResult = await query(
            'SELECT COUNT(*) as count FROM withdrawals WHERE processorId = ?',
            [staffId]
        );

        const processedPaymentsResult = await query(
            'SELECT COUNT(*) as count FROM payments WHERE processorId = ?',
            [staffId]
        );

        const stats = {
            assignedTickets: assignedTicketsResult[0].count,
            processedWithdrawals: processedWithdrawalsResult[0].count,
            processedPayments: processedPaymentsResult[0].count,
            totalActivities: staffLogs.length
        };

        const roleOptions = [
            { value: 'admin', label: 'Administrador' },
            { value: 'support_manager', label: 'Gestor de Suporte' },
            { value: 'support', label: 'Suporte' },
            { value: 'finance', label: 'Financeiro' },
            { value: 'moderator', label: 'Moderador' },
            { value: 'viewer', label: 'Visualizador' }
        ];

        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [req.session.staff.id]
        );

        res.render('staff-details', {
            title: `Detalhes do Staff - ${staffData.name}`,
            breadcrumb: 'Staff / Detalhes',
            staffMember: staffData,
            staffLogs,
            stats,
            roleOptions,
            user: req.session.staff,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [req.session.staff.id]
                ))[0].count,
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar detalhes do staff:', error);
        req.flash('error', 'Erro ao carregar detalhes do staff');
        res.status(500).render('error', {
            title: 'Erro',
            message: 'Erro ao carregar detalhes do staff',
            user: req.session.staff
        });
    }
});

app.post('/api/staff/create', requireAuth, requirePermission('manage_staff'), async (req, res) => {
    try {
        const { name, email, role, department, password } = req.body;
        
        if (!name || !email || !role || !password) {
            return res.status(400).json({ success: false, error: 'Dados incompletos' });
        }
        
        const existingStaff = await query(
            'SELECT id FROM staffs WHERE email = ?',
            [email.trim()]
        );
        
        if (existingStaff && existingStaff.length > 0) {
            return res.status(400).json({ success: false, error: 'Email já está em uso' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await execute(
            'INSERT INTO staffs (name, email, role, department, password, isActive, isOnline, lastActive) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [name, email, role, department || 'Staff', hashedPassword, 1, 0, new Date()]
        );
        
        const newStaff = await query(
            'SELECT id, name, email, role, department, photo, isActive, isOnline, lastActive, createdAt FROM staffs WHERE id = ?',
            [result.insertId]
        );
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'create',
            'staff',
            `Novo staff criado: ${name} (${role})`,
            JSON.stringify({ name, email, role, department }),
            req
        );
        
        res.json({ 
            success: true, 
            message: 'Staff criado com sucesso!',
            staff: newStaff[0]
        });
    } catch (error) {
        console.error('Erro ao criar staff:', error);
        res.status(500).json({ success: false, error: 'Erro ao criar staff' });
    }
});

app.post('/api/staff/:id/update', requireAuth, requirePermission('manage_staff'), async (req, res) => {
    try {
        const staffId = parseInt(req.params.id);
        const { name, email, role, department, isActive, isOnline } = req.body;
        
        if (isNaN(staffId)) {
            return res.status(400).json({ success: false, error: 'ID de staff inválido' });
        }
        
        const staffResult = await query('SELECT * FROM staffs WHERE id = ?', [staffId]);
        
        if (!staffResult || staffResult.length === 0) {
            return res.status(404).json({ success: false, error: 'Staff não encontrado' });
        }
        
        const staff = staffResult[0];
        
        if (email && email !== staff.email) {
            const existingStaff = await query(
                'SELECT id FROM staffs WHERE email = ? AND id != ?',
                [email.trim(), staffId]
            );
            
            if (existingStaff && existingStaff.length > 0) {
                return res.status(400).json({ success: false, error: 'Email já está em uso' });
            }
        }
        
        const updateData = {};
        if (name !== undefined) updateData.name = name;
        if (email !== undefined) updateData.email = email;
        if (role !== undefined) updateData.role = role;
        if (department !== undefined) updateData.department = department;
        if (isActive !== undefined) updateData.isActive = isActive === 'true' ? 1 : 0;
        if (isOnline !== undefined) {
            updateData.isOnline = isOnline === 'true' ? 1 : 0;
            if (isOnline === 'true') {
                updateData.lastActive = new Date();
            }
        }
        
        const setClause = Object.keys(updateData).map(key => `${key} = ?`).join(', ');
        const values = Object.values(updateData);
        
        if (setClause) {
            await execute(
                `UPDATE staffs SET ${setClause} WHERE id = ?`,
                [...values, staffId]
            );
        }
        
        const updatedStaff = await query(
            'SELECT id, name, email, role, department, photo, isActive, isOnline, lastActive, lastLogin, createdAt FROM staffs WHERE id = ?',
            [staffId]
        );
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'update',
            'staff',
            `Staff atualizado: ${updatedStaff[0].name}`,
            JSON.stringify(updateData),
            req
        );
        
        res.json({ 
            success: true, 
            message: 'Staff atualizado com sucesso!',
            staff: updatedStaff[0]
        });
    } catch (error) {
        console.error('Erro ao atualizar staff:', error);
        res.status(500).json({ success: false, error: 'Erro ao atualizar staff' });
    }
});

app.post('/api/staff/:id/delete', requireAuth, requirePermission('manage_staff'), async (req, res) => {
    try {
        const staffId = parseInt(req.params.id);
        
        if (isNaN(staffId)) {
            return res.status(400).json({ success: false, error: 'ID de staff inválido' });
        }
        
        if (staffId === req.session.staff.id) {
            return res.status(400).json({ 
                success: false, 
                error: 'Não pode eliminar a sua própria conta' 
            });
        }
        
        const staffResult = await query('SELECT * FROM staffs WHERE id = ?', [staffId]);
        
        if (!staffResult || staffResult.length === 0) {
            return res.status(404).json({ success: false, error: 'Staff não encontrado' });
        }
        
        const staff = staffResult[0];
        
        await execute(
            'UPDATE staffs SET isActive = 0, isOnline = 0 WHERE id = ?',
            [staffId]
        );
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'delete',
            'staff',
            `Staff desativado: ${staff.name}`,
            null,
            req
        );
        
        res.json({ 
            success: true, 
            message: 'Staff desativado com sucesso!'
        });
    } catch (error) {
        console.error('Erro ao eliminar staff:', error);
        res.status(500).json({ success: false, error: 'Erro ao eliminar staff' });
    }
});

app.delete('/api/staff/:id/permanent', requireAuth, requirePermission('manage_staff'), async (req, res) => {
    try {
        const staffId = parseInt(req.params.id);
        
        if (isNaN(staffId)) {
            return res.status(400).json({ 
                success: false, 
                error: 'ID de staff inválido' 
            });
        }
        
        if (staffId === req.session.staff.id) {
            return res.status(400).json({ 
                success: false, 
                error: 'Não pode eliminar a sua própria conta' 
            });
        }
        
        const staffResult = await query('SELECT * FROM staffs WHERE id = ?', [staffId]);
        
        if (!staffResult || staffResult.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Staff não encontrado' 
            });
        }
        
        const staff = staffResult[0];
        const staffName = staff.name;
        const staffEmail = staff.email;
        
        await execute('DELETE FROM staffs WHERE id = ?', [staffId]);
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'delete',
            'staff',
            `Staff eliminado permanentemente: ${staffName}`,
            JSON.stringify({
                staffId: staffId,
                name: staffName,
                email: staffEmail,
                eliminatedAt: new Date().toISOString()
            }),
            req
        );
        
        await execute(
            'INSERT INTO alerts (type, severity, title, message, metadata, isResolved, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)',
            ['security', 'high', 'Staff Eliminado Permanentemente', 
             `Staff ${staffName} foi eliminado permanentemente do sistema por ${req.session.staff.name}`,
             JSON.stringify({
                staffId: staffId,
                staffName: staffName,
                eliminatedBy: req.session.staff.name,
                eliminatedAt: new Date().toISOString()
             }),
             0, new Date()]
        );
        
        res.json({ 
            success: true, 
            message: 'Staff eliminado permanentemente com sucesso!',
            details: {
                name: staffName,
                email: staffEmail,
                eliminatedAt: new Date().toISOString()
            }
        });
        
    } catch (error) {
        console.error('Erro ao eliminar staff permanentemente:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro interno ao eliminar staff' 
        });
    }
});

// ==============================
// ROTAS DE SUPORTE
// ==============================

app.get('/support', requireAuth, requirePermission('view_support'), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;
        
        const status = req.query.status || 'all';
        const priority = req.query.priority || 'all';
        const category = req.query.category || 'all';
        const search = req.query.search || '';
        
        let whereClause = '';
        let params = [];
        
        if (status !== 'all') {
            whereClause += ' AND status = ?';
            params.push(status === 'in-progress' ? 'in_progress' : status);
        }
        
        if (priority !== 'all') {
            whereClause += ' AND priority = ?';
            params.push(priority);
        }
        
        if (category !== 'all') {
            whereClause += ' AND category = ?';
            params.push(category);
        }
        
        if (search) {
            whereClause += ' AND (ticketId LIKE ? OR playerName LIKE ? OR playerEmail LIKE ? OR subject LIKE ?)';
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm, searchTerm);
        }
        
        const where = whereClause ? `WHERE 1=1 ${whereClause}` : '';

        const tickets = await query(
            `SELECT t.*, 
                    u.username as playerUsername, 
                    u.email as playerEmail,
                    s.name as assignedStaffName
             FROM support_tickets t
             LEFT JOIN users u ON t.playerId = u.id
             LEFT JOIN staffs s ON t.assignedToStaffId = s.id
             ${where}
             ORDER BY t.createdAt DESC 
             LIMIT ? OFFSET ?`,
            [...params, limit, offset]
        );

        const totalTicketsResult = await query(`SELECT COUNT(*) as count FROM support_tickets ${where}`, params);
        const totalTickets = totalTicketsResult[0].count;
        const totalPages = Math.ceil(totalTickets / limit);

        const stats = {
            total: (await query('SELECT COUNT(*) as count FROM support_tickets'))[0].count,
            open: (await query('SELECT COUNT(*) as count FROM support_tickets WHERE status = "open"'))[0].count,
            inProgress: (await query('SELECT COUNT(*) as count FROM support_tickets WHERE status = "in_progress"'))[0].count,
            assigned: (await query('SELECT COUNT(*) as count FROM support_tickets WHERE assignedToStaffId IS NOT NULL'))[0].count,
            resolved: (await query('SELECT COUNT(*) as count FROM support_tickets WHERE status = "resolved"'))[0].count
        };

        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [req.session.staff.id]
        );

        res.render('suporte', {
            title: 'Suporte Técnico - VelvetWin',
            breadcrumb: 'Suporte',
            tickets,
            stats,
            currentPage: page,
            totalPages,
            limit,
            status: req.query.status || 'all',
            priority: req.query.priority || 'all',
            category: req.query.category || 'all',
            search: req.query.search || '',
            user: req.session.staff,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [req.session.staff.id]
                ))[0].count,
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar tickets de suporte:', error);
        req.flash('error', 'Erro ao carregar tickets de suporte');
        
        res.render('suporte', {
            title: 'Suporte Técnico - VelvetWin',
            breadcrumb: 'Suporte',
            tickets: [],
            stats: {
                total: 0,
                open: 0,
                inProgress: 0,
                assigned: 0,
                resolved: 0
            },
            currentPage: 1,
            totalPages: 1,
            limit: 20,
            status: 'all',
            priority: 'all',
            category: 'all',
            search: '',
            user: req.session.staff,
            notifications: {
                unreadCount: 0,
                notifications: []
            }
        });
    }
});

// ==============================
// API ROUTES PARA SUPORTE (AJAX)
// ==============================

app.get('/api/tickets/:id', requireAuth, async (req, res) => {
    try {
        const ticketId = parseInt(req.params.id);
        
        if (isNaN(ticketId)) {
            return res.status(400).json({ 
                success: false, 
                error: 'ID de ticket inválido' 
            });
        }
        
        const ticket = await query(
            `SELECT t.*, 
                    u.username, 
                    u.email, 
                    u.firstName, 
                    u.lastName,
                    s.name as assignedStaffName
             FROM support_tickets t
             LEFT JOIN users u ON t.playerId = u.id
             LEFT JOIN staffs s ON t.assignedToStaffId = s.id
             WHERE t.id = ?`,
            [ticketId]
        );
        
        if (!ticket || ticket.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Ticket não encontrado' 
            });
        }
        
        const ticketData = ticket[0];
        const messages = await query(
            'SELECT * FROM ticket_messages WHERE ticketId = ? ORDER BY timestamp ASC',
            [ticketId]
        );
        
        res.json({
            success: true,
            ticket: {
                id: ticketData.id,
                ticketId: ticketData.ticketId,
                subject: ticketData.subject,
                email: ticketData.playerEmail || ticketData.email || '',
                category: ticketData.category,
                priority: ticketData.priority === 'urgent' ? 'Urgente' : 
                         ticketData.priority === 'high' ? 'Alta' :
                         ticketData.priority === 'medium' ? 'Média' : 'Baixa',
                status: ticketData.status === 'in_progress' ? 'Em Progresso' : 
                        ticketData.status === 'resolved' ? 'Resolvido' : 
                        ticketData.status === 'closed' ? 'Fechado' : 'Aberto',
                createdAt: new Date(ticketData.createdAt).toLocaleString('pt-PT'),
                updatedAt: new Date(ticketData.lastMessageAt || ticketData.createdAt).toLocaleString('pt-PT'),
                message: messages && messages.length > 0 ? messages[0].message : 'Sem mensagem',
                responses: messages ? messages.filter(m => m.senderType === 'staff').map(m => ({
                    sender: m.senderName || 'Suporte',
                    message: m.message,
                    time: new Date(m.timestamp).toLocaleTimeString('pt-PT', {hour: '2-digit', minute:'2-digit'}),
                    date: new Date(m.timestamp).toLocaleDateString('pt-PT')
                })) : [],
                assignedTo: ticketData.assignedStaffName || 'Não atribuído'
            }
        });
    } catch (error) {
        console.error('Erro ao buscar detalhes do ticket:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro interno do servidor' 
        });
    }
});

app.post('/api/tickets/create', requireAuth, async (req, res) => {
    try {
        const { subject, customerEmail, category, priority, message, createdBy } = req.body;
        
        if (!subject || !customerEmail || !message) {
            return res.status(400).json({ 
                success: false, 
                error: 'Assunto, email e mensagem são obrigatórios' 
            });
        }
        
        const ticketId = generateTicketId();
        
        const user = await query('SELECT id, username, firstName, lastName FROM users WHERE email = ?', [customerEmail]);
        
        const result = await execute(
            'INSERT INTO support_tickets (ticketId, playerId, playerName, playerEmail, subject, category, priority, status, assignedToStaffId, lastMessageAt, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [ticketId, 
             user && user.length > 0 ? user[0].id : null,
             user && user.length > 0 ? `${user[0].firstName || ''} ${user[0].lastName || ''}`.trim() || user[0].username : 'Cliente',
             customerEmail,
             subject,
             category || 'other',
             priority || 'medium',
             'open',
             null,
             new Date(),
             new Date()]
        );
        
        const ticketInsertId = result.insertId;
        
        await execute(
            'INSERT INTO ticket_messages (ticketId, senderType, senderId, senderName, message, timestamp, \`read\`) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [ticketInsertId, 'staff', req.session.staff.id, createdBy || req.session.staff.name, message, new Date(), 0]
        );
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'create',
            'support',
            `Ticket criado: ${subject}`,
            `Ticket #${ticketId} criado para ${customerEmail}`,
            req
        );
        
        await execute(
            'INSERT INTO alerts (type, severity, title, message, relatedTo, metadata, isResolved, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            ['system', 'medium', 'Novo Ticket Criado', 
             `Ticket #${ticketId} criado por ${createdBy || req.session.staff.name}`,
             ticketInsertId,
             JSON.stringify({
                ticketId: ticketId,
                createdBy: createdBy || req.session.staff.name
             }),
             0, new Date()]
        );
        
        res.json({
            success: true,
            message: 'Ticket criado com sucesso!',
            ticketId: ticketId
        });
    } catch (error) {
        console.error('Erro ao criar ticket:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro ao criar ticket: ' + error.message 
        });
    }
});

app.post('/api/tickets/:id/assign', requireAuth, async (req, res) => {
    try {
        const ticketId = parseInt(req.params.id);
        const { assignedTo, message, assignedBy } = req.body;
        
        if (isNaN(ticketId)) {
            return res.status(400).json({ 
                success: false, 
                error: 'ID de ticket inválido' 
            });
        }
        
        if (!assignedTo) {
            return res.status(400).json({ 
                success: false, 
                error: 'Destinatário é obrigatório' 
            });
        }
        
        const ticketResult = await query('SELECT * FROM support_tickets WHERE id = ?', [ticketId]);
        
        if (!ticketResult || ticketResult.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Ticket não encontrado' 
            });
        }
        
        const ticket = ticketResult[0];
        let staffMember = null;
        
        if (assignedTo === req.session.staff.name) {
            staffMember = await query('SELECT id, name FROM staffs WHERE id = ?', [req.session.staff.id]);
        } else {
            staffMember = await query('SELECT id, name FROM staffs WHERE name LIKE ?', [`%${assignedTo}%`]);
        }
        
        const staffId = staffMember && staffMember.length > 0 ? staffMember[0].id : null;
        const staffName = staffMember && staffMember.length > 0 ? staffMember[0].name : assignedTo;
        
        await execute(
            'UPDATE support_tickets SET assignedToStaffId = ?, assignedToStaffName = ?, status = CASE WHEN status = "open" THEN "in_progress" ELSE status END WHERE id = ?',
            [staffId, staffName, ticketId]
        );
        
        if (message) {
            await execute(
                'INSERT INTO ticket_messages (ticketId, senderType, senderId, senderName, message, timestamp, \`read\`) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [ticketId, 'staff', req.session.staff.id, assignedBy || req.session.staff.name, 
                 `Ticket atribuído a ${staffName}. ${message}`, new Date(), 0]
            );
        }
        
        await execute(
            'UPDATE support_tickets SET lastMessageAt = ? WHERE id = ?',
            [new Date(), ticketId]
        );
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'update',
            'support',
            `Ticket #${ticket.ticketId} atribuído a ${staffName}`,
            message || 'Sem mensagem adicional',
            req
        );
        
        res.json({
            success: true,
            message: `Ticket atribuído a ${staffName} com sucesso!`
        });
    } catch (error) {
        console.error('Erro ao atribuir ticket:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro ao atribuir ticket' 
        });
    }
});

app.post('/api/tickets/:id/escalate', requireAuth, async (req, res) => {
    try {
        const ticketId = parseInt(req.params.id);
        const { escalateTo, reason, description, escalatedBy } = req.body;
        
        if (isNaN(ticketId)) {
            return res.status(400).json({ 
                success: false, 
                error: 'ID de ticket inválido' 
            });
        }
        
        if (!escalateTo || !reason) {
            return res.status(400).json({ 
                success: false, 
                error: 'Departamento e motivo são obrigatórios' 
            });
        }
        
        const ticketResult = await query('SELECT * FROM support_tickets WHERE id = ?', [ticketId]);
        
        if (!ticketResult || ticketResult.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Ticket não encontrado' 
            });
        }
        
        const ticket = ticketResult[0];
        
        await execute(
            'UPDATE support_tickets SET priority = "urgent" WHERE id = ?',
            [ticketId]
        );
        
        const escalateMessage = `Ticket escalonado para ${escalateTo}. Motivo: ${reason}. ${description ? `Descrição: ${description}` : ''}`;
        
        await execute(
            'INSERT INTO ticket_messages (ticketId, senderType, senderId, senderName, message, timestamp, \`read\`) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [ticketId, 'staff', req.session.staff.id, escalatedBy || req.session.staff.name, escalateMessage, new Date(), 0]
        );
        
        await execute(
            'UPDATE support_tickets SET lastMessageAt = ? WHERE id = ?',
            [new Date(), ticketId]
        );
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'update',
            'support',
            `Ticket #${ticket.ticketId} escalonado para ${escalateTo}`,
            `Motivo: ${reason}`,
            req
        );
        
        await execute(
            'INSERT INTO alerts (type, severity, title, message, relatedTo, metadata, isResolved, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            ['system', 'high', 'Ticket Escalonado', 
             `Ticket #${ticket.ticketId} escalonado para ${escalateTo} por ${escalatedBy || req.session.staff.name}`,
             ticketId,
             JSON.stringify({
                ticketId: ticket.ticketId,
                escalatedTo: escalateTo,
                reason: reason
             }),
             0, new Date()]
        );
        
        res.json({
            success: true,
            message: `Ticket escalonado para ${escalateTo} com sucesso!`
        });
    } catch (error) {
        console.error('Erro ao escalonar ticket:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro ao escalonar ticket' 
        });
    }
});

app.post('/api/tickets/:id/close', requireAuth, async (req, res) => {
    try {
        const ticketId = parseInt(req.params.id);
        const { closedBy, closedAt } = req.body;
        
        if (isNaN(ticketId)) {
            return res.status(400).json({ 
                success: false, 
                error: 'ID de ticket inválido' 
            });
        }
        
        const ticketResult = await query('SELECT * FROM support_tickets WHERE id = ?', [ticketId]);
        
        if (!ticketResult || ticketResult.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Ticket não encontrado' 
            });
        }
        
        const ticket = ticketResult[0];
        
        await execute(
            'UPDATE support_tickets SET status = "closed", closedAt = ? WHERE id = ?',
            [closedAt ? new Date(closedAt) : new Date(), ticketId]
        );
        
        await execute(
            'INSERT INTO ticket_messages (ticketId, senderType, senderId, senderName, message, timestamp, \`read\`) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [ticketId, 'staff', req.session.staff.id, closedBy || req.session.staff.name, 'Ticket fechado pelo suporte.', new Date(), 0]
        );
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'update',
            'support',
            `Ticket #${ticket.ticketId} fechado`,
            `Fechado por ${closedBy || req.session.staff.name}`,
            req
        );
        
        res.json({
            success: true,
            message: 'Ticket fechado com sucesso!'
        });
    } catch (error) {
        console.error('Erro ao fechar ticket:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro ao fechar ticket' 
        });
    }
});

app.post('/api/tickets/:id/respond', requireAuth, async (req, res) => {
    try {
        const ticketId = parseInt(req.params.id);
        const { message, status, respondedBy } = req.body;
        
        if (isNaN(ticketId)) {
            return res.status(400).json({ 
                success: false, 
                error: 'ID de ticket inválido' 
            });
        }
        
        if (!message) {
            return res.status(400).json({ 
                success: false, 
                error: 'Mensagem é obrigatória' 
            });
        }
        
        const ticketResult = await query('SELECT * FROM support_tickets WHERE id = ?', [ticketId]);
        
        if (!ticketResult || ticketResult.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Ticket não encontrado' 
            });
        }
        
        const ticket = ticketResult[0];
        
        await execute(
            'INSERT INTO ticket_messages (ticketId, senderType, senderId, senderName, message, timestamp, \`read\`) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [ticketId, 'staff', req.session.staff.id, respondedBy || req.session.staff.name, message, new Date(), 0]
        );
        
        if (status) {
            const newStatus = status === 'in-progress' ? 'in_progress' : 
                            status === 'resolved' ? 'resolved' : 
                            status === 'open' ? 'open' : ticket.status;
            
            let resolvedAt = ticket.resolvedAt;
            if (status === 'resolved') {
                resolvedAt = new Date();
            }
            
            await execute(
                'UPDATE support_tickets SET status = ?, resolvedAt = ? WHERE id = ?',
                [newStatus, resolvedAt, ticketId]
            );
        }
        
        if (!ticket.assignedToStaffId) {
            await execute(
                'UPDATE support_tickets SET assignedToStaffId = ?, assignedToStaffName = ? WHERE id = ?',
                [req.session.staff.id, respondedBy || req.session.staff.name, ticketId]
            );
        }
        
        await execute(
            'UPDATE support_tickets SET lastMessageAt = ? WHERE id = ?',
            [new Date(), ticketId]
        );
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'update',
            'support',
            `Resposta enviada para ticket #${ticket.ticketId}`,
            `Status atualizado para: ${status || 'mantido'}`,
            req
        );
        
        res.json({
            success: true,
            message: 'Resposta enviada com sucesso!'
        });
    } catch (error) {
        console.error('Erro ao responder ao ticket:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro ao responder ao ticket' 
        });
    }
});

// ==============================
// ROTAS DE EMAIL/CHAT
// ==============================

app.get('/email', requireAuth, requirePermission('view_email'), async (req, res) => {
    try {
        const currentUserId = req.session.staff.id;
        
        const staffMembers = await query(
            `SELECT id, name, email, role, photo, isOnline, lastActive 
             FROM staffs 
             WHERE id != ? AND isActive = 1 
             ORDER BY isOnline DESC, name ASC`,
            [currentUserId]
        );
        
        const unreadInternalCountResult = await query(
            'SELECT COUNT(*) as count FROM internal_messages WHERE recipientId = ? AND \`read\` = 0',
            [currentUserId]
        );
        
        const unreadInternalCount = unreadInternalCountResult[0].count;

        const emailLogs = await query(
            'SELECT * FROM email_logs ORDER BY sentAt DESC LIMIT 10'
        );

        const totalPlayersResult = await query('SELECT COUNT(*) as count FROM users WHERE isActive = 1');
        const playersWithEmailResult = await query('SELECT COUNT(*) as count FROM users WHERE isActive = 1 AND email IS NOT NULL AND email != ""');
        const newsletterSubscribersResult = await query('SELECT COUNT(*) as count FROM users WHERE isActive = 1 AND newsletter = 1 AND email IS NOT NULL AND email != ""');

        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [currentUserId]
        );

        res.render('email', {
            title: 'Sistema de Comunicação - VelvetWin',
            breadcrumb: 'Comunicação',
            emailLogs,
            stats: {
                totalPlayers: totalPlayersResult[0].count,
                playersWithEmail: playersWithEmailResult[0].count,
                newsletterSubscribers: newsletterSubscribersResult[0].count
            },
            user: req.session.staff,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [currentUserId]
                ))[0].count,
                notifications: notifications
            },
            staffMembers: staffMembers,
            unreadInternalCount: unreadInternalCount || 0,
            recentConversations: []
        });
    } catch (error) {
        console.error('Erro ao carregar página de email:', error);
        req.flash('error', 'Erro ao carregar página de email');
        
        res.render('email', {
            title: 'Sistema de Comunicação - VelvetWin',
            breadcrumb: 'Comunicação',
            emailLogs: [],
            stats: { totalPlayers: 0, playersWithEmail: 0, newsletterSubscribers: 0 },
            user: req.session.staff,
            notifications: {
                unreadCount: 0,
                notifications: []
            },
            staffMembers: [],
            unreadInternalCount: 0,
            recentConversations: []
        });
    }
});

// ==============================
// ROTA PARA ENVIAR EMAIL (USANDO CHAT INTERNO)
// ==============================

app.post('/api/email/send', requireAuth, async (req, res) => {
    try {
        const { recipients, subject, message, clientMessageId } = req.body;
        const currentUserId = req.session.staff.id;
        const currentStaff = req.session.staff;
        
        if (recipients && !isNaN(recipients)) {
            const recipientStaff = await query(
                'SELECT id, name FROM staffs WHERE id = ?',
                [recipients]
            );
            
            if (recipientStaff && recipientStaff.length > 0) {
                const messageHash = `${currentUserId}-${recipients}-${Date.now()}-${subject.substring(0, 20).replace(/\s/g, '')}`;
                
                try {
                    const result = await execute(
                        'INSERT INTO internal_messages (senderId, recipientId, message, \`read\`, timestamp, messageHash) VALUES (?, ?, ?, ?, ?, ?)',
                        [currentUserId, recipients, `📧 ${subject}: ${message}`, 0, new Date(), messageHash]
                    );
                    
                    wss.clients.forEach(client => {
                        if (client.readyState === WebSocket.OPEN && client.userId == recipients) {
                            client.send(JSON.stringify({
                                type: 'chat_message',
                                messageId: result.insertId,
                                senderId: currentUserId,
                                senderName: currentStaff.name,
                                message: `📧 ${subject}: ${message}`,
                                timestamp: new Date(),
                                clientMessageId: clientMessageId
                            }));
                        }
                    });
                    
                    return res.json({
                        success: true,
                        message: 'Mensagem interna enviada com sucesso',
                        type: 'internal',
                        messageId: result.insertId
                    });
                } catch (error) {
                    if (error.code === 'ER_DUP_ENTRY') {
                        return res.json({
                            success: true,
                            message: 'Mensagem já enviada anteriormente',
                            type: 'internal',
                            duplicate: true
                        });
                    }
                    throw error;
                }
            }
        }
        
        await execute(
            'INSERT INTO email_logs (\`to\`, subject, message, template, sentByStaffId, sentByStaffName, status, playersCount, sentAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [typeof recipients === 'string' ? recipients : 'Grupo de jogadores', subject, message, 'manual', currentUserId, currentStaff.name, 'sent', 0, new Date()]
        );
        
        res.json({
            success: true,
            message: 'Mensagem registrada (sistema de chat interno ativo)',
            type: 'log'
        });
        
    } catch (error) {
        console.error('Erro ao enviar email:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao processar envio'
        });
    }
});

// ==============================
// ROTAS DE EMAIL - API ADICIONAIS
// ==============================

app.get('/api/email/stats', requireAuth, async (req, res) => {
    try {
        const totalPlayersResult = await query('SELECT COUNT(*) as count FROM users WHERE isActive = 1');
        const playersWithEmailResult = await query('SELECT COUNT(*) as count FROM users WHERE isActive = 1 AND email IS NOT NULL AND email != ""');
        const newsletterSubscribersResult = await query('SELECT COUNT(*) as count FROM users WHERE isActive = 1 AND newsletter = 1 AND email IS NOT NULL AND email != ""');

        res.json({
            success: true,
            totalPlayers: totalPlayersResult[0].count,
            playersWithEmail: playersWithEmailResult[0].count,
            newsletterSubscribers: newsletterSubscribersResult[0].count
        });
    } catch (error) {
        console.error('Erro ao buscar estatísticas de email:', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar estatísticas' });
    }
});

app.get('/api/email/logs', requireAuth, async (req, res) => {
    try {
        const emailLogs = await query(
            'SELECT * FROM email_logs ORDER BY sentAt DESC LIMIT 50'
        );

        res.json({
            success: true,
            logs: emailLogs
        });
    } catch (error) {
        console.error('Erro ao buscar logs de email:', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar logs' });
    }
});

app.get('/api/email/recipients/:type', requireAuth, async (req, res) => {
    try {
        const type = req.params.type;
        let whereClause = 'WHERE isActive = 1 AND email IS NOT NULL AND email != ""';
        
        if (type === 'newsletter') {
            whereClause += ' AND newsletter = 1';
        } else if (type === 'vip') {
            whereClause += ' AND level IN ("VIP", "Gold", "Platinum", "Diamond")';
        } else if (type === 'active') {
            const thirtyDaysAgo = new Date();
            thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
            whereClause += ' AND lastLogin >= ?';
        }

        const params = type === 'active' ? [thirtyDaysAgo] : [];
        const players = await query(
            `SELECT id, username, email, firstName, lastName, level, lastLogin 
             FROM users 
             ${whereClause} 
             LIMIT 500`,
            params
        );

        res.json({
            success: true,
            players: players.map(player => ({
                _id: player.id,
                username: player.username,
                email: player.email,
                firstName: player.firstName,
                lastName: player.lastName,
                name: `${player.firstName || ''} ${player.lastName || ''}`.trim() || player.username,
                level: player.level || 'Bronze',
                lastLogin: player.lastLogin
            }))
        });
    } catch (error) {
        console.error('Erro ao buscar destinatários:', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar destinatários' });
    }
});

// ==============================
// ROTAS DE LOGS DO SISTEMA (PÁGINA)
// ==============================

app.get('/logs', requireAuth, requirePermission('view_logs'), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const offset = (page - 1) * limit;
        
        let whereClause = '';
        let params = [];
        
        if (req.query.user) {
            whereClause += ' AND userId = ?';
            params.push(req.query.user);
        }
        if (req.query.action) {
            whereClause += ' AND action = ?';
            params.push(req.query.action);
        }
        if (req.query.module) {
            whereClause += ' AND module = ?';
            params.push(req.query.module);
        }
        if (req.query.search) {
            whereClause += ' AND (message LIKE ? OR details LIKE ? OR ip LIKE ? OR user LIKE ?)';
            const searchTerm = `%${req.query.search}%`;
            params.push(searchTerm, searchTerm, searchTerm, searchTerm);
        }
        
        if (req.query.dateFrom || req.query.dateTo) {
            if (req.query.dateFrom) {
                whereClause += ' AND timestamp >= ?';
                params.push(new Date(req.query.dateFrom));
            }
            if (req.query.dateTo) {
                const dateTo = new Date(req.query.dateTo);
                dateTo.setHours(23, 59, 59, 999);
                whereClause += ' AND timestamp <= ?';
                params.push(dateTo);
            }
        }
        
        const where = whereClause ? `WHERE 1=1 ${whereClause}` : '';
        const sortField = req.query.sort || 'timestamp';
        const sortOrder = req.query.order === 'asc' ? 'ASC' : 'DESC';

        const logs = await query(
            `SELECT * FROM system_logs 
             ${where}
             ORDER BY ${sortField} ${sortOrder} 
             LIMIT ? OFFSET ?`,
            [...params, limit, offset]
        );
        
        const totalLogsResult = await query(`SELECT COUNT(*) as count FROM system_logs ${where}`, params);
        const totalLogs = totalLogsResult[0].count;
        const totalPages = Math.ceil(totalLogs / limit);
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const stats = {
            total: totalLogs,
            today: (await query('SELECT COUNT(*) as count FROM system_logs WHERE timestamp >= ?', [today]))[0].count,
            byAction: await query('SELECT action, COUNT(*) as count FROM system_logs GROUP BY action ORDER BY count DESC'),
            byModule: await query('SELECT module, COUNT(*) as count FROM system_logs GROUP BY module ORDER BY count DESC')
        };
        
        const usersResult = await query('SELECT DISTINCT userId, user FROM system_logs WHERE userId IS NOT NULL');
        const users = usersResult.map(u => {
            try {
                const userData = JSON.parse(u.user);
                return {
                    _id: u.userId,
                    name: userData.name,
                    email: userData.email,
                    role: userData.role
                };
            } catch (e) {
                return null;
            }
        }).filter(u => u !== null);
        
        const actionOptions = ['login', 'logout', 'create', 'update', 'delete', 'view', 'approve', 'reject', 'system'];
        const moduleOptions = ['auth', 'players', 'withdrawals', 'payments', 'staff', 'support', 'settings', 'system', 'email', 'dashboard'];
        
        const unreadLogsResult = await query('SELECT COUNT(*) as count FROM system_logs WHERE \`read\` = 0');
        const unreadLogs = unreadLogsResult[0].count;

        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [req.session.staff.id]
        );

        res.render('logs', {
            title: 'Logs do Sistema - VelvetWin',
            breadcrumb: 'Logs',
            logs,
            stats,
            users,
            actionOptions,
            moduleOptions,
            currentPage: page,
            totalPages,
            limit,
            filters: req.query,
            user: req.session.staff,
            unreadLogs,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [req.session.staff.id]
                ))[0].count,
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar logs:', error);
        req.flash('error', 'Erro ao carregar logs');
        
        res.render('logs', {
            title: 'Logs do Sistema - VelvetWin',
            breadcrumb: 'Logs',
            logs: [],
            stats: { total: 0, today: 0, byAction: [], byModule: [] },
            users: [],
            actionOptions: [],
            moduleOptions: [],
            currentPage: 1,
            totalPages: 1,
            limit: 50,
            filters: {},
            user: req.session.staff,
            unreadLogs: 0,
            notifications: {
                unreadCount: 0,
                notifications: []
            }
        });
    }
});

// ==============================
// API ROUTES PARA LOGS
// ==============================

app.get('/api/logs', requireAuth, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;
        
        let whereClause = '';
        let params = [];
        
        if (req.query.user) {
            whereClause += ' AND userId = ?';
            params.push(req.query.user);
        }
        if (req.query.action) {
            whereClause += ' AND action = ?';
            params.push(req.query.action);
        }
        if (req.query.module) {
            whereClause += ' AND module = ?';
            params.push(req.query.module);
        }
        if (req.query.search) {
            whereClause += ' AND (message LIKE ? OR details LIKE ? OR ip LIKE ? OR user LIKE ?)';
            const searchTerm = `%${req.query.search}%`;
            params.push(searchTerm, searchTerm, searchTerm, searchTerm);
        }
        
        if (req.query.dateFrom || req.query.dateTo) {
            if (req.query.dateFrom) {
                whereClause += ' AND timestamp >= ?';
                params.push(new Date(req.query.dateFrom));
            }
            if (req.query.dateTo) {
                const dateTo = new Date(req.query.dateTo);
                dateTo.setHours(23, 59, 59, 999);
                whereClause += ' AND timestamp <= ?';
                params.push(dateTo);
            }
        }
        
        const where = whereClause ? `WHERE 1=1 ${whereClause}` : '';
        const sortField = req.query.sort || 'timestamp';
        const sortOrder = req.query.order === 'asc' ? 'ASC' : 'DESC';

        const logs = await query(
            `SELECT * FROM system_logs 
             ${where}
             ORDER BY ${sortField} ${sortOrder} 
             LIMIT ? OFFSET ?`,
            [...params, limit, offset]
        );
        
        const totalLogsResult = await query(`SELECT COUNT(*) as count FROM system_logs ${where}`, params);
        const totalLogs = totalLogsResult[0].count;
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const twoHoursAgo = new Date();
        twoHoursAgo.setHours(twoHoursAgo.getHours() - 2);
        
        const todayLogsResult = await query('SELECT COUNT(*) as count FROM system_logs WHERE timestamp >= ?', [today]);
        const last30Days = new Date();
        last30Days.setDate(last30Days.getDate() - 30);
        const last30DaysLogsResult = await query('SELECT COUNT(*) as count FROM system_logs WHERE timestamp >= ?', [last30Days]);
        const activeAdminsResult = await query('SELECT DISTINCT userId FROM system_logs WHERE action = "login" AND timestamp >= ?', [twoHoursAgo]);
        const oneHourAgo = new Date();
        oneHourAgo.setHours(oneHourAgo.getHours() - 1);
        const lastHourLogsResult = await query('SELECT COUNT(*) as count FROM system_logs WHERE timestamp >= ?', [oneHourAgo]);
        
        const activityRate = (lastHourLogsResult[0].count / 60).toFixed(1);
        
        res.json({
            success: true,
            logs: logs,
            page: page,
            pages: Math.ceil(totalLogs / limit),
            total: totalLogs,
            stats: {
                total: last30DaysLogsResult[0].count,
                today: todayLogsResult[0].count,
                activeAdmins: activeAdminsResult.length,
                activityRate: `${activityRate}/min`
            }
        });
        
    } catch (error) {
        console.error('Error getting logs:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao carregar logs'
        });
    }
});

app.get('/api/logs/:id', requireAuth, async (req, res) => {
    try {
        const logId = parseInt(req.params.id);
        if (isNaN(logId)) {
            return res.status(400).json({
                success: false,
                message: 'ID inválido'
            });
        }
        
        const log = await query('SELECT * FROM system_logs WHERE id = ?', [logId]);
        
        if (!log || log.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Log não encontrado'
            });
        }
        
        res.json({
            success: true,
            log: log[0]
        });
        
    } catch (error) {
        console.error('Error getting log by ID:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao carregar log'
        });
    }
});

app.get('/api/logs/users', requireAuth, async (req, res) => {
    try {
        const usersWithLogs = await query('SELECT DISTINCT userId, user FROM system_logs WHERE userId IS NOT NULL');
        
        let users = [];
        
        if (usersWithLogs && usersWithLogs.length > 0) {
            users = usersWithLogs.map(u => {
                try {
                    const userData = JSON.parse(u.user);
                    return {
                        _id: u.userId,
                        name: userData.name,
                        email: userData.email,
                        role: userData.role
                    };
                } catch (e) {
                    return null;
                }
            }).filter(u => u !== null);
        } else {
            const staffDocs = await query('SELECT id as _id, name, email, role FROM staffs WHERE isActive = 1');
            users = staffDocs;
        }
        
        res.json({
            success: true,
            users: users
        });
        
    } catch (error) {
        console.error('Error getting users for filter:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao carregar utilizadores'
        });
    }
});

app.post('/api/logs/mark-read', requireAuth, async (req, res) => {
    try {
        await execute(
            'UPDATE system_logs SET \`read\` = 1 WHERE userId = ? AND \`read\` = 0',
            [req.session.staff.id]
        );
        
        res.json({
            success: true,
            message: 'Logs marcados como lidos'
        });
        
    } catch (error) {
        console.error('Error marking logs as read:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao marcar logs como lidos'
        });
    }
});

app.get('/api/logs/export', requireAuth, async (req, res) => {
    try {
        const format = req.query.format || 'csv';
        
        let whereClause = '';
        let params = [];
        
        if (req.query.user) {
            whereClause += ' AND userId = ?';
            params.push(req.query.user);
        }
        if (req.query.action) {
            whereClause += ' AND action = ?';
            params.push(req.query.action);
        }
        if (req.query.module) {
            whereClause += ' AND module = ?';
            params.push(req.query.module);
        }
        if (req.query.search) {
            whereClause += ' AND (message LIKE ? OR details LIKE ? OR ip LIKE ? OR user LIKE ?)';
            const searchTerm = `%${req.query.search}%`;
            params.push(searchTerm, searchTerm, searchTerm, searchTerm);
        }
        
        if (req.query.dateFrom || req.query.dateTo) {
            if (req.query.dateFrom) {
                whereClause += ' AND timestamp >= ?';
                params.push(new Date(req.query.dateFrom));
            }
            if (req.query.dateTo) {
                const dateTo = new Date(req.query.dateTo);
                dateTo.setHours(23, 59, 59, 999);
                whereClause += ' AND timestamp <= ?';
                params.push(dateTo);
            }
        }
        
        const where = whereClause ? `WHERE 1=1 ${whereClause}` : '';

        const logs = await query(
            `SELECT * FROM system_logs 
             ${where}
             ORDER BY timestamp DESC`,
            params
        );
        
        if (format === 'csv') {
            let csv = 'Data,Hora,Utilizador,Email,Cargo,Ação,Módulo,Mensagem,IP,Localização,User Agent\n';
            
            logs.forEach(log => {
                const date = new Date(log.timestamp);
                const dateStr = date.toLocaleDateString('pt-PT');
                const timeStr = date.toLocaleTimeString('pt-PT');
                
                let userData = {};
                try {
                    userData = JSON.parse(log.user);
                } catch (e) {
                    userData = {};
                }
                
                csv += `"${dateStr}","${timeStr}","${userData.name || ''}","${userData.email || ''}","${userData.role || ''}","${log.action || ''}","${log.module || ''}","${log.message || ''}","${log.ip || ''}","${log.location || ''}","${log.userAgent || ''}"\n`;
            });
            
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', 'attachment; filename=logs.csv');
            res.send(csv);
            
        } else if (format === 'json') {
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', 'attachment; filename=logs.json');
            res.json(logs);
            
        } else {
            res.status(400).json({
                success: false,
                message: 'Formato não suportado'
            });
        }
        
    } catch (error) {
        console.error('Error exporting logs:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao exportar logs'
        });
    }
});

app.post('/api/logs/cleanup', requireAuth, async (req, res) => {
    try {
        if (!req.session.staff || req.session.staff.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Acesso negado'
            });
        }
        
        const ninetyDaysAgo = new Date();
        ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
        
        const result = await execute(
            'DELETE FROM system_logs WHERE timestamp < ?',
            [ninetyDaysAgo]
        );
        
        res.json({
            success: true,
            message: `Foram eliminados ${result.affectedRows} logs antigos`,
            deletedCount: result.affectedRows
        });
        
    } catch (error) {
        console.error('Error cleaning up logs:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao limpar logs'
        });
    }
});

app.post('/api/logs/:id/flag', requireAuth, async (req, res) => {
    try {
        const logId = parseInt(req.params.id);
        if (isNaN(logId)) {
            return res.status(400).json({
                success: false,
                message: 'ID inválido'
            });
        }
        
        const logResult = await query('SELECT * FROM system_logs WHERE id = ?', [logId]);
        
        if (!logResult || logResult.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Log não encontrado'
            });
        }
        
        const log = logResult[0];
        let metadata = {};
        try {
            metadata = JSON.parse(log.metadata || '{}');
        } catch (e) {
            metadata = {};
        }
        
        metadata.flagged = true;
        metadata.flaggedBy = req.session.staff.id;
        metadata.flaggedAt = new Date();
        metadata.reason = req.body.reason || 'Reportado por administrador';
        
        await execute(
            'UPDATE system_logs SET metadata = ? WHERE id = ?',
            [JSON.stringify(metadata), logId]
        );
        
        await execute(
            'INSERT INTO alerts (type, severity, title, message, metadata, isResolved, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)',
            ['security', 'medium', 'Log Reportado', 
             `Log #${logId.toString().slice(-6)} reportado por ${req.session.staff.name}`,
             JSON.stringify({
                logId: logId,
                reason: metadata.reason,
                logAction: log.action,
                logModule: log.module
             }),
             0, new Date()]
        );
        
        res.json({
            success: true,
            message: 'Log reportado para análise'
        });
        
    } catch (error) {
        console.error('Error flagging log:', error);
        res.status(500).json({
            success: false,
            message: 'Erro ao reportar log'
        });
    }
});

// ==============================
// ROTAS DE DEFINIÇÕES
// ==============================

app.get('/settings', requireAuth, requirePermission('view_settings'), async (req, res) => {
    try {
        const settings = await query('SELECT * FROM system_settings');
        
        const settingsByCategory = {};
        settings.forEach(setting => {
            if (!settingsByCategory[setting.category]) {
                settingsByCategory[setting.category] = [];
            }
            settingsByCategory[setting.category].push(setting);
        });
        
        const categories = ['general', 'email', 'security', 'payment', 'withdrawal', 'notification'];
        
        const notifications = await query(
            'SELECT id, title, message, type, \`read\`, createdAt FROM user_notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 10',
            [req.session.staff.id]
        );

        res.render('settings', {
            title: 'Definições do Sistema - VelvetWin',
            breadcrumb: 'Definições',
            settingsByCategory,
            categories,
            user: req.session.staff,
            notifications: {
                unreadCount: (await query(
                    'SELECT COUNT(*) as count FROM user_notifications WHERE userId = ? AND \`read\` = 0',
                    [req.session.staff.id]
                ))[0].count,
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar definições:', error);
        req.flash('error', 'Erro ao carregar definições');
        
        res.render('settings', {
            title: 'Definições do Sistema - VelvetWin',
            breadcrumb: 'Definições',
            settingsByCategory: {},
            categories: [],
            user: req.session.staff,
            notifications: {
                unreadCount: 0,
                notifications: []
            }
        });
    }
});

app.post('/api/settings/save', requireAuth, requirePermission('manage_settings'), async (req, res) => {
    try {
        const settings = req.body;
        const staff = req.session.staff;
        
        for (const [key, value] of Object.entries(settings)) {
            const existing = await query('SELECT id FROM system_settings WHERE `key` = ?', [key]);
            
            if (existing && existing.length > 0) {
                await execute(
                    'UPDATE system_settings SET value = ?, updatedBy = ?, updatedAt = ? WHERE `key` = ?',
                    [JSON.stringify(value), staff.id, new Date(), key]
                );
            } else {
                await execute(
                    'INSERT INTO system_settings (`key`, value, category, updatedBy, updatedAt) VALUES (?, ?, ?, ?, ?)',
                    [key, JSON.stringify(value), 'general', staff.id, new Date()]
                );
            }
        }
        
        await createSystemLog(
            staff.id,
            staff,
            'update',
            'settings',
            'Definições do sistema atualizadas',
            `Alteradas ${Object.keys(settings).length} definições`,
            req
        );
        
        res.json({ success: true, message: 'Definições guardadas com sucesso' });
    } catch (error) {
        console.error('Erro ao guardar definições:', error);
        res.status(500).json({ success: false, error: 'Erro ao guardar definições' });
    }
});

// ==============================
// ROTAS ADICIONAIS E DE TESTE
// ==============================

app.get('/cleanup-sessions', async (req, res) => {
    if (process.env.NODE_ENV === 'production') {
        return res.status(403).send('Não disponível em produção');
    }
    
    try {
        const result = await execute('DELETE FROM sessions WHERE expires < ?', [new Date()]);
        
        if (req.session && req.session.destroy) {
            req.session.destroy(() => {
                res.send(`
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Sessões Limpas - VelvetWin</title>
                        <style>
                            body { font-family: Arial, sans-serif; padding: 20px; }
                            .success { color: green; }
                        </style>
                    </head>
                    <body>
                        <h1 class="success">✅ Sessões limpas com sucesso!</h1>
                        <p>Sessions: ${result.affectedRows} removidas</p>
                        <p><a href="/login">Ir para Login</a></p>
                    </body>
                    </html>
                `);
            });
        }
    } catch (error) {
        console.error('Erro ao limpar sessões:', error);
        res.status(500).send('Erro ao limpar sessões');
    }
});

app.get('/favicon.ico', (req, res) => {
    res.status(204).end();
});

app.use('/public', express.static(path.join(__dirname, 'public')));

app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date(),
        database: 'MySQL connected',
        sessionId: req.sessionID,
        sessionExists: !!req.session,
        staff: req.session && req.session.staff ? req.session.staff : 'not_logged_in'
    });
});

app.get('/session-info', (req, res) => {
    if (!req.session) {
        return res.json({
            error: 'Sessão não está disponível',
            sessionID: null
        });
    }
    
    res.json({
        sessionID: req.sessionID,
        session: {
            id: req.session.id,
            staff: req.session.staff,
            cookie: req.session.cookie
        }
    });
});

app.get('/ws-test', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>WebSocket Test - VelvetWin</title>
            <script>
                const ws = new WebSocket('ws://localhost:${PORT}');
                
                ws.onopen = () => {
                    console.log('WebSocket conectado');
                    ws.send(JSON.stringify({ type: 'subscribe_notifications' }));
                };
                
                ws.onmessage = (event) => {
                    console.log('Mensagem recebida:', event.data);
                    document.getElementById('messages').innerHTML += '<p>' + event.data + '</p>';
                };
                
                ws.onerror = (error) => {
                    console.error('Erro WebSocket:', error);
                };
                
                function sendTest() {
                    ws.send(JSON.stringify({ type: 'test', message: 'Hello WebSocket' }));
                }
                
                function sendNotification() {
                    fetch('/api/test-notification', {
                        method: 'GET',
                        headers: { 'Content-Type': 'application/json' }
                    })
                    .then(response => response.json())
                    .then(data => console.log('Notificação enviada:', data));
                }
            </script>
        </head>
        <body>
            <h1>WebSocket Test - VelvetWin</h1>
            <button onclick="sendTest()">Enviar Teste</button>
            <button onclick="sendNotification()">Enviar Notificação</button>
            <div id="messages"></div>
        </body>
        </html>
    `);
});

app.use('/profile-photos', express.static(path.join(__dirname, 'public', 'uploads')));

const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log('✅ Diretório de uploads criado:', uploadsDir);
}

// ==============================
// ROTA RAIZ
// ==============================

app.get('/', (req, res) => {
    if (req.session && req.session.staff && req.session.staff.loggedIn) {
        return res.redirect('/dashboard');
    }
    res.redirect('/login');
});

// ==============================
// HANDLERS DE ERRO
// ==============================

app.use((req, res) => {
    res.status(404).render('error', {
        title: 'Página Não Encontrada - VelvetWin',
        message: 'A página que procura não existe.',
        error: { status: 404 },
        user: req.session?.staff || null
    });
});

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
// INICIAR SERVIDOR
// ==============================

server.listen(PORT, () => {
    console.log(`\n=========================================`);
    console.log(`🎰 VELVETWIN ADMIN DASHBOARD COMPLETO`);
    console.log(`=========================================`);
    console.log(`📡 Porta: ${PORT}`);
    console.log(`🌐 URL: http://localhost:${PORT}`);
    console.log(`💾 MySQL: CONECTADO`);
    console.log(`📡 WebSocket: ws://localhost:${PORT}`);
    console.log(`📁 Uploads: ${uploadsDir}`);
    console.log(`=========================================`);
    console.log(`✅ SISTEMA MIGRADO PARA MYSQL/phpMyAdmin!`);
    console.log(`=========================================`);
    console.log(`🔧 ROTAS PRINCIPAIS:`);
    console.log(`   • Login: http://localhost:${PORT}/login`);
    console.log(`   • Dashboard: http://localhost:${PORT}/dashboard`);
    console.log(`   • Jogadores: http://localhost:${PORT}/players`);
    console.log(`   • Pagamentos: http://localhost:${PORT}/payments`);
    console.log(`   • Levantamentos: http://localhost:${PORT}/withdrawals`);
    console.log(`   • Staff: http://localhost:${PORT}/staff`);
    console.log(`   • Suporte: http://localhost:${PORT}/support`);
    console.log(`   • Email/Chat: http://localhost:${PORT}/email`);
    console.log(`   • Logs: http://localhost:${PORT}/logs`);
    console.log(`   • Definições: http://localhost:${PORT}/settings`);
    console.log(`   • Perfil: http://localhost:${PORT}/profile`);
    console.log(`=========================================`);
    console.log(`⚡ SISTEMA PRONTO PARA USO!`);
    console.log(`=========================================\n`);
});
