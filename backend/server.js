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
// 1. CONFIGURAÇÃO CRÍTICA PARA HOSTINGER
// ==============================
app.set('trust proxy', 1); // CRÍTICO para Hostinger/Cpanel

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
// MIDDLEWARES (ORDEM CRÍTICA PARA HOSTINGER)
// ==============================

// 1. Helmet com CSP seguro para Hostinger
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
            connectSrc: ["'self'", `ws://localhost:${PORT}`, `http://localhost:${PORT}`],
            frameSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameAncestors: ["'self'"]
        },
        reportOnly: false
    }
}));

// 2. CORS configurado para Hostinger
app.use(cors({ 
    origin: ['http://localhost:3000', 'https://yourdomain.com'], // Substitua pelo seu domínio
    credentials: true 
}));

// 3. Body parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 4. Session com configuração para Hostinger
app.use(session({
    key: 'velvetwin.sid',
    secret: process.env.SESSION_SECRET || 'velvetwin-admin-secret-2024-' + Math.random().toString(36).substring(7),
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: false, // Mude para true se usar HTTPS
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax',
        proxy: true // CRÍTICO para Hostinger
    },
    proxy: true // CRÍTICO para Hostinger
}));

// 5. Flash messages
app.use(flash());

// 6. Static files
app.use(express.static(path.join(__dirname, 'public')));

// 7. Logging
app.use(morgan('dev'));

// 8. View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ==============================
// ROTA RAIZ CORRIGIDA (EVITA ERRO 503)
// ==============================

app.get('/', (req, res) => {
    if (req.session && req.session.staff && req.session.staff.loggedIn) {
        return res.redirect('/dashboard');
    }
    // Renderiza uma página inicial simples para evitar erro 503
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>VelvetWin Admin Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; padding: 50px; text-align: center; }
                .container { max-width: 600px; margin: 0 auto; }
                h1 { color: #333; }
                .btn { display: inline-block; padding: 12px 30px; background: #4CAF50; color: white; 
                       text-decoration: none; border-radius: 5px; margin-top: 20px; }
                .status { background: #f0f0f0; padding: 20px; border-radius: 5px; margin-top: 30px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🎰 VelvetWin Admin Dashboard</h1>
                <p>Sistema de gestão administrativa para casino online</p>
                <a href="/login" class="btn">🔐 Ir para Login</a>
                
                <div class="status">
                    <h3>✅ Sistema Operacional</h3>
                    <p>Servidor: Online | Database: MySQL Conectado</p>
                    <p>Porta: ${PORT} | Ambiente: ${process.env.NODE_ENV || 'development'}</p>
                </div>
            </div>
        </body>
        </html>
    `);
});

// ==============================
// ROTA DE LOGIN (MANTIDA PARA TESTE)
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

// ==============================
// ROTA DE HEALTH CHECK (OBRIGATÓRIA PARA HOSTINGER)
// ==============================

app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        service: 'velvetwin-admin',
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development'
    });
});

// ==============================
// ROTA DE STATUS DO BANCO DE DADOS
// ==============================

app.get('/db-status', async (req, res) => {
    try {
        const connection = await pool.getConnection();
        await connection.ping();
        connection.release();
        
        res.json({
            status: 'connected',
            database: dbConfig.database,
            host: dbConfig.host,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            status: 'disconnected',
            error: error.message,
            timestamp: new Date().toISOString()
        });
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
// WEBSOCKET (CONFIGURAÇÃO SEGURA)
// ==============================

const wss = new WebSocket.Server({ server });
const activeConnections = new Map();

wss.on('connection', (ws, req) => {
    console.log('✅ Novo cliente WebSocket conectado');
    
    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            
            if (data.type === 'heartbeat') {
                ws.send(JSON.stringify({ type: 'heartbeat', timestamp: Date.now() }));
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
            }
        } catch (error) {
            console.error('Erro ao carregar staff:', error);
        }
    }
    
    res.locals.staff = req.session && req.session.staff ? req.session.staff : null;
    res.locals.currentPath = req.path;
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    next();
});

// ==============================
// ROTAS PRINCIPAIS (SIMPLIFICADAS PARA TESTE)
// ==============================

// Dashboard
app.get('/dashboard', requireAuth, async (req, res) => {
    try {
        const stats = {
            totalPlayers: (await query('SELECT COUNT(*) as count FROM users WHERE isActive = 1'))[0].count,
            pendingWithdrawals: (await query('SELECT COUNT(*) as count FROM withdrawals WHERE status = "pending"'))[0].count,
            openTickets: (await query('SELECT COUNT(*) as count FROM support_tickets WHERE status = "open"'))[0].count
        };

        res.render('dashboard', {
            title: 'Dashboard - VelvetWin Admin',
            breadcrumb: 'Dashboard',
            stats,
            user: req.session.staff
        });
    } catch (error) {
        console.error('Erro ao carregar dashboard:', error);
        res.render('dashboard', {
            title: 'Dashboard - VelvetWin Admin',
            breadcrumb: 'Dashboard',
            stats: { totalPlayers: 0, pendingWithdrawals: 0, openTickets: 0 },
            user: req.session.staff
        });
    }
});

// Players
app.get('/players', requireAuth, async (req, res) => {
    try {
        const players = await query('SELECT id, username, email, balance, lastLogin FROM users LIMIT 50');
        
        res.render('players', {
            title: 'Gestão de Jogadores - VelvetWin',
            breadcrumb: 'Jogadores',
            players,
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

// ==============================
// HANDLER DE ERRO 404 (CRÍTICO PARA EVITAR 503)
// ==============================

app.use((req, res) => {
    res.status(404).render('error', {
        title: 'Página Não Encontrada',
        message: 'A página que procura não existe.',
        error: { status: 404 },
        user: req.session?.staff || null
    });
});

// ==============================
// HANDLER DE ERRO 500 (CRÍTICO PARA EVITAR 503)
// ==============================

app.use((err, req, res, next) => {
    console.error('❌ Erro no servidor:', err.message || err);
    
    res.status(500).render('error', {
        title: 'Erro Interno',
        message: 'Ocorreu um erro no servidor. Por favor, tente novamente.',
        error: process.env.NODE_ENV === 'development' ? err : {},
        user: req.session?.staff || null
    });
});

// ==============================
// INICIAR SERVIDOR (CONFIGURAÇÃO FINAL)
// ==============================

// Garantir que o diretório de uploads existe
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log('✅ Diretório de uploads criado:', uploadsDir);
}

// Garantir que o diretório views existe
const viewsDir = path.join(__dirname, 'views');
if (!fs.existsSync(viewsDir)) {
    fs.mkdirSync(viewsDir, { recursive: true });
    console.log('✅ Diretório de views criado:', viewsDir);
}

server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n=========================================`);
    console.log(`🎰 VELVETWIN ADMIN DASHBOARD`);
    console.log(`=========================================`);
    console.log(`✅ Servidor iniciado na porta: ${PORT}`);
    console.log(`✅ Modo: ${process.env.NODE_ENV || 'development'}`);
    console.log(`✅ Database: ${dbConfig.database}`);
    console.log(`✅ Host: ${dbConfig.host}`);
    console.log(`=========================================`);
    console.log(`🔧 ROTAS DISPONÍVEIS:`);
    console.log(`   • Home: http://localhost:${PORT}/`);
    console.log(`   • Login: http://localhost:${PORT}/login`);
    console.log(`   • Dashboard: http://localhost:${PORT}/dashboard`);
    console.log(`   • Health Check: http://localhost:${PORT}/health`);
    console.log(`   • DB Status: http://localhost:${PORT}/db-status`);
    console.log(`=========================================`);
    console.log(`⚡ SISTEMA PRONTO PARA HOSTINGER!`);
    console.log(`=========================================\n`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🔄 Recebido SIGTERM, encerrando servidor...');
    server.close(() => {
        console.log('✅ Servidor encerrado.');
        pool.end();
        process.exit(0);
    });
});
