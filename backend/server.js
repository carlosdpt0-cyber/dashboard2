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
const http = require('http');
const flash = require('connect-flash');
const fs = require('fs');

dotenv.config();

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// ==============================
// CONFIGURAÇÃO SIMPLIFICADA PARA HOSTINGER
// ==============================

// Configuração do pool MySQL otimizado
const pool = mysql.createPool({
    host: process.env.DB_HOST || '193.203.168.151',
    user: process.env.DB_USER || 'u920267475_dashboard',
    password: process.env.DB_PASSWORD || 'Zy@jtldui@_sy1@',
    database: process.env.DB_NAME || 'u920267475_dashboard',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10, // Reduzido para Hostinger
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
});

// Testar conexão
pool.getConnection()
    .then(conn => {
        console.log('✅ MySQL conectado');
        conn.release();
    })
    .catch(err => {
        console.error('❌ Erro MySQL:', err.message);
    });

// ==============================
// MIDDLEWARES OTIMIZADOS
// ==============================

app.use(helmet({
    contentSecurityPolicy: false, // Desabilitado temporariamente
    crossOriginEmbedderPolicy: false
}));

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Sessão simplificada
const sessionStore = new MySQLStore({
    host: process.env.DB_HOST || '193.203.168.151',
    user: process.env.DB_USER || 'u920267475_dashboard',
    password: process.env.DB_PASSWORD || 'Zy@jtldui@_sy1@',
    database: process.env.DB_NAME || 'u920267475_dashboard',
    port: process.env.DB_PORT || 3306,
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

app.use(session({
    key: 'velvetwin.sid',
    secret: process.env.SESSION_SECRET || 'velvetwin-secret-key',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.use(flash());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ==============================
// FUNÇÕES DE BANCO DE DADOS
// ==============================

async function query(sql, params = []) {
    try {
        const [rows] = await pool.execute(sql, params);
        return rows;
    } catch (error) {
        console.error('Erro query:', error.message);
        throw error;
    }
}

async function execute(sql, params = []) {
    try {
        const [result] = await pool.execute(sql, params);
        return result;
    } catch (error) {
        console.error('Erro execute:', error.message);
        throw error;
    }
}

// ==============================
// ROTA DE HEALTH CHECK
// ==============================

app.get('/health', async (req, res) => {
    try {
        const conn = await pool.getConnection();
        await conn.ping();
        conn.release();
        
        res.json({
            status: 'ok',
            timestamp: new Date().toISOString(),
            database: 'connected'
        });
    } catch (error) {
        res.status(500).json({
            status: 'error',
            message: error.message
        });
    }
});

// ==============================
// ROTA DE LOGIN SIMPLIFICADA
// ==============================

app.get('/login', (req, res) => {
    if (req.session && req.session.staff) {
        return res.redirect('/dashboard');
    }
    res.render('login', { 
        title: 'Login',
        error: req.flash('error')[0],
        success: req.flash('success')[0]
    });
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            req.flash('error', 'Email e senha são obrigatórios');
            return res.redirect('/login');
        }
        
        const users = await query(
            'SELECT id, name, email, password, role FROM staffs WHERE email = ? AND isActive = 1 LIMIT 1',
            [email]
        );
        
        if (users.length === 0) {
            req.flash('error', 'Credenciais inválidas');
            return res.redirect('/login');
        }
        
        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            // Fallback para senha não hashada (durante migração)
            if (password === user.password) {
                console.log('⚠️ Login com senha não hashada');
            } else {
                req.flash('error', 'Credenciais inválidas');
                return res.redirect('/login');
            }
        }
        
        // Criar sessão
        req.session.staff = {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            loggedIn: true,
            loginTime: new Date()
        };
        
        // Atualizar último login
        await execute(
            'UPDATE staffs SET lastLogin = ?, lastActive = ? WHERE id = ?',
            [new Date(), new Date(), user.id]
        );
        
        req.flash('success', `Bem-vindo, ${user.name}!`);
        res.redirect('/dashboard');
        
    } catch (error) {
        console.error('Erro login:', error);
        req.flash('error', 'Erro interno do servidor');
        res.redirect('/login');
    }
});

// ==============================
// MIDDLEWARE DE AUTENTICAÇÃO
// ==============================

function requireAuth(req, res, next) {
    if (req.session && req.session.staff && req.session.staff.loggedIn) {
        return next();
    }
    req.flash('error', 'Por favor faça login');
    res.redirect('/login');
}

// ==============================
// DASHBOARD SIMPLIFICADO
// ==============================

app.get('/dashboard', requireAuth, async (req, res) => {
    try {
        // Estatísticas básicas
        const totalPlayers = await query('SELECT COUNT(*) as count FROM users WHERE isActive = 1');
        const pendingWithdrawals = await query('SELECT COUNT(*) as count FROM withdrawals WHERE status = "pending"');
        const openTickets = await query('SELECT COUNT(*) as count FROM support_tickets WHERE status = "open"');
        
        res.render('dashboard', {
            title: 'Dashboard',
            user: req.session.staff,
            stats: {
                players: totalPlayers[0]?.count || 0,
                withdrawals: pendingWithdrawals[0]?.count || 0,
                tickets: openTickets[0]?.count || 0
            }
        });
    } catch (error) {
        console.error('Erro dashboard:', error);
        req.flash('error', 'Erro ao carregar dashboard');
        res.render('dashboard', {
            title: 'Dashboard',
            user: req.session.staff,
            stats: { players: 0, withdrawals: 0, tickets: 0 }
        });
    }
});

// ==============================
// LOGOUT
// ==============================

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// ==============================
// ROTA RAIZ
// ==============================

app.get('/', (req, res) => {
    if (req.session && req.session.staff) {
        return res.redirect('/dashboard');
    }
    res.redirect('/login');
});

// ==============================
// ROTAS ESTÁTICAS DE TESTE
// ==============================

app.get('/test', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Teste VelvetWin</title>
            <style>
                body { font-family: Arial, sans-serif; padding: 20px; }
                .success { color: green; }
                .error { color: red; }
            </style>
        </head>
        <body>
            <h1>✅ VelvetWin Admin - Teste</h1>
            <p>Servidor está funcionando!</p>
            <p><a href="/health">Health Check</a></p>
            <p><a href="/login">Login</a></p>
            <p><a href="/dashboard">Dashboard (requer login)</a></p>
        </body>
        </html>
    `);
});

// ==============================
// MANUSEIO DE ERROS
// ==============================

app.use((req, res) => {
    res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head><title>404 - Não Encontrado</title></head>
        <body>
            <h1>404 - Página Não Encontrada</h1>
            <p><a href="/">Voltar ao início</a></p>
        </body>
        </html>
    `);
});

app.use((err, req, res, next) => {
    console.error('Erro:', err);
    res.status(500).send(`
        <!DOCTYPE html>
        <html>
        <head><title>500 - Erro Interno</title></head>
        <body>
            <h1>500 - Erro Interno do Servidor</h1>
            <p><a href="/">Voltar ao início</a></p>
        </body>
        </html>
    `);
});

// ==============================
// INICIAR SERVIDOR
// ==============================

server.listen(PORT, '0.0.0.0', () => {
    console.log(`
=========================================
🎰 VELVETWIN ADMIN - VERSÃO SIMPLIFICADA
=========================================
📡 Porta: ${PORT}
🌐 URL: http://localhost:${PORT}
💾 MySQL: ${pool ? 'CONECTADO' : 'ERRO'}
🏥 Health: http://localhost:${PORT}/health
🔧 Teste: http://localhost:${PORT}/test
=========================================
✅ PRONTO PARA HOSTINGER
=========================================
`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🛑 Recebido SIGTERM, fechando servidor...');
    server.close(() => {
        console.log('✅ Servidor fechado');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('🛑 Recebido SIGINT, fechando servidor...');
    server.close(() => {
        console.log('✅ Servidor fechado');
        process.exit(0);
    });
});
