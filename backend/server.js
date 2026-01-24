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

dotenv.config();

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// ==============================
// 1. CONFIGURAÇÃO CRÍTICA HOSTINGER
// ==============================
app.set('trust proxy', 1);

// ==============================
// 2. CONFIGURAÇÃO MYSQL SIMPLIFICADA
// ==============================
const dbConfig = {
    host: process.env.DB_HOST || '193.203.168.151',
    user: process.env.DB_USER || 'u920267475_dashboard',
    password: process.env.DB_PASSWORD || 'Zy@jtldui@_sy1@',
    database: process.env.DB_NAME || 'u920267475_dashboard',
    port: process.env.DB_PORT || 3306
};

const pool = mysql.createPool(dbConfig);

// ==============================
// 3. MIDDLEWARES ESSENCIAIS (ORDEM CRÍTICA)
// ==============================
app.use(helmet({
    contentSecurityPolicy: false // Desativa CSP temporariamente
}));

app.use(cors());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session simplificada
app.use(session({
    secret: process.env.SESSION_SECRET || 'velvetwin-secret-' + Math.random().toString(36),
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.use(express.static(path.join(__dirname, 'public')));
app.use(morgan('combined'));

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ==============================
// 4. ROTAS ESSENCIAIS (TESTAR PRIMEIRO)
// ==============================

// ROTA 1: RAIZ - SEMPRE RESPONDE
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>VelvetWin - Sistema Online</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .container {
                    background: white;
                    padding: 50px;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    text-align: center;
                    max-width: 500px;
                    width: 90%;
                }
                h1 {
                    color: #333;
                    margin-bottom: 20px;
                    font-size: 2.5em;
                }
                .status {
                    background: #4CAF50;
                    color: white;
                    padding: 15px;
                    border-radius: 10px;
                    margin: 20px 0;
                }
                .btn {
                    display: inline-block;
                    background: #667eea;
                    color: white;
                    padding: 15px 30px;
                    text-decoration: none;
                    border-radius: 50px;
                    font-weight: bold;
                    margin: 10px;
                    transition: transform 0.3s;
                }
                .btn:hover {
                    transform: translateY(-3px);
                }
                .info {
                    margin-top: 30px;
                    color: #666;
                    font-size: 0.9em;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🎰 VelvetWin Admin</h1>
                <p>Sistema de gestão administrativa</p>
                
                <div class="status">
                    ✅ SISTEMA OPERACIONAL<br>
                    Porta: ${PORT}<br>
                    ${process.env.NODE_ENV || 'Ambiente de Desenvolvimento'}
                </div>
                
                <a href="/login" class="btn">🔐 Ir para Login</a>
                <a href="/health" class="btn" style="background: #10B981;">🩺 Health Check</a>
                <a href="/test-db" class="btn" style="background: #F59E0B;">🗄️ Testar Database</a>
                
                <div class="info">
                    Servidor: Node.js Express<br>
                    Versão: 1.0.0<br>
                    © 2024 VelvetWin
                </div>
            </div>
        </body>
        </html>
    `);
});

// ROTA 2: HEALTH CHECK - CRÍTICA PARA HOSTINGER
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

// ROTA 3: TESTE DATABASE SIMPLES
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
            error: error.message,
            config: {
                host: dbConfig.host,
                database: dbConfig.database
            }
        });
    }
});

// ROTA 4: LOGIN SIMPLIFICADO
app.get('/login', (req, res) => {
    // Página de login estática simples
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - VelvetWin</title>
            <style>
                body { 
                    font-family: Arial, sans-serif;
                    background: #f5f5f5;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                }
                .login-box {
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                    width: 350px;
                }
                h2 { text-align: center; color: #333; margin-bottom: 30px; }
                input { 
                    width: 100%; 
                    padding: 12px; 
                    margin: 10px 0; 
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    box-sizing: border-box;
                }
                button {
                    width: 100%;
                    padding: 12px;
                    background: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 16px;
                }
                .back { 
                    display: block; 
                    text-align: center; 
                    margin-top: 20px;
                    color: #666;
                }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>🔐 VelvetWin Login</h2>
                <form action="/api/login" method="POST">
                    <input type="email" name="email" placeholder="Email" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Entrar</button>
                </form>
                <a href="/" class="back">← Voltar à página inicial</a>
            </div>
        </body>
        </html>
    `);
});

// ROTA 5: API LOGIN SIMPLES
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Login hardcoded para teste
        if (email === 'admin@velvetwin.com' && password === 'admin123') {
            req.session.user = {
                id: 1,
                email: email,
                name: 'Administrador',
                role: 'admin'
            };
            
            return res.json({
                success: true,
                message: 'Login bem-sucedido!',
                redirect: '/dashboard'
            });
        }
        
        res.status(401).json({
            success: false,
            message: 'Credenciais inválidas'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Erro no servidor'
        });
    }
});

// ROTA 6: DASHBOARD SIMPLES
app.get('/dashboard', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - VelvetWin</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
                .header { 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                }
                .stats { display: flex; gap: 20px; margin-top: 30px; }
                .stat-card { 
                    background: white; 
                    padding: 20px; 
                    border-radius: 10px;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                    flex: 1;
                    text-align: center;
                }
                .logout { 
                    background: #EF4444;
                    color: white;
                    padding: 10px 20px;
                    text-decoration: none;
                    border-radius: 5px;
                    float: right;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🎰 Dashboard VelvetWin</h1>
                <p>Bem-vindo, ${req.session.user.name}!</p>
                <a href="/logout" class="logout">🚪 Sair</a>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>📊 Total de Jogadores</h3>
                    <p style="font-size: 2em; color: #4CAF50;">0</p>
                </div>
                <div class="stat-card">
                    <h3>💰 Levantamentos Pendentes</h3>
                    <p style="font-size: 2em; color: #F59E0B;">0</p>
                </div>
                <div class="stat-card">
                    <h3>🎫 Tickets Abertos</h3>
                    <p style="font-size: 2em; color: #667eea;">0</p>
                </div>
            </div>
            
            <p style="margin-top: 50px;">
                <a href="/">🏠 Home</a> | 
                <a href="/players">👥 Jogadores</a> |
                <a href="/test-db">🗄️ Testar DB</a>
            </p>
        </body>
        </html>
    `);
});

// ROTA 7: LOGOUT
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// ROTA 8: PLAYERS SIMPLES
app.get('/players', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Jogadores - VelvetWin</title>
            <style>
                body { font-family: Arial, sans-serif; padding: 20px; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background: #667eea; color: white; }
                .back { display: inline-block; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <a href="/dashboard" class="back">← Voltar ao Dashboard</a>
            <h1>👥 Gestão de Jogadores</h1>
            <p>Funcionalidade em desenvolvimento</p>
            <table>
                <tr><th>ID</th><th>Nome</th><th>Email</th><th>Saldo</th></tr>
                <tr><td>1</td><td>João Silva</td><td>joao@email.com</td><td>€100.00</td></tr>
                <tr><td>2</td><td>Maria Santos</td><td>maria@email.com</td><td>€250.50</td></tr>
            </table>
        </body>
        </html>
    `);
});

// ==============================
// 5. ERROR HANDLERS (CRÍTICO)
// ==============================

// 404 - Sempre responde
app.use((req, res) => {
    res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Página Não Encontrada</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    text-align: center; 
                    padding: 50px;
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    color: white;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .error-box { 
                    background: rgba(255,255,255,0.1); 
                    padding: 50px; 
                    border-radius: 20px;
                    backdrop-filter: blur(10px);
                }
                h1 { font-size: 4em; margin: 0; }
                a { 
                    color: white; 
                    text-decoration: none;
                    border: 2px solid white;
                    padding: 10px 20px;
                    border-radius: 50px;
                    display: inline-block;
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <div class="error-box">
                <h1>404</h1>
                <h2>Página Não Encontrada</h2>
                <p>A página que procura não existe.</p>
                <a href="/">🏠 Voltar à página inicial</a>
            </div>
        </body>
        </html>
    `);
});

// 500 - Sempre responde
app.use((err, req, res, next) => {
    console.error('❌ Erro:', err.message);
    
    res.status(500).send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Erro do Servidor</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    text-align: center; 
                    padding: 50px;
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    color: white;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .error-box { 
                    background: rgba(255,255,255,0.1); 
                    padding: 50px; 
                    border-radius: 20px;
                    backdrop-filter: blur(10px);
                    max-width: 600px;
                }
                h1 { font-size: 4em; margin: 0; }
                .debug { 
                    background: rgba(0,0,0,0.2); 
                    padding: 20px; 
                    border-radius: 10px;
                    margin-top: 20px;
                    text-align: left;
                    font-family: monospace;
                    font-size: 0.9em;
                }
            </style>
        </head>
        <body>
            <div class="error-box">
                <h1>500</h1>
                <h2>Erro Interno do Servidor</h2>
                <p>Ocorreu um erro. Por favor, tente novamente.</p>
                
                <div class="debug">
                    <strong>Informação de Debug:</strong><br>
                    Hora: ${new Date().toISOString()}<br>
                    Erro: ${process.env.NODE_ENV === 'development' ? err.message : 'Ocultado em produção'}
                </div>
                
                <a href="/" style="color: white; margin-top: 20px; display: inline-block;">🏠 Voltar à página inicial</a>
            </div>
        </body>
        </html>
    `);
});

// ==============================
// 6. INICIAR SERVIDOR (CONFIGURAÇÃO FINAL)
// ==============================

// Garantir diretórios
const ensureDirectory = (dir) => {
    if (!require('fs').existsSync(dir)) {
        require('fs').mkdirSync(dir, { recursive: true });
        console.log(`✅ Diretório criado: ${dir}`);
    }
};

ensureDirectory(path.join(__dirname, 'public'));
ensureDirectory(path.join(__dirname, 'views'));

server.listen(PORT, '0.0.0.0', () => {
    console.log(`
╔═══════════════════════════════════════════════════╗
║          🎰 VELVETWIN ADMIN ONLINE                ║
╠═══════════════════════════════════════════════════╣
║ ✅ Servidor iniciado na porta: ${PORT}             
║ ✅ URL: http://localhost:${PORT}                   
║ ✅ Database: ${dbConfig.database}                  
║ ✅ Host: ${dbConfig.host}                         
║ ✅ Ambiente: ${process.env.NODE_ENV || 'dev'}      
╠═══════════════════════════════════════════════════╣
║ 🔧 ROTAS PARA TESTAR IMEDIATAMENTE:               
║   • http://localhost:${PORT}/        (Home)        
║   • http://localhost:${PORT}/health  (Health Check)
║   • http://localhost:${PORT}/test-db (Teste DB)    
║   • http://localhost:${PORT}/login   (Login)       
║                                                  
║ 📊 DADOS LOGIN TESTE:                             
║   Email: admin@velvetwin.com                      
║   Password: admin123                              
╚═══════════════════════════════════════════════════╝
    `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🔄 Encerrando servidor...');
    server.close(() => {
        console.log('✅ Servidor encerrado com sucesso.');
        process.exit(0);
    });
});
