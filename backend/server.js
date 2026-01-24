const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Rota de teste básica
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>VelvetWin Test</title>
            <style>
                body { font-family: Arial, sans-serif; padding: 40px; background: #f5f5f5; }
                .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .success { color: #28a745; font-size: 24px; }
                .error { color: #dc3545; }
                pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="success">✅ VelvetWin - Teste Básico</h1>
                <p>Servidor Express está funcionando!</p>
                <p><strong>Data/Hora:</strong> ${new Date().toLocaleString('pt-PT')}</p>
                <p><strong>Porta:</strong> ${PORT}</p>
                <p><strong>Node.js:</strong> ${process.version}</p>
                <p><strong>Plataforma:</strong> ${process.platform}</p>
                
                <h3>Rotas disponíveis:</h3>
                <ul>
                    <li><a href="/health">/health</a> - Health check</li>
                    <li><a href="/test-db">/test-db</a> - Teste de banco de dados</li>
                    <li><a href="/env">/env</a> - Variáveis de ambiente</li>
                </ul>
            </div>
        </body>
        </html>
    `);
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage()
    });
});

// Teste de variáveis de ambiente
app.get('/env', (req, res) => {
    const safeEnv = {
        NODE_ENV: process.env.NODE_ENV,
        PORT: process.env.PORT,
        DB_HOST: process.env.DB_HOST ? '*** configurado ***' : 'não configurado',
        DB_USER: process.env.DB_USER ? '*** configurado ***' : 'não configurado',
        DB_NAME: process.env.DB_NAME ? '*** configurado ***' : 'não configurado'
    };
    
    res.json(safeEnv);
});

// Rota de teste de banco de dados
app.get('/test-db', async (req, res) => {
    try {
        const mysql = require('mysql2/promise');
        
        const config = {
            host: process.env.DB_HOST || '193.203.168.151',
            user: process.env.DB_USER || 'u920267475_dashboard',
            password: process.env.DB_PASSWORD || 'Zy@jtldui@_sy1@',
            database: process.env.DB_NAME || 'u920267475_dashboard',
            port: process.env.DB_PORT || 3306,
            connectTimeout: 10000
        };
        
        const connection = await mysql.createConnection(config);
        const [rows] = await connection.execute('SELECT 1 + 1 as result');
        await connection.end();
        
        res.json({
            success: true,
            message: 'Conexão MySQL bem sucedida',
            result: rows[0]
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            code: error.code
        });
    }
});

// Error handling
app.use((req, res) => {
    res.status(404).send(`
        <div style="padding: 20px;">
            <h1>404 - Não encontrado</h1>
            <p><a href="/">Voltar</a></p>
        </div>
    `);
});

app.use((err, req, res, next) => {
    console.error('Erro:', err);
    res.status(500).send(`
        <div style="padding: 20px;">
            <h1 style="color: red;">500 - Erro Interno</h1>
            <p><strong>Mensagem:</strong> ${err.message}</p>
            <pre>${err.stack}</pre>
            <p><a href="/">Voltar</a></p>
        </div>
    `);
});

// Iniciar servidor
app.listen(PORT, '0.0.0.0', () => {
    console.log(`
=======================================
🚀 VelvetWin Test Server
=======================================
✅ Porta: ${PORT}
✅ URL: http://localhost:${PORT}
✅ Node.js: ${process.version}
✅ Data: ${new Date().toLocaleString('pt-PT')}
=======================================
`);
});
