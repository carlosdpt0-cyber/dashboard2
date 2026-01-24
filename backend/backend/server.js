const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const dotenv = require('dotenv');;
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

// ADICIONE ESTE CÓDIGO:
// Limpa o cache de todos os modelos antes de definir
const modelNames = Object.keys(mongoose.models);
modelNames.forEach(modelName => {
    delete mongoose.models[modelName];
    delete mongoose.connection.models[modelName];
});

dotenv.config();

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 5001;

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/casinox';

console.log('🔄 Tentando conectar ao MongoDB Atlas...');

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 15000,
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
    minPoolSize: 2,
    retryWrites: true,
    w: 'majority',
    tls: true,
    tlsAllowInvalidCertificates: false,
})
.then(() => {
    console.log('✅ Conectado ao MongoDB Atlas - Base: casinox');
})
.catch(err => {
    console.error('❌ ERRO CRÍTICO ao conectar ao MongoDB Atlas:', err.message);
    process.exit(1);
});

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

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'seu-email@gmail.com',
        pass: process.env.EMAIL_PASS || 'sua-password'
    }
});

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
    secret: process.env.SESSION_SECRET || 'casino-b7uno-admin-secret-2024-' + Math.random().toString(36).substring(7),
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: MONGODB_URI,
        collectionName: 'admin_sessions',
        ttl: 24 * 60 * 60,
        autoRemove: 'interval',
        autoRemoveInterval: 10,
        touchAfter: 24 * 3600,
        stringify: false,
        serialize: (obj) => obj,
        unserialize: (obj) => obj
    }),
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    },
    name: 'casinox.admin.sid'
}));

app.use(flash());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use((req, res, next) => {
    if (!req.session) {
        req.session = {};
    }
    
    if (!req.sessionID && req.session && req.session.id) {
        req.sessionID = req.session.id;
    }
    
    next();
});

// ========== MIDDLEWARE ATUALIZADO ==========

// Carregar dados do usuário em todas as rotas (ADICIONADO DO PRIMEIRO ARQUIVO)
app.use(async (req, res, next) => {
    if (req.session && req.session.staff) {
        try {
            const staff = await Staff.findById(req.session.staff.id);
            if (staff && staff.isActive) {
                req.user = staff;
                res.locals.user = {
                    id: staff._id,
                    name: staff.name,
                    email: staff.email,
                    role: staff.role,
                    photo: staff.photo,
                    isOnline: staff.isOnline || false
                };
                
                // Atualizar lastActive (ADICIONADO)
                staff.lastActive = new Date();
                await staff.save();
            }
        } catch (error) {
            console.error('Erro ao carregar staff:', error);
        }
    }
    
    // Mantém o código original para compatibilidade
    const sessionUser = (req.session && req.session.staff) ? req.session.staff : null;
    
    res.locals.staff = sessionUser;
    res.locals.currentPath = req.path;
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    next();
});

// ==============================
// SCHEMAS DO MONGODB - ATUALIZADOS
// ==============================

const StaffSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    role: { 
        type: String, 
        enum: ['admin', 'support_manager', 'support', 'finance', 'moderator', 'viewer'],
        default: 'support'
    },
    department: String,
    photo: {
        type: String,
        default: null
    },
    isActive: { type: Boolean, default: true },
    isOnline: { type: Boolean, default: false }, // ADICIONADO DO PRIMEIRO ARQUIVO
    lastActive: { type: Date, default: Date.now }, // ADICIONADO DO PRIMEIRO ARQUIVO
    createdAt: { type: Date, default: Date.now },
    lastLogin: Date,
    permissions: [String],
    acceptedConfidentiality: { type: Boolean, default: false },
    confidentialityAcceptedAt: Date
}, { 
    collection: 'staffs',
    timestamps: false
});

// Métodos do Staff (ADICIONADO DO PRIMEIRO ARQUIVO)
StaffSchema.methods.comparePassword = async function(password) {
    return await bcrypt.compare(password, this.password);
};

const Staff = mongoose.model('Staff', StaffSchema); // ADICIONADO: Criar o modelo Staff

const UserSchema = new mongoose.Schema({
    username: String,
    email: String,
    firstName: String,
    lastName: String,
    password: String,
    balance: { type: Number, default: 0 },
    bonusBalance: { type: Number, default: 0 },
    level: { type: String, default: 'Bronze' },
    country: String,
    newsletter: Boolean,
    totalWagered: { type: Number, default: 0 },
    totalWins: { type: Number, default: 0 },
    gamesPlayed: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    lastLogin: Date,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
    ipAddress: String,
    kycStatus: { type: String, default: 'pending' },
    depositLimit: { type: Number, default: 1000 },
    withdrawalLimit: { type: Number, default: 1000 }
}, { 
    collection: 'users',
    timestamps: false
});

const User = mongoose.model('User', UserSchema);

const UserNotificationSchema = new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    title: String,
    message: String,
    type: {
        type: String,
        enum: ['info', 'warning', 'danger', 'success', 'system'],
        default: 'info'
    },
    read: { type: Boolean, default: false },
    relatedTo: String,
    relatedId: mongoose.Schema.Types.ObjectId,
    createdAt: { type: Date, default: Date.now },
    metadata: Object
}, { collection: 'user_notifications' });

const UserNotification = mongoose.model('UserNotification', UserNotificationSchema);

const EmailLogSchema = new mongoose.Schema({
    to: [String],
    subject: String,
    template: String,
    sentBy: {
        staffId: String,
        staffName: String
    },
    sentAt: { type: Date, default: Date.now },
    status: {
        type: String,
        enum: ['sent', 'failed', 'pending'],
        default: 'pending'
    },
    error: String,
    playersCount: Number,
    message: String
}, { collection: 'email_logs' });

const EmailLog = mongoose.model('EmailLog', EmailLogSchema);

const WithdrawalSchema = new mongoose.Schema({
    playerId: mongoose.Schema.Types.ObjectId,
    playerName: String,
    playerEmail: String,
    amount: Number,
    currency: { type: String, default: 'EUR' },
    method: String,
    status: { 
        type: String, 
        enum: ['pending', 'approved', 'rejected', 'processing', 'cancelled'],
        default: 'pending'
    },
    accountDetails: {
        accountName: String,
        accountNumber: String,
        bankName: String,
        iban: String,
        swift: String
    },
    requestedAt: { type: Date, default: Date.now },
    processedAt: Date,
    processedBy: String,
    processorId: mongoose.Schema.Types.ObjectId,
    notes: String,
    transactionId: String,
    fee: { type: Number, default: 0 },
    netAmount: Number,
    playerBalanceBefore: Number,
    playerBalanceAfter: Number
}, { collection: 'withdrawals' });

const Withdrawal = mongoose.model('Withdrawal', WithdrawalSchema);

const PaymentSchema = new mongoose.Schema({
    playerId: mongoose.Schema.Types.ObjectId,
    playerName: String,
    playerEmail: String,
    amount: Number,
    currency: { type: String, default: 'EUR' },
    method: String,
    status: { 
        type: String, 
        enum: ['pending', 'approved', 'rejected', 'processing', 'cancelled'],
        default: 'pending'
    },
    transactionId: String,
    paymentDetails: {
        provider: String,
        reference: String,
        cardLast4: String,
        paymentMethod: String
    },
    requestedAt: { type: Date, default: Date.now },
    processedAt: Date,
    processedBy: String,
    processorId: mongoose.Schema.Types.ObjectId,
    notes: String,
    bonusGiven: { type: Number, default: 0 },
    playerBalanceBefore: Number,
    playerBalanceAfter: Number
}, { collection: 'payments' });

const Payment = mongoose.model('Payment', PaymentSchema);

const SupportTicketSchema = new mongoose.Schema({
    ticketId: { type: String, unique: true },
    playerId: mongoose.Schema.Types.ObjectId,
    playerName: String,
    playerEmail: String,
    subject: String,
    category: { 
        type: String, 
        enum: ['deposit', 'withdrawal', 'account', 'technical', 'game', 'bonus', 'other'],
        default: 'other'
    },
    priority: { 
        type: String, 
        enum: ['low', 'medium', 'high', 'urgent'],
        default: 'medium'
    },
    status: { 
        type: String, 
        enum: ['open', 'in_progress', 'resolved', 'closed'],
        default: 'open'
    },
    messages: [{
        senderType: { type: String, enum: ['player', 'staff'] },
        senderId: mongoose.Schema.Types.ObjectId,
        senderName: String,
        message: String,
        attachments: [String],
        timestamp: { type: Date, default: Date.now },
        read: { type: Boolean, default: false }
    }],
    assignedTo: {
        staffId: mongoose.Schema.Types.ObjectId,
        staffName: String
    },
    lastMessageAt: Date,
    createdAt: { type: Date, default: Date.now },
    resolvedAt: Date,
    closedAt: Date
}, { collection: 'support_tickets' });

const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);

const AlertSchema = new mongoose.Schema({
    type: {
        type: String,
        enum: ['security', 'fraud', 'withdrawal', 'payment', 'player', 'system', 'warning'],
        default: 'system'
    },
    severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'medium'
    },
    title: String,
    message: String,
    playerId: mongoose.Schema.Types.ObjectId,
    playerName: String,
    relatedTo: String,
    isResolved: { type: Boolean, default: false },
    resolvedBy: String,
    resolvedAt: Date,
    createdAt: { type: Date, default: Date.now },
    metadata: Object
}, { collection: 'alerts' });

const Alert = mongoose.model('Alert', AlertSchema);

const SystemLogSchema = new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    user: {
        name: String,
        email: String,
        role: String
    },
    action: {
        type: String,
        enum: ['login', 'logout', 'create', 'update', 'delete', 'view', 'approve', 'reject', 'system'],
        required: true
    },
    module: {
        type: String,
        enum: ['auth', 'players', 'withdrawals', 'payments', 'staff', 'support', 'settings', 'system', 'email', 'dashboard'],
        required: true
    },
    message: String,
    details: String,
    ip: String,
    userAgent: String,
    location: String,
    sessionId: String,
    metadata: Object,
    timestamp: { type: Date, default: Date.now },
    read: {
        type: Boolean,
        default: false
    }
}, { collection: 'system_logs' });

const SystemLog = mongoose.model('SystemLog', SystemLogSchema);

const SystemSettingSchema = new mongoose.Schema({
    key: { type: String, unique: true },
    value: mongoose.Schema.Types.Mixed,
    category: String,
    description: String,
    updatedBy: mongoose.Schema.Types.ObjectId,
    updatedAt: { type: Date, default: Date.now }
}, { collection: 'system_settings' });

const SystemSetting = mongoose.model('SystemSetting', SystemSettingSchema);

// ==============================
// SCHEMA PARA CHAT INTERNO - ATUALIZADO
// ==============================

const InternalMessageSchema = new mongoose.Schema({
    senderId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Staff', 
        required: true 
    },
    recipientId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Staff', 
        required: true 
    },
    message: { 
        type: String, 
        required: true, 
        trim: true 
    },
    read: { 
        type: Boolean, 
        default: false 
    },
    timestamp: { 
        type: Date, 
        default: Date.now 
    },
    // ADICIONADO: identificador único para evitar duplicação
    messageHash: {
        type: String,
        unique: true,
        sparse: true
    }
}, { 
    collection: 'internal_messages',
    timestamps: true 
});

// Índices (ADICIONADO DO PRIMEIRO ARQUIVO)
InternalMessageSchema.index({ senderId: 1, recipientId: 1 });
InternalMessageSchema.index({ recipientId: 1, read: 1 });
InternalMessageSchema.index({ messageHash: 1 }, { unique: true });

// Método estático para obter conversa (ADICIONADO DO PRIMEIRO ARQUIVO)
InternalMessageSchema.statics.getConversation = async function(userId1, userId2, limit = 100) {
    return this.find({
        $or: [
            { senderId: userId1, recipientId: userId2 },
            { senderId: userId2, recipientId: userId1 }
        ]
    })
    .sort({ timestamp: 1 })
    .limit(limit)
    .populate('senderId', 'name role photo')
    .populate('recipientId', 'name role photo')
    .lean();
};

// Método para marcar como lido (ADICIONADO DO PRIMEIRO ARQUIVO)
InternalMessageSchema.statics.markAsRead = async function(senderId, recipientId) {
    return this.updateMany(
        { senderId: senderId, recipientId: recipientId, read: false },
        { $set: { read: true } }
    );
};

// Método para contar não lidas (ADICIONADO DO PRIMEIRO ARQUIVO)
InternalMessageSchema.statics.countUnread = async function(userId) {
    return this.countDocuments({
        recipientId: userId,
        read: false
    });
};

const InternalMessage = mongoose.model('InternalMessage', InternalMessageSchema);

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

function getPlayerStatus(user) {
    if (!user.lastLogin) return 'offline';
    
    const lastLoginTime = new Date(user.lastLogin).getTime();
    const now = Date.now();
    const fifteenMinutes = 15 * 60 * 1000;
    
    if ((now - lastLoginTime) < fifteenMinutes) {
        return 'online';
    }
    return 'offline';
}

function formatPlayTime(ms) {
    if (!ms || ms < 0) return '0m';
    
    const seconds = Math.floor(ms / 1000);
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (hours > 0) {
        return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
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
            user: userData,
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
        
        const log = new SystemLog(logData);
        await log.save();
        
        return log;
    } catch (error) {
        console.error('Erro ao criar log:', error.message);
        return null;
    }
}

// ==============================
// WEBSOCKET - CORRIGIDO PARA EVITAR DUPLICAÇÃO
// ==============================

const wss = new WebSocket.Server({ server });

// Map para controlar conexões e evitar duplicação
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
            
            // Conectar ao chat interno
            if (data.type === 'chat_connect') {
                const userId = data.userId;
                
                // Remover conexões antigas para o mesmo usuário
                wss.clients.forEach(client => {
                    if (client !== ws && client.userId === userId && client.readyState === WebSocket.OPEN) {
                        console.log(`🔌 Fechando conexão duplicada para usuário ${userId}`);
                        client.close();
                    }
                });
                
                ws.userId = userId;
                activeConnections.set(userId, ws);
                
                console.log(`💬 Usuário ${userId} conectado ao chat`);
                
                // Atualizar status como online
                await Staff.findByIdAndUpdate(userId, {
                    isOnline: true,
                    lastActive: new Date()
                });
                
                // Notificar outros sobre o status online
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
            
            // Receber mensagem via WebSocket
            if (data.type === 'chat_message' && ws.userId) {
                const { recipientId, message: msgContent, messageId } = data;
                
                // Verificar se a mensagem já foi processada (evitar duplicação)
                const messageHash = `${ws.userId}-${recipientId}-${Date.now()}-${msgContent.substring(0, 20)}`;
                
                try {
                    // Salvar no banco de dados
                    const newMessage = new InternalMessage({
                        senderId: ws.userId,
                        recipientId: recipientId,
                        message: msgContent,
                        read: false,
                        timestamp: new Date(),
                        messageHash: messageHash
                    });
                    
                    await newMessage.save();
                    
                    // Enviar para o destinatário
                    wss.clients.forEach(client => {
                        if (client.readyState === WebSocket.OPEN && client.userId === recipientId) {
                            client.send(JSON.stringify({
                                type: 'chat_message',
                                messageId: newMessage._id,
                                senderId: ws.userId,
                                message: msgContent,
                                timestamp: newMessage.timestamp,
                                originalMessageId: messageId // Para o cliente identificar duplicações
                            }));
                        }
                    });
                    
                    // Confirmar para o remetente
                    ws.send(JSON.stringify({
                        type: 'chat_sent',
                        messageId: newMessage._id,
                        originalMessageId: messageId,
                        timestamp: newMessage.timestamp
                    }));
                    
                } catch (error) {
                    // Se houver erro de chave duplicada, significa que a mensagem já foi processada
                    if (error.code === 11000) {
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
            
            // Marcar mensagens como lidas via WebSocket
            if (data.type === 'mark_read' && ws.userId) {
                const { senderId } = data;
                
                await InternalMessage.updateMany(
                    { 
                        senderId: senderId, 
                        recipientId: ws.userId,
                        read: false 
                    },
                    { read: true }
                );
                
                // Notificar o remetente
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN && client.userId === senderId) {
                        client.send(JSON.stringify({
                            type: 'messages_read',
                            readerId: ws.userId,
                            timestamp: new Date()
                        }));
                    }
                });
            }
            
            // Indicador de digitação
            if (data.type === 'typing' && ws.userId) {
                const { recipientId, isTyping } = data;
                
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN && client.userId === recipientId) {
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
                // Broadcast para todos os clientes
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
            
            // Verificar se ainda há conexões ativas para este usuário
            const userStillConnected = Array.from(wss.clients).some(
                client => client.userId === ws.userId && client.readyState === WebSocket.OPEN
            );
            
            if (!userStillConnected) {
                // Atualizar status como offline
                await Staff.findByIdAndUpdate(ws.userId, {
                    isOnline: false,
                    lastActive: new Date()
                });
                
                // Notificar outros sobre o status offline
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN && client.userId && client.userId !== ws.userId) {
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
// MIDDLEWARES DE AUTENTICAÇÃO - ATUALIZADOS
// ==============================

const isAuthenticated = (req, res, next) => { // ADICIONADO DO PRIMEIRO ARQUIVO
    if (req.session && req.session.staff) {
        return next();
    }
    res.redirect('/login');
};

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
                if (err) {
                    console.error('Erro ao salvar permissões na sessão:', err);
                }
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

// ==============================
// ROTA TEMPORÁRIA PARA CORRIGIR SENHAS
// ==============================

app.get('/fix-passwords', async (req, res) => {
    try {
        console.log('🔧 Iniciando correção de senhas...');
        
        const staffs = await Staff.find({});
        console.log(`📊 Encontrados ${staffs.length} staffs`);
        
        let updatedCount = 0;
        let alreadyHashed = 0;
        
        for (const staff of staffs) {
            console.log(`📝 Verificando: ${staff.email}`);
            
            // Verificar se a senha já está hashada (bcrypt hash começa com $2)
            const isBcryptHash = staff.password && 
                (staff.password.startsWith('$2b$') || 
                 staff.password.startsWith('$2a$') || 
                 staff.password.startsWith('$2y$'));
            
            if (!isBcryptHash && staff.password) {
                console.log(`🔐 Hashando senha de: ${staff.email}`);
                const salt = await bcrypt.genSalt(10);
                const oldPassword = staff.password;
                staff.password = await bcrypt.hash(staff.password, salt);
                await staff.save();
                updatedCount++;
                console.log(`✅ Senha atualizada: ${staff.email} (${oldPassword} -> hash)`);
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
                <title>Correção de Senhas - B7Uno</title>
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
                    .info-box {
                        background: #f0f9ff;
                        border: 1px solid #bae6fd;
                        padding: 20px;
                        border-radius: 8px;
                        margin: 20px 0;
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
                    .btn:hover {
                        background: #1d4ed8;
                    }
                    .warning {
                        color: #dc2626;
                        font-size: 12px;
                        margin-top: 30px;
                        padding-top: 15px;
                        border-top: 1px solid #e5e7eb;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="success">✅ Correção de Senhas Concluída!</div>
                    
                    <div class="info-box">
                        <p><strong>Status:</strong> Todas as senhas foram verificadas e corrigidas.</p>
                        <p>Agora todos os staffs (antigos e novos) poderão fazer login corretamente.</p>
                    </div>
                    
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
                    
                    <div class="warning">
                        <strong>Importante:</strong> Após testar os logins, você pode remover esta rota do código.
                        Procure por "ROTA TEMPORÁRIA PARA CORRIGIR SENHAS" no server.js e remova essa seção.
                    </div>
                </div>
                
                <script>
                    console.log('Correção de senhas: ${updatedCount} atualizadas, ${alreadyHashed} já hashadas');
                </script>
            </body>
            </html>
        `);
    } catch (error) {
        console.error('💥 Erro ao corrigir senhas:', error);
        res.status(500).send(`
            <h1>❌ Erro</h1>
            <p>Erro ao corrigir senhas: ${error.message}</p>
            <p>Verifique o console do servidor para mais detalhes.</p>
        `);
    }
});

// ==============================
// ROTAS DE CONFIDENCIALIDADE
// ==============================

app.post('/api/confidentiality/accept', requireAuth, async (req, res) => {
    try {
        req.session.staff.acceptedConfidentiality = true;
        req.session.staff.confidentialityAcceptedAt = new Date();
        
        await Staff.findByIdAndUpdate(
            req.session.staff.id,
            {
                acceptedConfidentiality: true,
                confidentialityAcceptedAt: new Date()
            }
        );
        
        req.session.save(async (err) => {
            if (err) {
                console.error('❌ Erro ao salvar sessão:', err);
                return res.status(500).json({ success: false, error: 'Erro ao salvar sessão' });
            }
            
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
        const staff = await Staff.findById(req.session.staff.id)
            .select('acceptedConfidentiality confidentialityAcceptedAt');
            
        res.json({
            success: true,
            accepted: staff?.acceptedConfidentiality || false,
            acceptedAt: staff?.confidentialityAcceptedAt || null
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
        const result = await UserNotification.updateMany(
            { userId: req.session.staff.id, read: false },
            { read: true }
        );
        
        await Alert.updateMany(
            { isResolved: false },
            { isResolved: true }
        );
        
        res.json({ 
            success: true, 
            message: 'Todas as notificações foram marcadas como lidas',
            updatedCount: result.modifiedCount
        });
    } catch (error) {
        console.error('Erro ao marcar todas as notificações como lidas:', error);
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
        
        const result = await UserNotification.deleteMany({
            userId: req.session.staff.id,
            $or: [
                { read: true },
                { createdAt: { $lt: thirtyDaysAgo } }
            ]
        });
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'delete',
            'system',
            'Notificações limpas',
            `Foram eliminadas ${result.deletedCount} notificações`,
            req
        );
        
        res.json({ 
            success: true, 
            message: `Foram eliminadas ${result.deletedCount} notificações`,
            deletedCount: result.deletedCount
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
        
        const result = await UserNotification.deleteMany({
            userId: req.session.staff.id,
            $or: [
                { read: true },
                { createdAt: { $lt: thirtyDaysAgo } }
            ]
        });
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'delete',
            'system',
            'Notificações limpas',
            `Foram eliminadas ${result.deletedCount} notificações`,
            req
        );
        
        res.json({ 
            success: true, 
            message: `Foram eliminadas ${result.deletedCount} notificações`,
            deletedCount: result.deletedCount
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
        
        const stats = {
            total: await UserNotification.countDocuments({ userId }),
            unread: await UserNotification.countDocuments({ 
                userId, 
                read: false 
            }),
            read: await UserNotification.countDocuments({ 
                userId, 
                read: true 
            }),
            byType: await UserNotification.aggregate([
                { $match: { userId: mongoose.Types.ObjectId(userId) } },
                { $group: { 
                    _id: '$type', 
                    count: { $sum: 1 },
                    unread: {
                        $sum: { $cond: [{ $eq: ['$read', false] }, 1, 0] }
                    }
                }},
                { $sort: { count: -1 } }
            ]),
            recent: await UserNotification.find({ userId })
                .sort({ createdAt: -1 })
                .limit(5)
                .select('title type read createdAt')
                .lean()
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
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({
                success: false,
                error: 'ID de notificação inválido'
            });
        }
        
        const result = await UserNotification.findOneAndDelete({
            _id: req.params.id,
            userId: req.session.staff.id
        });
        
        if (!result) {
            return res.status(404).json({
                success: false,
                error: 'Notificação não encontrada ou não pertence ao utilizador'
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Notificação eliminada com sucesso',
            deletedId: req.params.id
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
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({
                success: false,
                error: 'ID de notificação inválido'
            });
        }
        
        const result = await UserNotification.findOneAndDelete({
            _id: req.params.id,
            userId: req.session.staff.id
        });
        
        if (!result) {
            return res.status(404).json({
                success: false,
                error: 'Notificação não encontrada ou não pertence ao utilizador'
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Notificação eliminada com sucesso',
            deletedId: req.params.id
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
// ROTAS DO CHAT INTERNO - CORRIGIDAS PARA EVITAR DUPLICAÇÃO
// ==============================

// GET: Obter todos os membros da equipa
app.get('/api/chat/staff', requireAuth, async (req, res) => {
    try {
        const currentUserId = req.session.staff.id;
        
        const staffMembers = await Staff.find({
            _id: { $ne: currentUserId },
            isActive: true
        })
        .select('name email role photo isOnline lastActive')
        .sort({ isOnline: -1, name: 1 })
        .lean();
        
        // Adicionar contagem de mensagens não lidas
        const staffWithUnread = await Promise.all(
            staffMembers.map(async (staff) => {
                const unreadCount = await InternalMessage.countDocuments({
                    senderId: staff._id,
                    recipientId: currentUserId,
                    read: false
                });
                
                return {
                    ...staff,
                    unreadCount,
                    lastActiveFormatted: new Date(staff.lastActive).toLocaleTimeString('pt-PT', {
                        hour: '2-digit',
                        minute: '2-digit'
                    })
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

// GET: Obter mensagens com um staff específico
app.get('/api/chat/messages/:staffId', requireAuth, async (req, res) => {
    try {
        const { staffId } = req.params;
        const currentUserId = req.session.staff.id;
        
        if (!mongoose.Types.ObjectId.isValid(staffId)) {
            return res.status(400).json({
                success: false,
                error: 'ID inválido'
            });
        }
        
        // Verificar se o staff existe
        const staffExists = await Staff.findById(staffId);
        if (!staffExists) {
            return res.status(404).json({
                success: false,
                error: 'Membro da equipa não encontrado'
            });
        }
        
        // Obter mensagens da conversa
        const messages = await InternalMessage.getConversation(currentUserId, staffId, 100);
        
        // Formatar mensagens
        const formattedMessages = messages.map(msg => ({
            _id: msg._id,
            senderId: msg.senderId._id,
            recipientId: msg.recipientId._id,
            message: msg.message,
            read: msg.read,
            timestamp: msg.timestamp,
            senderName: msg.senderId.name,
            senderPhoto: msg.senderId.photo,
            recipientName: msg.recipientId.name
        }));
        
        // Marcar mensagens como lidas
        await InternalMessage.markAsRead(staffId, currentUserId);
        
        res.json({
            success: true,
            messages: formattedMessages
        });
        
    } catch (error) {
        console.error('Erro ao obter mensagens:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao carregar mensagens'
        });
    }
});

// POST: Enviar mensagem - CORRIGIDO PARA EVITAR DUPLICAÇÃO
app.post('/api/chat/send', requireAuth, async (req, res) => {
    try {
        const { recipientId, message, clientMessageId } = req.body;
        const currentUserId = req.session.staff.id;
        
        // Validações
        if (!recipientId || !message || !message.trim()) {
            return res.status(400).json({
                success: false,
                error: 'Destinatário e mensagem são obrigatórios'
            });
        }
        
        if (recipientId === currentUserId) {
            return res.status(400).json({
                success: false,
                error: 'Não pode enviar mensagens para si mesmo'
            });
        }
        
        // Verificar se o destinatário existe
        const recipient = await Staff.findById(recipientId);
        if (!recipient) {
            return res.status(404).json({
                success: false,
                error: 'Destinatário não encontrado'
            });
        }
        
        // Gerar hash único para evitar duplicação
        const messageHash = `${currentUserId}-${recipientId}-${Date.now()}-${message.substring(0, 20).replace(/\s/g, '')}`;
        
        try {
            // Criar e salvar mensagem
            const newMessage = new InternalMessage({
                senderId: currentUserId,
                recipientId: recipientId,
                message: message.trim(),
                read: false,
                timestamp: new Date(),
                messageHash: messageHash
            });
            
            await newMessage.save();
            
            // Buscar dados completos para resposta
            const populatedMessage = await InternalMessage.findById(newMessage._id)
                .populate('senderId', 'name role photo')
                .populate('recipientId', 'name role photo')
                .lean();
            
            // Enviar notificação via WebSocket APENAS se o destinatário estiver online
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN && client.userId === recipientId) {
                    client.send(JSON.stringify({
                        type: 'chat_message',
                        messageId: newMessage._id,
                        senderId: currentUserId,
                        senderName: populatedMessage.senderId.name,
                        message: message.trim(),
                        timestamp: newMessage.timestamp,
                        clientMessageId: clientMessageId // Para identificar no cliente
                    }));
                }
            });
            
            // Atualizar status do remetente
            await Staff.findByIdAndUpdate(currentUserId, {
                lastActive: new Date()
            });
            
            res.json({
                success: true,
                message: 'Mensagem enviada com sucesso',
                data: {
                    _id: populatedMessage._id,
                    senderId: populatedMessage.senderId._id,
                    recipientId: populatedMessage.recipientId._id,
                    message: populatedMessage.message,
                    timestamp: populatedMessage.timestamp,
                    senderName: populatedMessage.senderId.name,
                    recipientName: populatedMessage.recipientId.name
                }
            });
            
        } catch (error) {
            // Se for erro de duplicação, retornar a mensagem existente
            if (error.code === 11000) {
                console.log('⚠️ Mensagem duplicada, retornando existente');
                
                // Buscar mensagem existente
                const existingMessage = await InternalMessage.findOne({ messageHash });
                if (existingMessage) {
                    const populatedMessage = await InternalMessage.findById(existingMessage._id)
                        .populate('senderId', 'name role photo')
                        .populate('recipientId', 'name role photo')
                        .lean();
                    
                    return res.json({
                        success: true,
                        message: 'Mensagem já enviada anteriormente',
                        data: {
                            _id: populatedMessage._id,
                            senderId: populatedMessage.senderId._id,
                            recipientId: populatedMessage.recipientId._id,
                            message: populatedMessage.message,
                            timestamp: populatedMessage.timestamp,
                            senderName: populatedMessage.senderId.name,
                            recipientName: populatedMessage.recipientId.name
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

// POST: Marcar mensagens como lidas
app.post('/api/chat/mark-read/:staffId', requireAuth, async (req, res) => {
    try {
        const { staffId } = req.params;
        const currentUserId = req.session.staff.id;
        
        await InternalMessage.markAsRead(staffId, currentUserId);
        
        // Notificar via WebSocket que as mensagens foram lidas
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN && client.userId === staffId) {
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

// GET: Contar mensagens não lidas
app.get('/api/chat/unread-count', requireAuth, async (req, res) => {
    try {
        const currentUserId = req.session.staff.id;
        const count = await InternalMessage.countUnread(currentUserId);
        
        res.json({
            success: true,
            count: count
        });
        
    } catch (error) {
        console.error('Erro ao contar mensagens não lidas:', error);
        res.status(500).json({
            success: false,
            error: 'Erro ao contar mensagens não lidas'
        });
    }
});

// NOVA ROTA: Atualizar status online
app.post('/api/chat/update-status', requireAuth, async (req, res) => {
    try {
        const { isOnline } = req.body;
        const currentUserId = req.session.staff.id;
        
        await Staff.findByIdAndUpdate(currentUserId, {
            isOnline: isOnline === true,
            lastActive: new Date()
        });
        
        // Notificar outros via WebSocket
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN && client.userId !== currentUserId) {
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

// NOVA ROTA: Obter conversas recentes
app.get('/api/chat/recent-conversations', requireAuth, async (req, res) => {
    try {
        const currentUserId = req.session.staff.id;
        
        const recentConversations = await InternalMessage.aggregate([
            {
                $match: {
                    $or: [
                        { senderId: mongoose.Types.ObjectId(currentUserId) },
                        { recipientId: mongoose.Types.ObjectId(currentUserId) }
                    ]
                }
            },
            {
                $sort: { timestamp: -1 }
            },
            {
                $group: {
                    _id: {
                        $cond: {
                            if: { $eq: ["$senderId", mongoose.Types.ObjectId(currentUserId)] },
                            then: "$recipientId",
                            else: "$senderId"
                        }
                    },
                    lastMessage: { $first: "$$ROOT" },
                    unreadCount: {
                        $sum: {
                            $cond: [
                                { 
                                    $and: [
                                        { $eq: ["$recipientId", mongoose.Types.ObjectId(currentUserId)] },
                                        { $eq: ["$read", false] }
                                    ]
                                },
                                1,
                                0
                            ]
                        }
                    }
                }
            },
            {
                $lookup: {
                    from: 'staffs',
                    localField: '_id',
                    foreignField: '_id',
                    as: 'staff'
                }
            },
            {
                $unwind: '$staff'
            },
            {
                $project: {
                    _id: 1,
                    staff: {
                        _id: '$staff._id',
                        name: '$staff.name',
                        role: '$staff.role',
                        photo: '$staff.photo',
                        isOnline: '$staff.isOnline',
                        lastActive: '$staff.lastActive'
                    },
                    lastMessage: {
                        _id: '$lastMessage._id',
                        message: '$lastMessage.message',
                        timestamp: '$lastMessage.timestamp',
                        senderId: '$lastMessage.senderId'
                    },
                    unreadCount: 1
                }
            },
            {
                $sort: { 'lastMessage.timestamp': -1 }
            },
            {
                $limit: 10
            }
        ]);
        
        res.json({
            success: true,
            conversations: recentConversations
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
// ATUALIZAR ROTA DE EMAIL PARA USAR CHAT INTERNO
// ==============================

// POST: Enviar email (convertido para chat interno)
app.post('/api/email/send', requireAuth, async (req, res) => {
    try {
        const { recipients, subject, message, clientMessageId } = req.body;
        const currentUserId = req.session.staff.id;
        const currentStaff = req.session.staff;
        
        // Se recipients for um ID de staff, enviar como mensagem interna
        if (mongoose.Types.ObjectId.isValid(recipients)) {
            const recipientStaff = await Staff.findById(recipients);
            if (recipientStaff) {
                // Gerar hash único para evitar duplicação
                const messageHash = `${currentUserId}-${recipients}-${Date.now()}-${subject.substring(0, 20).replace(/\s/g, '')}`;
                
                try {
                    // Criar mensagem interna
                    const newMessage = new InternalMessage({
                        senderId: currentUserId,
                        recipientId: recipients,
                        message: `📧 ${subject}: ${message}`,
                        read: false,
                        timestamp: new Date(),
                        messageHash: messageHash
                    });
                    
                    await newMessage.save();
                    
                    // Notificar via WebSocket APENAS se estiver online
                    wss.clients.forEach(client => {
                        if (client.readyState === WebSocket.OPEN && client.userId === recipients) {
                            client.send(JSON.stringify({
                                type: 'chat_message',
                                messageId: newMessage._id,
                                senderId: currentUserId,
                                senderName: currentStaff.name,
                                message: `📧 ${subject}: ${message}`,
                                timestamp: newMessage.timestamp,
                                clientMessageId: clientMessageId
                            }));
                        }
                    });
                    
                    return res.json({
                        success: true,
                        message: 'Mensagem interna enviada com sucesso',
                        type: 'internal',
                        messageId: newMessage._id
                    });
                } catch (error) {
                    if (error.code === 11000) {
                        // Mensagem duplicada, retornar sucesso
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
        
        // Se for um grupo, apenas registrar como log
        const emailLog = new EmailLog({
            to: [typeof recipients === 'string' ? recipients : 'Grupo de jogadores'],
            subject: subject,
            message: message,
            template: 'manual',
            sentBy: {
                staffId: currentUserId,
                staffName: currentStaff.name
            },
            status: 'sent',
            playersCount: 0
        });
        
        await emailLog.save();
        
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
// ROTAS DE LOGS DO SISTEMA
// ==============================

app.get('/api/logs', requireAuth, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        
        const filter = {};
        
        if (req.query.user) {
            filter['user._id'] = req.query.user;
        }
        
        if (req.query.action) {
            filter.action = req.query.action;
        }
        
        if (req.query.module) {
            filter.module = req.query.module;
        }
        
        if (req.query.dateFrom || req.query.dateTo) {
            filter.timestamp = {};
            
            if (req.query.dateFrom) {
                filter.timestamp.$gte = new Date(req.query.dateFrom);
            }
            
            if (req.query.dateTo) {
                const dateTo = new Date(req.query.dateTo);
                dateTo.setHours(23, 59, 59, 999);
                filter.timestamp.$lte = dateTo;
            }
        }
        
        if (req.query.search) {
            const searchRegex = new RegExp(req.query.search, 'i');
            filter.$or = [
                { message: searchRegex },
                { details: searchRegex },
                { ip: searchRegex },
                { 'user.name': searchRegex },
                { 'user.email': searchRegex }
            ];
        }
        
        const sortField = req.query.sort || 'timestamp';
        const sortOrder = req.query.order === 'asc' ? 1 : -1;
        const sort = { [sortField]: sortOrder };
        
        const total = await SystemLog.countDocuments(filter);
        
        const logs = await SystemLog.find(filter)
            .sort(sort)
            .skip(skip)
            .limit(limit)
            .lean();
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const last30Days = new Date();
        last30Days.setDate(last30Days.getDate() - 30);
        
        const todayLogs = await SystemLog.countDocuments({
            timestamp: { $gte: today }
        });
        
        const last30DaysLogs = await SystemLog.countDocuments({
            timestamp: { $gte: last30Days }
        });
        
        const twoHoursAgo = new Date();
        twoHoursAgo.setHours(twoHoursAgo.getHours() - 2);
        
        const activeAdmins = await SystemLog.distinct('user._id', {
            action: 'login',
            timestamp: { $gte: twoHoursAgo }
        });
        
        const oneHourAgo = new Date();
        oneHourAgo.setHours(oneHourAgo.getHours() - 1);
        
        const lastHourLogs = await SystemLog.countDocuments({
            timestamp: { $gte: oneHourAgo }
        });
        
        const activityRate = (lastHourLogs / 60).toFixed(1);
        
        res.json({
            success: true,
            logs: logs,
            page: page,
            pages: Math.ceil(total / limit),
            total: total,
            stats: {
                total: last30DaysLogs,
                today: todayLogs,
                activeAdmins: activeAdmins.length,
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
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({
                success: false,
                message: 'ID inválido'
            });
        }
        
        const log = await SystemLog.findById(req.params.id).lean();
        
        if (!log) {
            return res.status(404).json({
                success: false,
                message: 'Log não encontrado'
            });
        }
        
        res.json({
            success: true,
            log: log
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
        const usersWithLogs = await SystemLog.distinct('user', { 'user._id': { $exists: true } });
        
        let users = [];
        
        if (usersWithLogs && usersWithLogs.length > 0) {
            users = usersWithLogs;
        } else {
            const staffDocs = await Staff.find({ isActive: true }, 'name email role').lean();
            users = staffDocs.map(staff => ({
                _id: staff._id,
                name: staff.name,
                email: staff.email,
                role: staff.role
            }));
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
        await SystemLog.updateMany(
            { 'user._id': req.session.staff.id, read: false },
            { $set: { read: true } }
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
        
        const filter = {};
        
        if (req.query.user) {
            filter['user._id'] = req.query.user;
        }
        
        if (req.query.action) {
            filter.action = req.query.action;
        }
        
        if (req.query.module) {
            filter.module = req.query.module;
        }
        
        if (req.query.dateFrom || req.query.dateTo) {
            filter.timestamp = {};
            
            if (req.query.dateFrom) {
                filter.timestamp.$gte = new Date(req.query.dateFrom);
            }
            
            if (req.query.dateTo) {
                const dateTo = new Date(req.query.dateTo);
                dateTo.setHours(23, 59, 59, 999);
                filter.timestamp.$lte = dateTo;
            }
        }
        
        if (req.query.search) {
            const searchRegex = new RegExp(req.query.search, 'i');
            filter.$or = [
                { message: searchRegex },
                { details: searchRegex },
                { ip: searchRegex },
                { 'user.name': searchRegex },
                { 'user.email': searchRegex }
            ];
        }
        
        const logs = await SystemLog.find(filter)
            .sort({ timestamp: -1 })
            .lean();
        
        if (format === 'csv') {
            let csv = 'Data,Hora,Utilizador,Email,Cargo,Ação,Módulo,Mensagem,IP,Localização,User Agent\n';
            
            logs.forEach(log => {
                const date = new Date(log.timestamp);
                const dateStr = date.toLocaleDateString('pt-PT');
                const timeStr = date.toLocaleTimeString('pt-PT');
                
                csv += `"${dateStr}","${timeStr}","${log.user?.name || ''}","${log.user?.email || ''}","${log.user?.role || ''}","${log.action || ''}","${log.module || ''}","${log.message || ''}","${log.ip || ''}","${log.location || ''}","${log.userAgent || ''}"\n`;
            });
            
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', 'attachment; filename=logs.csv');
            res.send(csv);
            
        } else if (format === 'json') {
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', 'attachment; filename=logs.json');
            res.json(logs);
            
        } else if (format === 'pdf') {
            res.redirect(`/api/logs/export?format=csv&${req.query}`);
            
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
        
        const result = await SystemLog.deleteMany({
            timestamp: { $lt: ninetyDaysAgo }
        });
        
        res.json({
            success: true,
            message: `Foram eliminados ${result.deletedCount} logs antigos`,
            deletedCount: result.deletedCount
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
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({
                success: false,
                message: 'ID inválido'
            });
        }
        
        const log = await SystemLog.findById(req.params.id);
        
        if (!log) {
            return res.status(404).json({
                success: false,
                message: 'Log não encontrado'
            });
        }
        
        log.metadata = log.metadata || {};
        log.metadata.flagged = true;
        log.metadata.flaggedBy = req.session.staff.id;
        log.metadata.flaggedAt = new Date();
        log.metadata.reason = req.body.reason || 'Reportado por administrador';
        
        await log.save();
        
        await Alert.create({
            type: 'security',
            severity: 'medium',
            title: 'Log Reportado',
            message: `Log #${log._id.toString().slice(-6)} reportado por ${req.session.staff.name}`,
            metadata: {
                logId: log._id,
                reason: log.metadata.reason,
                logAction: log.action,
                logModule: log.module
            }
        });
        
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
// ROTAS PRINCIPAIS - ATUALIZADAS
// ==============================

app.get('/cleanup-sessions', async (req, res) => {
    if (process.env.NODE_ENV === 'production') {
        return res.status(403).send('Não disponível em produção');
    }
    
    try {
        const db = mongoose.connection.db;
        const result = await db.collection('admin_sessions').deleteMany({});
        
        if (req.session && req.session.destroy) {
            req.session.destroy(() => {
                res.send(`
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Sessões Limpas</title>
                        <style>
                            body { font-family: Arial, sans-serif; padding: 20px; }
                            .success { color: green; }
                        </style>
                    </head>
                    <body>
                        <h1 class="success">✅ Sessões limpas com sucesso!</h1>
                        <p>Admin Sessions: ${result.deletedCount} removidas</p>
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

app.get('/', (req, res) => {
    if (req.session && req.session.staff && req.session.staff.loggedIn) {
        return res.redirect('/dashboard');
    }
    res.redirect('/login');
});

// ========== PÁGINA DE LOGIN - ATUALIZADA ==========

app.get('/login', (req, res) => {
    if (req.session && req.session.staff && req.session.staff.loggedIn) {
        return res.redirect('/dashboard');
    }
    
    res.render('login', {
        title: 'Login - Casino B7uno Admin',
        error: req.query.error || (req.flash('error') || []).join(', '),
        email: req.query.email || '',
        user: null
    });
});

// Processar Login - VERSÃO CORRIGIDA
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            req.flash('error', 'Email e password são obrigatórios');
            return res.render('login', {
                title: 'Login - Casino B7uno Admin',
                error: 'Email e password são obrigatórios',
                email,
                user: null
            });
        }

        const staff = await Staff.findOne({ 
            email: { $regex: new RegExp(`^${email.trim()}$`, 'i') },
            isActive: { $ne: false }
        });
        
        if (!staff) {
            req.flash('error', 'Credenciais inválidas');
            return res.render('login', {
                title: 'Login - Casino B7uno Admin',
                error: 'Credenciais inválidas',
                email,
                user: null
            });
        }

        // CORREÇÃO: Comparar senha usando bcrypt.compare sempre
        let isValid = false;
        
        if (staff.password) {
            // Tentar comparar com bcrypt primeiro
            try {
                isValid = await bcrypt.compare(password, staff.password);
            } catch (bcryptError) {
                console.log('Tentando comparação direta para senha não-hashada');
                // Se falhar, pode ser senha em texto simples (para compatibilidade)
                isValid = (password === staff.password);
            }
        }
        
        if (!isValid) {
            req.flash('error', 'Credenciais inválidas');
            return res.render('login', {
                title: 'Login - Casino B7uno Admin',
                error: 'Credenciais inválidas',
                email,
                user: null
            });
        }

        let permissions = [];
        switch (staff.role) {
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

        // Atualizar status online
        staff.isOnline = true;
        staff.lastLogin = new Date();
        staff.lastActive = new Date();
        await staff.save();

        req.session.staff = {
            id: staff._id.toString(),
            name: staff.name,
            email: staff.email,
            role: staff.role || 'support',
            department: staff.department || 'Staff',
            photo: staff.photo || null,
            acceptedConfidentiality: staff.acceptedConfidentiality || false,
            confidentialityAcceptedAt: staff.confidentialityAcceptedAt || null,
            loggedIn: true,
            loginTime: new Date(),
            permissions: permissions
        };

        req.session.save(async (err) => {
            if (err) {
                req.flash('error', 'Erro ao iniciar sessão');
                return res.render('login', {
                    title: 'Login - Casino B7uno Admin',
                    error: 'Erro ao iniciar sessão',
                    email,
                    user: null
                });
            }

            await createSystemLog(
                staff._id,
                {
                    name: staff.name,
                    email: staff.email,
                    role: staff.role
                },
                'login',
                'auth',
                'Login realizado no sistema',
                null,
                req
            );

            await UserNotification.create({
                userId: staff._id,
                title: 'Bem-vindo ao Casino B7uno Admin!',
                message: `Login realizado com sucesso em ${new Date().toLocaleString('pt-PT')}`,
                type: 'success'
            });

            req.flash('success', `Bem-vindo, ${staff.name}!`);
            res.redirect('/dashboard');
        });
        
    } catch (error) {
        console.error('💥 Erro no login:', error);
        req.flash('error', 'Erro interno do servidor');
        res.render('login', {
            title: 'Login - Casino B7uno Admin',
            error: 'Erro interno do servidor',
            email: req.body.email || '',
            user: null
        });
    }
});

// ========== LOGOUT - ATUALIZADO ==========

app.get('/logout', async (req, res) => {
    const staffName = req.session?.staff?.name || 'Utilizador';
    
    // Atualizar status offline
    if (req.user) {
        try {
            req.user.isOnline = false;
            await req.user.save();
        } catch (error) {
            console.error('Erro ao atualizar status offline:', error);
        }
    }
    
    if (!req.session) {
        return res.render('logout', {
            title: 'Logout - Casino B7uno Admin',
            logoutMessage: 'Sessão já terminada',
            redirectTime: 3,
            redirectUrl: '/login'
        });
    }
    
    req.session.destroy((err) => {
        if (err) {
            console.error('❌ Erro no logout:', err);
            return res.render('logout', {
                title: 'Logout - Casino B7uno Admin',
                logoutMessage: 'Erro ao terminar sessão',
                redirectTime: 3,
                redirectUrl: '/login'
            });
        }
        
        res.clearCookie('casinox.admin.sid');
        
        res.render('logout', {
            title: 'Logout - Casino B7uno Admin',
            logoutMessage: `Sessão terminada com sucesso. Adeus, ${staffName}!`,
            redirectTime: 5,
            redirectUrl: '/login',
            homeUrl: '/',
            logoText: 'CASINO B7UNO',
            systemName: 'Sistema de Gestão Interno'
        });
    });
});

app.get('/logout-simple', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('casinox.admin.sid');
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
            
            res.clearCookie('casinox.admin.sid');
            
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
// ROTAS DE PERFIL API - NOVAS ROTAS ADICIONADAS
// ==============================

app.get('/api/auth/profile', requireAuth, async (req, res) => {
    try {
        if (!req.session.staff) {
            return res.status(401).json({ 
                success: false, 
                error: 'Não autenticado' 
            });
        }
        
        const staff = await Staff.findById(req.session.staff.id)
            .select('name email role department photo lastLogin isOnline lastActive');
        
        if (!staff) {
            return res.status(404).json({ 
                success: false, 
                error: 'Utilizador não encontrado' 
            });
        }
        
        res.json({
            success: true,
            user: {
                id: staff._id,
                name: staff.name,
                email: staff.email,
                role: staff.role,
                department: staff.department,
                photo: staff.photo,
                lastLogin: staff.lastLogin,
                isOnline: staff.isOnline,
                lastActive: staff.lastActive,
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

        const staff = await Staff.findOne({ 
            email: { $regex: new RegExp(`^${email.trim()}$`, 'i') },
            isActive: { $ne: false }
        });
        
        if (!staff) {
            return res.status(401).json({ 
                success: false, 
                error: 'Credenciais inválidas' 
            });
        }

        // CORREÇÃO: Comparar senha usando bcrypt.compare sempre
        let isValid = false;
        
        if (staff.password) {
            // Tentar comparar com bcrypt primeiro
            try {
                isValid = await bcrypt.compare(password, staff.password);
            } catch (bcryptError) {
                console.log('Tentando comparação direta para senha não-hashada');
                // Se falhar, pode ser senha em texto simples (para compatibilidade)
                isValid = (password === staff.password);
            }
        }
        
        if (!isValid) {
            return res.status(401).json({ 
                success: false, 
                error: 'Credenciais inválidas' 
            });
        }

        let permissions = [];
        switch (staff.role) {
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

        // Atualizar status online
        staff.isOnline = true;
        staff.lastLogin = new Date();
        staff.lastActive = new Date();
        await staff.save();

        req.session.staff = {
            id: staff._id.toString(),
            name: staff.name,
            email: staff.email,
            role: staff.role || 'support',
            department: staff.department || 'Staff',
            photo: staff.photo || null,
            acceptedConfidentiality: staff.acceptedConfidentiality || false,
            confidentialityAcceptedAt: staff.confidentialityAcceptedAt || null,
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
                staff._id,
                {
                    name: staff.name,
                    email: staff.email,
                    role: staff.role
                },
                'login',
                'auth',
                'Login realizado no sistema',
                null,
                req
            );

            await UserNotification.create({
                userId: staff._id,
                title: 'Bem-vindo ao Casino B7uno Admin!',
                message: `Login realizado com sucesso em ${new Date().toLocaleString('pt-PT')}`,
                type: 'success'
            });

            res.json({ 
                success: true, 
                message: `Bem-vindo, ${staff.name}!`,
                user: {
                    id: staff._id,
                    name: staff.name,
                    email: staff.email,
                    role: staff.role,
                    photo: staff.photo,
                    isOnline: staff.isOnline,
                    lastActive: staff.lastActive,
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
        const staff = await Staff.findById(req.session.staff.id);
        
        if (!staff) {
            req.flash('error', 'Utilizador não encontrado');
            return res.redirect('/logout');
        }
        
        const notifications = await UserNotification.find({ 
            userId: staff._id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();
        
        const userLogs = await SystemLog.find({ 
            userId: staff._id 
        })
        .sort({ timestamp: -1 })
        .limit(20)
        .lean();
        
        const userWithPhoto = {
            ...req.session.staff,
            photo: staff.photo || null
        };
        
        res.render('profile', {
            title: 'Meu Perfil - B7uno Admin',
            breadcrumb: 'Perfil',
            staff,
            notifications: {
                unreadCount: await UserNotification.countDocuments({ 
                    userId: staff._id,
                    read: false 
                }),
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
        
        const staff = await Staff.findById(req.session.staff.id);
        
        if (!staff) {
            return res.status(404).json({ 
                success: false, 
                message: 'Utilizador não encontrado' 
            });
        }
        
        const { name, username } = req.body;
        
        console.log('📝 Dados recebidos:', { name, username });
        console.log('📁 Ficheiro recebido:', req.file ? req.file.filename : 'Nenhum');
        
        staff.name = name || staff.name;
        
        if (req.file) {
            try {
                if (staff.photo) {
                    const oldPhotoPath = path.join(__dirname, 'public', 'uploads', staff.photo);
                    if (fs.existsSync(oldPhotoPath)) {
                        fs.unlinkSync(oldPhotoPath);
                        console.log(`🗑️ Foto antiga removida: ${staff.photo}`);
                    }
                }
                
                staff.photo = req.file.filename;
                
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
        
        await staff.save();
        
        req.session.staff.name = staff.name;
        req.session.save();
        
        await createSystemLog(
            staff._id,
            {
                name: staff.name,
                email: staff.email,
                role: staff.role
            },
            'update',
            'auth',
            'Perfil atualizado',
            JSON.stringify({
                name: staff.name,
                photo: staff.photo ? 'atualizada' : 'mantida'
            }),
            req
        );
        
        console.log(`✅ Perfil atualizado para ${staff.name}`);
        
        res.json({
            success: true,
            message: 'Perfil atualizado com sucesso!',
            photo: staff.photo,
            user: {
                name: staff.name,
                email: staff.email,
                photo: staff.photo
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

app.get('/uploads/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'public', 'uploads', filename);
    
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.status(404).json({ error: 'Imagem não encontrada' });
    }
});

// ==============================
// DASHBOARD - ATUALIZADO
// ==============================

app.get('/dashboard', requireAuth, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
        const onlineUsers = await User.countDocuments({ 
            lastLogin: { $gte: fifteenMinutesAgo },
            isActive: true
        });

        const stats = {
            totalPlayers: totalUsers,
            onlinePlayers: onlineUsers,
            pendingWithdrawals: await Withdrawal.countDocuments({ status: 'pending' }),
            pendingPayments: await Payment.countDocuments({ status: 'pending' }),
            openTickets: await SupportTicket.countDocuments({ status: 'open' }),
            unresolvedAlerts: await Alert.countDocuments({ isResolved: false })
        };

        const withdrawalsResult = await Withdrawal.aggregate([
            { $match: { status: 'pending' } },
            { $group: { _id: null, totalAmount: { $sum: '$amount' } } }
        ]);
        
        stats.withdrawalsAmount = withdrawalsResult[0] ? withdrawalsResult[0].totalAmount : 0;
        stats.playerPercentage = stats.totalPlayers > 0 ? 
            Math.round((stats.onlinePlayers / stats.totalPlayers) * 100) : 0;

        const recentUsers = await User.find({ isActive: true })
            .sort({ lastLogin: -1 })
            .limit(5)
            .select('username email firstName lastName balance lastLogin');

        const recentPlayers = recentUsers.map(user => ({
            playerId: user._id,
            name: `${user.firstName || ''} ${user.lastName || ''}`.trim() || user.username,
            email: user.email,
            status: getPlayerStatus(user),
            balance: user.balance || 0,
            lastActivity: user.lastLogin
        }));

        const recentWithdrawals = await Withdrawal.find({ status: 'pending' })
            .sort({ requestedAt: -1 })
            .limit(5)
            .select('playerName amount currency method requestedAt');

        const recentPayments = await Payment.find({ status: 'pending' })
            .sort({ requestedAt: -1 })
            .limit(5)
            .select('playerName amount currency method requestedAt');

        const recentTickets = await SupportTicket.find({ status: 'open' })
            .sort({ createdAt: -1 })
            .limit(5)
            .select('ticketId playerName subject category priority createdAt');

        const recentAlerts = await Alert.find({ isResolved: false })
            .sort({ createdAt: -1 })
            .limit(5)
            .select('title message type severity createdAt');

        const staff = await Staff.findById(req.session.staff.id)
            .select('acceptedConfidentiality confidentialityAcceptedAt');
        
        const acceptedConfidentiality = staff?.acceptedConfidentiality || false;

        const notifications = await UserNotification.find({ 
            userId: req.session.staff.id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();

        res.render('dashboard', {
            title: 'Dashboard - Casino B7uno Admin',
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
                unreadCount: await UserNotification.countDocuments({ 
                    userId: req.session.staff.id,
                    read: false 
                }),
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar dashboard:', error);
        req.flash('error', 'Erro ao carregar dashboard');
        
        res.render('dashboard', {
            title: 'Dashboard - Casino B7uno Admin',
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
        const totalUsers = await User.countDocuments();
        const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
        const onlineUsers = await User.countDocuments({ 
            lastLogin: { $gte: fifteenMinutesAgo },
            isActive: true
        });

        const stats = {
            totalPlayers: totalUsers,
            onlinePlayers: onlineUsers,
            pendingWithdrawals: await Withdrawal.countDocuments({ status: 'pending' }),
            pendingPayments: await Payment.countDocuments({ status: 'pending' }),
            unresolvedAlerts: await Alert.countDocuments({ isResolved: false }),
            playerPercentage: totalUsers > 0 ? Math.round((onlineUsers / totalUsers) * 100) : 0
        };

        const withdrawalsResult = await Withdrawal.aggregate([
            { $match: { status: 'pending' } },
            { $group: { _id: null, totalAmount: { $sum: '$amount' } } }
        ]);
        
        stats.withdrawalsAmount = withdrawalsResult[0] ? withdrawalsResult[0].totalAmount : 0;

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
        const alerts = await Alert.find({ isResolved: false })
            .sort({ createdAt: -1 })
            .limit(20)
            .select('title message type severity createdAt')
            .lean();
            
        const userNotifications = await UserNotification.find({ 
            userId: req.session.staff.id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();
        
        const notifications = [
            ...alerts.map((alert, index) => ({
                id: alert._id.toString(),
                title: alert.title,
                message: alert.message,
                type: alert.severity === 'critical' ? 'danger' : 
                      alert.severity === 'high' ? 'warning' : 'info',
                read: false,
                createdAt: alert.createdAt,
                source: 'system'
            })),
            ...userNotifications.map(notification => ({
                id: notification._id.toString(),
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
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({
                success: false,
                message: 'ID inválido'
            });
        }
        
        const result = await UserNotification.findOneAndUpdate(
            { _id: req.params.id, userId: req.session.staff.id },
            { read: true },
            { new: true }
        );
        
        if (result) {
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
        await UserNotification.updateMany(
            { userId: req.session.staff.id, read: false },
            { read: true }
        );
        
        res.json({ success: true, message: 'Todas as notificações foram marcadas como lidas' });
    } catch (error) {
        console.error('Erro ao marcar notificações:', error);
        res.json({ success: false, error: 'Erro interno' });
    }
});

app.get('/api/test-notification', requireAuth, async (req, res) => {
    try {
        const notification = new UserNotification({
            userId: req.session.staff.id,
            title: 'Notificação de Teste',
            message: `Esta é uma notificação de teste criada em ${new Date().toLocaleTimeString('pt-PT')}`,
            type: 'info'
        });
        
        await notification.save();
        
        broadcastNotification({
            id: notification._id.toString(),
            title: notification.title,
            message: notification.message,
            type: notification.type,
            createdAt: notification.createdAt
        });
        
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
        const skip = (page - 1) * limit;
        const status = req.query.status || 'all';
        const search = req.query.search || '';
        const sort = req.query.sort || 'lastLogin';
        const order = req.query.order === 'asc' ? 1 : -1;

        let query = { isActive: { $ne: false } };
        
        if (status === 'online') {
            query.lastLogin = { $gte: new Date(Date.now() - 15 * 60 * 1000) };
        } else if (status === 'offline') {
            query.$or = [
                { lastLogin: { $lt: new Date(Date.now() - 15 * 60 * 1000) } },
                { lastLogin: { $exists: false } }
            ];
        } else if (status === 'active') {
            query.isActive = true;
        } else if (status === 'inactive') {
            query.isActive = false;
        }

        if (search) {
            query.$or = [
                { username: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } }
            ];
        }

        const users = await User.find(query)
            .sort({ [sort]: order })
            .skip(skip)
            .limit(limit)
            .select('username email firstName lastName balance level country lastLogin createdAt isActive totalWagered totalWins gamesPlayed newsletter kycStatus');

        const totalUsers = await User.countDocuments(query);
        const totalPages = Math.ceil(totalUsers / limit);

        const players = users.map(user => {
            const status = getPlayerStatus(user);
            
            return {
                _id: user._id,
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
            online: await User.countDocuments({ 
                lastLogin: { $gte: new Date(Date.now() - 15 * 60 * 1000) },
                isActive: true 
            }),
            active: await User.countDocuments({ isActive: true }),
            withNewsletter: await User.countDocuments({ newsletter: true }),
            kycVerified: await User.countDocuments({ kycStatus: 'verified' })
        };

        const notifications = await UserNotification.find({ 
            userId: req.session.staff.id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();

        res.render('players', {
            title: 'Gestão de Jogadores',
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
                unreadCount: await UserNotification.countDocuments({ 
                    userId: req.session.staff.id,
                    read: false 
                }),
                notifications: notifications
            }
        });
        
    } catch (error) {
        console.error('Erro ao carregar jogadores:', error);
        req.flash('error', 'Erro ao carregar jogadores');
        
        res.render('players', {
            title: 'Gestão de Jogadores',
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
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            req.flash('error', 'ID de jogador inválido');
            return res.status(404).render('error', {
                title: 'Jogador não encontrado',
                message: 'O jogador não existe ou foi removido.',
                user: req.session.staff
            });
        }
        
        const player = await User.findById(req.params.id);
        
        if (!player) {
            req.flash('error', 'Jogador não encontrado');
            return res.status(404).render('error', {
                title: 'Jogador não encontrado',
                message: 'O jogador não existe ou foi removido.',
                user: req.session.staff
            });
        }

        const deposits = await Payment.find({ playerId: player._id })
            .sort({ requestedAt: -1 })
            .limit(10);

        const withdrawals = await Withdrawal.find({ playerId: player._id })
            .sort({ requestedAt: -1 })
            .limit(10);

        const tickets = await SupportTicket.find({ playerId: player._id })
            .sort({ createdAt: -1 })
            .limit(10);

        const totalDeposits = await Payment.aggregate([
            { $match: { playerId: player._id, status: 'approved' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);

        const totalWithdrawals = await Withdrawal.aggregate([
            { $match: { playerId: player._id, status: 'approved' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);

        const notifications = await UserNotification.find({ 
            userId: req.session.staff.id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();

        res.render('player-details', {
            title: `Detalhes do Jogador - ${player.username}`,
            breadcrumb: 'Jogadores / Detalhes',
            player,
            deposits,
            withdrawals,
            tickets,
            stats: {
                totalDeposits: totalDeposits[0]?.total || 0,
                totalWithdrawals: totalWithdrawals[0]?.total || 0,
                netProfit: (totalDeposits[0]?.total || 0) - (totalWithdrawals[0]?.total || 0)
            },
            user: req.session.staff,
            notifications: {
                unreadCount: await UserNotification.countDocuments({ 
                    userId: req.session.staff.id,
                    read: false 
                }),
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
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ success: false, error: 'ID de jogador inválido' });
        }
        
        const { balance, isActive, kycStatus, notes } = req.body;
        
        const updateData = {};
        if (balance !== undefined) updateData.balance = parseFloat(balance);
        if (isActive !== undefined) updateData.isActive = isActive === 'true';
        if (kycStatus !== undefined) updateData.kycStatus = kycStatus;
        
        const player = await User.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true }
        );
        
        if (!player) {
            return res.status(404).json({ success: false, error: 'Jogador não encontrado' });
        }
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'update',
            'players',
            `Jogador atualizado: ${player.username}`,
            JSON.stringify(updateData),
            req
        );
        
        res.json({ success: true, player });
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
        const skip = (page - 1) * limit;
        const status = req.query.status || 'all';
        const method = req.query.method || 'all';
        const search = req.query.search || '';
        const sort = req.query.sort || 'requestedAt';
        const order = req.query.order === 'asc' ? 1 : -1;

        let query = {};
        
        if (status !== 'all') {
            query.status = status;
        }
        
        if (method !== 'all') {
            query.method = method;
        }
        
        if (search) {
            query.$or = [
                { playerName: { $regex: search, $options: 'i' } },
                { playerEmail: { $regex: search, $options: 'i' } },
                { transactionId: { $regex: search, $options: 'i' } }
            ];
        }

        const withdrawals = await Withdrawal.find(query)
            .sort({ [sort]: order })
            .skip(skip)
            .limit(limit)
            .populate('playerId', 'username firstName lastName')
            .lean();

        const totalWithdrawals = await Withdrawal.countDocuments(query);
        const totalPages = Math.ceil(totalWithdrawals / limit);

        const stats = {
            total: totalWithdrawals,
            pending: await Withdrawal.countDocuments({ status: 'pending' }),
            approved: await Withdrawal.countDocuments({ status: 'approved' }),
            rejected: await Withdrawal.countDocuments({ status: 'rejected' }),
            processing: await Withdrawal.countDocuments({ status: 'processing' })
        };

        const pendingTotal = await Withdrawal.aggregate([
            { $match: { status: 'pending' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);

        const approvedTotal = await Withdrawal.aggregate([
            { $match: { status: 'approved' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);

        stats.pendingAmount = pendingTotal[0]?.total || 0;
        stats.approvedAmount = approvedTotal[0]?.total || 0;

        const notifications = await UserNotification.find({ 
            userId: req.session.staff.id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();

        res.render('withdrawals', {
            title: 'Gestão de Levantamentos',
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
                unreadCount: await UserNotification.countDocuments({ 
                    userId: req.session.staff.id,
                    read: false 
                }),
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar levantamentos:', error);
        req.flash('error', 'Erro ao carregar levantamentos');
        
        res.render('withdrawals', {
            title: 'Gestão de Levantamentos',
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
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            req.flash('error', 'ID de levantamento inválido');
            return res.status(404).render('error', {
                title: 'Levantamento não encontrado',
                message: 'O levantamento não existe ou foi removido.',
                user: req.session.staff
            });
        }
        
        const withdrawal = await Withdrawal.findById(req.params.id)
            .populate('playerId', 'username email firstName lastName balance')
            .lean();
        
        if (!withdrawal) {
            req.flash('error', 'Levantamento não encontrado');
            return res.status(404).render('error', {
                title: 'Levantamento não encontrado',
                message: 'O levantamento não existe ou foi removido.',
                user: req.session.staff
            });
        }

        const logs = await SystemLog.find({
            $or: [
                { 'metadata.withdrawalId': req.params.id },
                { details: { $regex: req.params.id } }
            ]
        })
        .sort({ timestamp: -1 })
        .limit(20);

        const notifications = await UserNotification.find({ 
            userId: req.session.staff.id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();

        res.render('withdrawal-details', {
            title: `Levantamento #${withdrawal._id.toString().slice(-6)}`,
            breadcrumb: 'Levantamentos / Detalhes',
            withdrawal,
            logs,
            user: req.session.staff,
            notifications: {
                unreadCount: await UserNotification.countDocuments({ 
                    userId: req.session.staff.id,
                    read: false 
                }),
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
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ success: false, error: 'ID de levantamento inválido' });
        }
        
        const { action, notes } = req.body;
        const withdrawal = await Withdrawal.findById(req.params.id);
        
        if (!withdrawal) {
            return res.status(404).json({ success: false, error: 'Levantamento não encontrado' });
        }
        
        if (!['approved', 'rejected', 'processing'].includes(action)) {
            return res.status(400).json({ success: false, error: 'Ação inválida' });
        }
        
        const player = await User.findById(withdrawal.playerId);
        
        if (!player) {
            return res.status(404).json({ success: false, error: 'Jogador não encontrado' });
        }
        
        const playerBalanceBefore = player.balance;
        
        if (action === 'approved') {
            if (player.balance < withdrawal.amount) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Saldo insuficiente do jogador' 
                });
            }
            
            player.balance -= withdrawal.amount;
            await player.save();
            
            withdrawal.playerBalanceBefore = playerBalanceBefore;
            withdrawal.playerBalanceAfter = player.balance;
        }
        
        withdrawal.status = action;
        withdrawal.processedAt = new Date();
        withdrawal.processedBy = req.session.staff.name;
        withdrawal.processorId = req.session.staff.id;
        withdrawal.notes = notes || withdrawal.notes;
        
        await withdrawal.save();
        
        await Alert.create({
            type: 'withdrawal',
            severity: action === 'rejected' ? 'medium' : 'low',
            title: `Levantamento ${action === 'approved' ? 'Aprovado' : 'Rejeitado'}`,
            message: `Levantamento de €${withdrawal.amount} ${action === 'approved' ? 'aprovado' : 'rejeitado'} para ${withdrawal.playerName}`,
            playerId: withdrawal.playerId,
            playerName: withdrawal.playerName,
            relatedTo: withdrawal._id
        });
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            action === 'approved' ? 'approve' : 'reject',
            'withdrawals',
            `Levantamento ${action === 'approved' ? 'aprovado' : 'rejeitado'}: €${withdrawal.amount} - ${withdrawal.playerName}`,
            JSON.stringify({
                withdrawalId: withdrawal._id,
                amount: withdrawal.amount,
                playerBalanceBefore,
                playerBalanceAfter: player.balance,
                notes
            }),
            req
        );
        
        res.json({ 
            success: true, 
            message: `Levantamento ${action === 'approved' ? 'aprovado' : 'rejeitado'} com sucesso`,
            withdrawal 
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
        const skip = (page - 1) * limit;
        const status = req.query.status || 'all';
        const method = req.query.method || 'all';
        const search = req.query.search || '';
        const sort = req.query.sort || 'requestedAt';
        const order = req.query.order === 'asc' ? 1 : -1;

        let query = {};
        
        if (status !== 'all') {
            query.status = status;
        }
        
        if (method !== 'all') {
            query.method = method;
        }
        
        if (search) {
            query.$or = [
                { playerName: { $regex: search, $options: 'i' } },
                { playerEmail: { $regex: search, $options: 'i' } },
                { transactionId: { $regex: search, $options: 'i' } }
            ];
        }

        const payments = await Payment.find(query)
            .sort({ [sort]: order })
            .skip(skip)
            .limit(limit)
            .populate('playerId', 'username firstName lastName')
            .lean();

        const totalPayments = await Payment.countDocuments(query);
        const totalPages = Math.ceil(totalPayments / limit);

        const stats = {
            total: totalPayments,
            pending: await Payment.countDocuments({ status: 'pending' }),
            approved: await Payment.countDocuments({ status: 'approved' }),
            rejected: await Payment.countDocuments({ status: 'rejected' }),
            processing: await Payment.countDocuments({ status: 'processing' })
        };

        const pendingTotal = await Payment.aggregate([
            { $match: { status: 'pending' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);

        const approvedTotal = await Payment.aggregate([
            { $match: { status: 'approved' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);

        stats.pendingAmount = pendingTotal[0]?.total || 0;
        stats.approvedAmount = approvedTotal[0]?.total || 0;

        const notifications = await UserNotification.find({ 
            userId: req.session.staff.id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();

        res.render('payments', {
            title: 'Gestão de Pagamentos',
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
                unreadCount: await UserNotification.countDocuments({ 
                    userId: req.session.staff.id,
                    read: false 
                }),
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar pagamentos:', error);
        req.flash('error', 'Erro ao carregar pagamentos');
        
        res.render('payments', {
            title: 'Gestão de Pagamentos',
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
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            req.flash('error', 'ID de pagamento inválido');
            return res.status(404).render('error', {
                title: 'Pagamento não encontrado',
                message: 'O pagamento não existe ou foi removido.',
                user: req.session.staff
            });
        }
        
        const payment = await Payment.findById(req.params.id)
            .populate('playerId', 'username email firstName lastName balance bonusBalance')
            .lean();
        
        if (!payment) {
            req.flash('error', 'Pagamento não encontrado');
            return res.status(404).render('error', {
                title: 'Pagamento não encontrado',
                message: 'O pagamento não existe ou foi removido.',
                user: req.session.staff
            });
        }

        const logs = await SystemLog.find({
            $or: [
                { 'metadata.paymentId': req.params.id },
                { details: { $regex: req.params.id } }
            ]
        })
        .sort({ timestamp: -1 })
        .limit(20);

        const notifications = await UserNotification.find({ 
            userId: req.session.staff.id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();

        res.render('payment-details', {
            title: `Pagamento #${payment._id.toString().slice(-6)}`,
            breadcrumb: 'Pagamentos / Detalhes',
            payment,
            logs,
            user: req.session.staff,
            notifications: {
                unreadCount: await UserNotification.countDocuments({ 
                    userId: req.session.staff.id,
                    read: false 
                }),
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
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ success: false, error: 'ID de pagamento inválido' });
        }
        
        const { action, notes, bonusAmount } = req.body;
        const payment = await Payment.findById(req.params.id);
        
        if (!payment) {
            return res.status(404).json({ success: false, error: 'Pagamento não encontrado' });
        }
        
        if (!['approved', 'rejected', 'processing'].includes(action)) {
            return res.status(400).json({ success: false, error: 'Ação inválida' });
        }
        
        const player = await User.findById(payment.playerId);
        
        if (!player) {
            return res.status(404).json({ success: false, error: 'Jogador não encontrado' });
        }
        
        const playerBalanceBefore = player.balance;
        
        if (action === 'approved') {
            player.balance += payment.amount;
            
            const bonus = parseFloat(bonusAmount) || 0;
            if (bonus > 0) {
                player.bonusBalance = (player.bonusBalance || 0) + bonus;
                payment.bonusGiven = bonus;
            }
            
            await player.save();
            
            payment.playerBalanceBefore = playerBalanceBefore;
            payment.playerBalanceAfter = player.balance;
        }
        
        payment.status = action;
        payment.processedAt = new Date();
        payment.processedBy = req.session.staff.name;
        payment.processorId = req.session.staff.id;
        payment.notes = notes || payment.notes;
        
        await payment.save();
        
        await Alert.create({
            type: 'payment',
            severity: 'low',
            title: `Pagamento ${action === 'approved' ? 'Aprovado' : 'Rejeitado'}`,
            message: `Pagamento de €${payment.amount} ${action === 'approved' ? 'aprovado' : 'rejeitado'} para ${payment.playerName}`,
            playerId: payment.playerId,
            playerName: payment.playerName,
            relatedTo: payment._id
        });
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            action === 'approved' ? 'approve' : 'reject',
            'payments',
            `Pagamento ${action === 'approved' ? 'aprovado' : 'rejeitado'}: €${payment.amount} - ${payment.playerName}`,
            JSON.stringify({
                paymentId: payment._id,
                amount: payment.amount,
                bonus: bonusAmount || 0,
                playerBalanceBefore,
                playerBalanceAfter: player.balance,
                notes
            }),
            req
        );
        
        res.json({ 
            success: true, 
            message: `Pagamento ${action === 'approved' ? 'aprovado' : 'rejeitado'} com sucesso`,
            payment 
        });
    } catch (error) {
        console.error('Erro ao processar pagamento:', error);
        res.status(500).json({ success: false, error: 'Erro ao processar pagamento' });
    }
});

// ==============================
// ROTAS DE STAFF - CORRIGIDAS
// ==============================



app.get('/staff', requireAuth, requirePermission('view_staff'), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        const role = req.query.role || 'all';
        const status = req.query.status || 'all';
        const search = req.query.search || '';
        const sort = req.query.sort || 'name';
        const order = req.query.order === 'asc' ? 1 : -1;

        let query = { isActive: { $ne: false } };
        
        if (role !== 'all') {
            query.role = role;
        }
        
        if (status !== 'all') {
            query.isActive = status === 'active';
        }
        
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { department: { $regex: search, $options: 'i' } }
            ];
        }

        const staffMembers = await Staff.find(query)
            .sort({ [sort]: order })
            .skip(skip)
            .limit(limit)
            .select('name email role department photo isActive isOnline lastActive lastLogin createdAt')
            .lean();

        const totalStaff = await Staff.countDocuments(query);
        const totalPages = Math.ceil(totalStaff / limit);

        const stats = {
            total: totalStaff,
            active: await Staff.countDocuments({ isActive: true }),
            admins: await Staff.countDocuments({ role: 'admin' }),
            support: await Staff.countDocuments({ role: { $in: ['support', 'support_manager'] } }),
            finance: await Staff.countDocuments({ role: 'finance' }),
            moderator: await Staff.countDocuments({ role: 'moderator' }),
            viewer: await Staff.countDocuments({ role: 'viewer' })
        };

        const roleOptions = [
            { value: 'admin', label: 'Administrador' },
            { value: 'support_manager', label: 'Gestor de Suporte' },
            { value: 'support', label: 'Suporte' },
            { value: 'finance', label: 'Financeiro' },
            { value: 'moderator', label: 'Moderador' },
            { value: 'viewer', label: 'Visualizador' }
        ];

        const notifications = await UserNotification.find({ 
            userId: req.session.staff.id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();

        res.render('staff', {
            title: 'Gestão de Staff',
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
                unreadCount: await UserNotification.countDocuments({ 
                    userId: req.session.staff.id,
                    read: false 
                }),
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
            title: 'Gestão de Staff',
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
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            req.flash('error', 'ID de staff inválido');
            return res.status(404).render('error', {
                title: 'Staff não encontrado',
                message: 'O membro da equipe não existe ou foi removido.',
                user: req.session.staff
            });
        }
        
        const staffMember = await Staff.findById(req.params.id)
            .select('-password')
            .lean();
        
        if (!staffMember) {
            req.flash('error', 'Membro da equipe não encontrado');
            return res.status(404).render('error', {
                title: 'Staff não encontrado',
                message: 'O membro da equipe não existe ou foi removido.',
                user: req.session.staff
            });
        }

        const staffLogs = await SystemLog.find({ 
            userId: staffMember._id 
        })
        .sort({ timestamp: -1 })
        .limit(20)
        .lean();

        const assignedTickets = await SupportTicket.countDocuments({ 
            'assignedTo.staffId': staffMember._id 
        });

        const processedWithdrawals = await Withdrawal.countDocuments({ 
            processorId: staffMember._id 
        });

        const processedPayments = await Payment.countDocuments({ 
            processorId: staffMember._id 
        });

        const stats = {
            assignedTickets,
            processedWithdrawals,
            processedPayments,
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

        const notifications = await UserNotification.find({ 
            userId: req.session.staff.id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();

        res.render('staff-details', {
            title: `Detalhes do Staff - ${staffMember.name}`,
            breadcrumb: 'Staff / Detalhes',
            staffMember,
            staffLogs,
            stats,
            roleOptions,
            user: req.session.staff,
            notifications: {
                unreadCount: await UserNotification.countDocuments({ 
                    userId: req.session.staff.id,
                    read: false 
                }),
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

// CORREÇÃO: Rota para criar staff - ADICIONADO HASH DE SENHA
app.post('/api/staff/create', requireAuth, requirePermission('manage_staff'), async (req, res) => {
    try {
        const { name, email, role, department, password } = req.body;
        
        if (!name || !email || !role || !password) {
            return res.status(400).json({ success: false, error: 'Dados incompletos' });
        }
        
        const existingStaff = await Staff.findOne({ 
            email: { $regex: new RegExp(`^${email.trim()}$`, 'i') }
        });
        
        if (existingStaff) {
            return res.status(400).json({ success: false, error: 'Email já está em uso' });
        }
        
        // CORREÇÃO: Garantir que a senha seja hashada
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const newStaff = new Staff({
            name,
            email,
            role,
            department: department || 'Staff',
            password: hashedPassword, // Agora está hashada corretamente
            isActive: true,
            isOnline: false,
            lastActive: new Date()
        });
        
        await newStaff.save();
        
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
            staff: newStaff
        });
    } catch (error) {
        console.error('Erro ao criar staff:', error);
        res.status(500).json({ success: false, error: 'Erro ao criar staff' });
    }
});

app.post('/api/staff/:id/update', requireAuth, requirePermission('manage_staff'), async (req, res) => {
    try {
        const { name, email, role, department, isActive, isOnline } = req.body;
        const staffId = req.params.id;
        
        if (!mongoose.Types.ObjectId.isValid(staffId)) {
            return res.status(400).json({ success: false, error: 'ID de staff inválido' });
        }
        
        const staff = await Staff.findById(staffId);
        
        if (!staff) {
            return res.status(404).json({ success: false, error: 'Staff não encontrado' });
        }
        
        if (email && email !== staff.email) {
            const existingStaff = await Staff.findOne({ 
                email: { $regex: new RegExp(`^${email.trim()}$`, 'i') },
                _id: { $ne: staffId }
            });
            
            if (existingStaff) {
                return res.status(400).json({ success: false, error: 'Email já está em uso' });
            }
        }
        
        const updateData = {};
        if (name !== undefined) updateData.name = name;
        if (email !== undefined) updateData.email = email;
        if (role !== undefined) updateData.role = role;
        if (department !== undefined) updateData.department = department;
        if (isActive !== undefined) updateData.isActive = isActive === 'true';
        if (isOnline !== undefined) {
            updateData.isOnline = isOnline === 'true';
            if (isOnline === 'true') {
                updateData.lastActive = new Date();
            }
        }
        
        const updatedStaff = await Staff.findByIdAndUpdate(
            staffId,
            updateData,
            { new: true }
        ).select('-password');
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'update',
            'staff',
            `Staff atualizado: ${updatedStaff.name}`,
            JSON.stringify(updateData),
            req
        );
        
        res.json({ 
            success: true, 
            message: 'Staff atualizado com sucesso!',
            staff: updatedStaff
        });
    } catch (error) {
        console.error('Erro ao atualizar staff:', error);
        res.status(500).json({ success: false, error: 'Erro ao atualizar staff' });
    }
});

app.post('/api/staff/:id/delete', requireAuth, requirePermission('manage_staff'), async (req, res) => {
    try {
        const staffId = req.params.id;
        
        if (!mongoose.Types.ObjectId.isValid(staffId)) {
            return res.status(400).json({ success: false, error: 'ID de staff inválido' });
        }
        
        if (staffId === req.session.staff.id) {
            return res.status(400).json({ 
                success: false, 
                error: 'Não pode eliminar a sua própria conta' 
            });
        }
        
        const staff = await Staff.findById(staffId);
        
        if (!staff) {
            return res.status(404).json({ success: false, error: 'Staff não encontrado' });
        }
        
        staff.isActive = false;
        staff.isOnline = false;
        await staff.save();
        
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


// ==============================
// NOVO ENDPOINT: ELIMINAÇÃO PERMANENTE
// ==============================



app.delete('/api/staff/:id/permanent', requireAuth, requirePermission('manage_staff'), async (req, res) => {
    try {
        const staffId = req.params.id;
        
        if (!mongoose.Types.ObjectId.isValid(staffId)) {
            return res.status(400).json({ 
                success: false, 
                error: 'ID de staff inválido' 
            });
        }
        
        // Verificar se está a tentar eliminar a própria conta
        if (staffId === req.session.staff.id) {
            return res.status(400).json({ 
                success: false, 
                error: 'Não pode eliminar a sua própria conta' 
            });
        }
        
        const staff = await Staff.findById(staffId);
        
        if (!staff) {
            return res.status(404).json({ 
                success: false, 
                error: 'Staff não encontrado' 
            });
        }
        
        // Guardar informações para o log
        const staffName = staff.name;
        const staffEmail = staff.email;
        
        // Eliminar permanentemente da base de dados
        await Staff.findByIdAndDelete(staffId);
        
        // Criar log do sistema
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
        
        // Criar alerta no sistema
        await Alert.create({
            type: 'security',
            severity: 'high',
            title: 'Staff Eliminado Permanentemente',
            message: `Staff ${staffName} foi eliminado permanentemente do sistema por ${req.session.staff.name}`,
            metadata: {
                staffId: staffId,
                staffName: staffName,
                eliminatedBy: req.session.staff.name,
                eliminatedAt: new Date().toISOString()
            }
        });
        
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
// ROTAS DE SUPORTE - ATUALIZADAS PARA O NOVO TEMPLATE
// ==============================

app.get('/support', requireAuth, requirePermission('view_support'), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        
        const status = req.query.status || 'all';
        const priority = req.query.priority || 'all';
        const category = req.query.category || 'all';
        const search = req.query.search || '';
        
        let query = {};
        
        if (status !== 'all') {
            query.status = status === 'in-progress' ? 'in_progress' : status;
        }
        
        if (priority !== 'all') {
            query.priority = priority;
        }
        
        if (category !== 'all') {
            query.category = category;
        }
        
        if (search) {
            query.$or = [
                { ticketId: { $regex: search, $options: 'i' } },
                { playerName: { $regex: search, $options: 'i' } },
                { playerEmail: { $regex: search, $options: 'i' } },
                { subject: { $regex: search, $options: 'i' } },
                { 'messages.message': { $regex: search, $options: 'i' } }
            ];
        }

        const tickets = await SupportTicket.find(query)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .populate('playerId', 'username email')
            .populate('assignedTo.staffId', 'name email')
            .lean();

        const totalTickets = await SupportTicket.countDocuments(query);
        const totalPages = Math.ceil(totalTickets / limit);

        const stats = {
            total: await SupportTicket.countDocuments({}),
            open: await SupportTicket.countDocuments({ status: 'open' }),
            inProgress: await SupportTicket.countDocuments({ status: 'in_progress' }),
            assigned: await SupportTicket.countDocuments({ 'assignedTo.staffId': { $ne: null } }),
            resolved: await SupportTicket.countDocuments({ status: 'resolved' })
        };

        const notifications = await UserNotification.find({ 
            userId: req.session.staff.id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();

        res.render('suporte', {
            title: 'Suporte Técnico',
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
                unreadCount: await UserNotification.countDocuments({ 
                    userId: req.session.staff.id,
                    read: false 
                }),
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar tickets de suporte:', error);
        req.flash('error', 'Erro ao carregar tickets de suporte');
        
        res.render('suporte', {
            title: 'Suporte Técnico',
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

// GET ticket details
app.get('/api/tickets/:id', requireAuth, async (req, res) => {
    try {
        const ticketId = req.params.id;
        
        if (!mongoose.Types.ObjectId.isValid(ticketId)) {
            return res.status(400).json({ 
                success: false, 
                error: 'ID de ticket inválido' 
            });
        }
        
        const ticket = await SupportTicket.findById(ticketId)
            .populate('playerId', 'username email firstName lastName')
            .populate('assignedTo.staffId', 'name email')
            .lean();
        
        if (!ticket) {
            return res.status(404).json({ 
                success: false, 
                error: 'Ticket não encontrado' 
            });
        }
        
        res.json({
            success: true,
            ticket: {
                id: ticket._id,
                ticketId: ticket.ticketId,
                subject: ticket.subject,
                email: ticket.playerEmail || (ticket.playerId ? ticket.playerId.email : ''),
                category: ticket.category,
                priority: ticket.priority === 'urgent' ? 'Urgente' : 
                         ticket.priority === 'high' ? 'Alta' :
                         ticket.priority === 'medium' ? 'Média' : 'Baixa',
                status: ticket.status === 'in_progress' ? 'Em Progresso' : 
                        ticket.status === 'resolved' ? 'Resolvido' : 
                        ticket.status === 'closed' ? 'Fechado' : 'Aberto',
                createdAt: new Date(ticket.createdAt).toLocaleString('pt-PT'),
                updatedAt: new Date(ticket.updatedAt || ticket.createdAt).toLocaleString('pt-PT'),
                message: ticket.messages && ticket.messages.length > 0 ? 
                        ticket.messages[0].message : 'Sem mensagem',
                responses: ticket.messages ? ticket.messages.filter(m => m.senderType === 'staff').map(m => ({
                    sender: m.senderName || 'Suporte',
                    message: m.message,
                    time: new Date(m.timestamp).toLocaleTimeString('pt-PT', {hour: '2-digit', minute:'2-digit'}),
                    date: new Date(m.timestamp).toLocaleDateString('pt-PT')
                })) : [],
                assignedTo: ticket.assignedTo ? ticket.assignedTo.staffName : 'Não atribuído'
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

// CREATE ticket
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
        
        const user = await User.findOne({ email: customerEmail });
        
        const newTicket = new SupportTicket({
            ticketId,
            playerId: user ? user._id : null,
            playerName: user ? `${user.firstName || ''} ${user.lastName || ''}`.trim() || user.username : 'Cliente',
            playerEmail: customerEmail,
            subject,
            category: category || 'other',
            priority: priority || 'medium',
            status: 'open',
            messages: [{
                senderType: 'staff',
                senderId: req.session.staff.id,
                senderName: createdBy || req.session.staff.name,
                message,
                timestamp: new Date()
            }],
            createdAt: new Date(),
            lastMessageAt: new Date()
        });
        
        await newTicket.save();
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'create',
            'support',
            `Ticket criado: ${subject}`,
            `Ticket #${ticketId} criado para ${customerEmail}`,
            req
        );
        
        await Alert.create({
            type: 'system',
            severity: 'medium',
            title: 'Novo Ticket Criado',
            message: `Ticket #${ticketId} criado por ${createdBy || req.session.staff.name}`,
            relatedTo: newTicket._id,
            metadata: {
                ticketId: newTicket.ticketId,
                createdBy: createdBy || req.session.staff.name
            }
        });
        
        res.json({
            success: true,
            message: 'Ticket criado com sucesso!',
            ticketId: newTicket.ticketId,
            ticket: newTicket
        });
    } catch (error) {
        console.error('Erro ao criar ticket:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro ao criar ticket: ' + error.message 
        });
    }
});

// ASSIGN ticket
app.post('/api/tickets/:id/assign', requireAuth, async (req, res) => {
    try {
        const ticketId = req.params.id;
        const { assignedTo, message, assignedBy } = req.body;
        
        if (!mongoose.Types.ObjectId.isValid(ticketId)) {
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
        
        const ticket = await SupportTicket.findById(ticketId);
        
        if (!ticket) {
            return res.status(404).json({ 
                success: false, 
                error: 'Ticket não encontrado' 
            });
        }
        
        let staffMember = null;
        
        if (assignedTo === req.session.staff.name) {
            staffMember = await Staff.findById(req.session.staff.id);
        } else {
            staffMember = await Staff.findOne({ 
                name: { $regex: new RegExp(`^${assignedTo}$`, 'i') }
            });
        }
        
        ticket.assignedTo = {
            staffId: staffMember ? staffMember._id : null,
            staffName: assignedTo
        };
        
        if (ticket.status === 'open') {
            ticket.status = 'in_progress';
        }
        
        if (message) {
            ticket.messages.push({
                senderType: 'staff',
                senderId: req.session.staff.id,
                senderName: assignedBy || req.session.staff.name,
                message: `Ticket atribuído a ${assignedTo}. ${message}`,
                timestamp: new Date()
            });
        }
        
        ticket.lastMessageAt = new Date();
        await ticket.save();
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'update',
            'support',
            `Ticket #${ticket.ticketId} atribuído a ${assignedTo}`,
            message || 'Sem mensagem adicional',
            req
        );
        
        res.json({
            success: true,
            message: `Ticket atribuído a ${assignedTo} com sucesso!`,
            ticket
        });
    } catch (error) {
        console.error('Erro ao atribuir ticket:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro ao atribuir ticket' 
        });
    }
});

// ESCALATE ticket
app.post('/api/tickets/:id/escalate', requireAuth, async (req, res) => {
    try {
        const ticketId = req.params.id;
        const { escalateTo, reason, description, escalatedBy } = req.body;
        
        if (!mongoose.Types.ObjectId.isValid(ticketId)) {
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
        
        const ticket = await SupportTicket.findById(ticketId);
        
        if (!ticket) {
            return res.status(404).json({ 
                success: false, 
                error: 'Ticket não encontrado' 
            });
        }
        
        ticket.priority = 'urgent';
        
        const escalateMessage = `Ticket escalonado para ${escalateTo}. Motivo: ${reason}. ${description ? `Descrição: ${description}` : ''}`;
        
        ticket.messages.push({
            senderType: 'staff',
            senderId: req.session.staff.id,
            senderName: escalatedBy || req.session.staff.name,
            message: escalateMessage,
            timestamp: new Date()
        });
        
        ticket.lastMessageAt = new Date();
        await ticket.save();
        
        await createSystemLog(
            req.session.staff.id,
            req.session.staff,
            'update',
            'support',
            `Ticket #${ticket.ticketId} escalonado para ${escalateTo}`,
            `Motivo: ${reason}`,
            req
        );
        
        await Alert.create({
            type: 'system',
            severity: 'high',
            title: 'Ticket Escalonado',
            message: `Ticket #${ticket.ticketId} escalonado para ${escalateTo} por ${escalatedBy || req.session.staff.name}`,
            relatedTo: ticket._id,
            metadata: {
                ticketId: ticket.ticketId,
                escalatedTo: escalateTo,
                reason: reason
            }
        });
        
        res.json({
            success: true,
            message: `Ticket escalonado para ${escalateTo} com sucesso!`,
            ticket
        });
    } catch (error) {
        console.error('Erro ao escalonar ticket:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro ao escalonar ticket' 
        });
    }
});

// CLOSE ticket
app.post('/api/tickets/:id/close', requireAuth, async (req, res) => {
    try {
        const ticketId = req.params.id;
        const { closedBy, closedAt } = req.body;
        
        if (!mongoose.Types.ObjectId.isValid(ticketId)) {
            return res.status(400).json({ 
                success: false, 
                error: 'ID de ticket inválido' 
            });
        }
        
        const ticket = await SupportTicket.findById(ticketId);
        
        if (!ticket) {
            return res.status(404).json({ 
                success: false, 
                error: 'Ticket não encontrado' 
            });
        }
        
        ticket.status = 'closed';
        ticket.closedAt = closedAt ? new Date(closedAt) : new Date();
        
        ticket.messages.push({
            senderType: 'staff',
            senderId: req.session.staff.id,
            senderName: closedBy || req.session.staff.name,
            message: 'Ticket fechado pelo suporte.',
            timestamp: new Date()
        });
        
        await ticket.save();
        
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
            message: 'Ticket fechado com sucesso!',
            ticket
        });
    } catch (error) {
        console.error('Erro ao fechar ticket:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Erro ao fechar ticket' 
        });
    }
});

// RESPOND to ticket
app.post('/api/tickets/:id/respond', requireAuth, async (req, res) => {
    try {
        const ticketId = req.params.id;
        const { message, status, respondedBy } = req.body;
        
        if (!mongoose.Types.ObjectId.isValid(ticketId)) {
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
        
        const ticket = await SupportTicket.findById(ticketId);
        
        if (!ticket) {
            return res.status(404).json({ 
                success: false, 
                error: 'Ticket não encontrado' 
            });
        }
        
        ticket.messages.push({
            senderType: 'staff',
            senderId: req.session.staff.id,
            senderName: respondedBy || req.session.staff.name,
            message,
            timestamp: new Date()
        });
        
        if (status) {
            ticket.status = status === 'in-progress' ? 'in_progress' : 
                           status === 'resolved' ? 'resolved' : 
                           status === 'open' ? 'open' : ticket.status;
            
            if (status === 'resolved') {
                ticket.resolvedAt = new Date();
            }
        }
        
        if (!ticket.assignedTo) {
            ticket.assignedTo = {
                staffId: req.session.staff.id,
                staffName: respondedBy || req.session.staff.name
            };
        }
        
        ticket.lastMessageAt = new Date();
        await ticket.save();
        
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
            message: 'Resposta enviada com sucesso!',
            ticket
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
// ROTAS DE EMAIL - ATUALIZADAS COM CHAT INTERNO
// ==============================

app.get('/email', requireAuth, requirePermission('view_email'), async (req, res) => {
    try {
        const currentUserId = req.session.staff.id;
        
        // Buscar todos os staff (exceto o próprio)
        const staffMembers = await Staff.find({
            _id: { $ne: currentUserId },
            isActive: true
        })
        .select('name email role photo isOnline lastActive')
        .sort({ isOnline: -1, name: 1 })
        .lean();
        
        // Contar mensagens não lidas
        const unreadInternalCount = await InternalMessage.countDocuments({
            recipientId: currentUserId,
            read: false
        });
        
        // Buscar conversas recentes
        const recentConversations = await InternalMessage.aggregate([
            {
                $match: {
                    $or: [
                        { senderId: mongoose.Types.ObjectId(currentUserId) },
                        { recipientId: mongoose.Types.ObjectId(currentUserId) }
                    ]
                }
            },
            {
                $sort: { timestamp: -1 }
            },
            {
                $limit: 5
            },
            {
                $lookup: {
                    from: 'staffs',
                    localField: 'senderId',
                    foreignField: '_id',
                    as: 'sender'
                }
            },
            {
                $lookup: {
                    from: 'staffs',
                    localField: 'recipientId',
                    foreignField: '_id',
                    as: 'recipient'
                }
            },
            {
                $unwind: '$sender'
            },
            {
                $unwind: '$recipient'
            },
            {
                $project: {
                    _id: 1,
                    message: 1,
                    timestamp: 1,
                    read: 1,
                    sender: {
                        _id: '$sender._id',
                        name: '$sender.name',
                        photo: '$sender.photo'
                    },
                    recipient: {
                        _id: '$recipient._id',
                        name: '$recipient.name',
                        photo: '$recipient.photo'
                    },
                    isFromMe: {
                        $eq: ['$sender._id', mongoose.Types.ObjectId(currentUserId)]
                    }
                }
            }
        ]);
        
        const emailLogs = await EmailLog.find()
            .sort({ sentAt: -1 })
            .limit(10);

        const totalPlayers = await User.countDocuments({ isActive: true });
        const playersWithEmail = await User.countDocuments({ 
            isActive: true, 
            email: { $exists: true, $ne: '' } 
        });

        const newsletterSubscribers = await User.countDocuments({ 
            isActive: true, 
            newsletter: true,
            email: { $exists: true, $ne: '' } 
        });

        const notifications = await UserNotification.find({ 
            userId: currentUserId 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();

        res.render('email', {
            title: 'Sistema de Comunicação',
            breadcrumb: 'Comunicação',
            emailLogs,
            stats: {
                totalPlayers,
                playersWithEmail,
                newsletterSubscribers
            },
            user: req.session.staff,
            notifications: {
                unreadCount: await UserNotification.countDocuments({ 
                    userId: currentUserId,
                    read: false 
                }),
                notifications: notifications
            },
            staffMembers: staffMembers,
            unreadInternalCount: unreadInternalCount || 0,
            recentConversations: recentConversations || []
        });
    } catch (error) {
        console.error('Erro ao carregar página de email:', error);
        req.flash('error', 'Erro ao carregar página de email');
        
        res.render('email', {
            title: 'Sistema de Comunicação',
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
// ROTAS DE EMAIL - API ADICIONAIS
// ==============================

app.get('/api/email/stats', requireAuth, async (req, res) => {
    try {
        const totalPlayers = await User.countDocuments({ isActive: true });
        const playersWithEmail = await User.countDocuments({ 
            isActive: true, 
            email: { $exists: true, $ne: '' } 
        });
        const newsletterSubscribers = await User.countDocuments({ 
            isActive: true, 
            newsletter: true,
            email: { $exists: true, $ne: '' } 
        });

        res.json({
            success: true,
            totalPlayers,
            playersWithEmail,
            newsletterSubscribers
        });
    } catch (error) {
        console.error('Erro ao buscar estatísticas de email:', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar estatísticas' });
    }
});

app.get('/api/email/logs', requireAuth, async (req, res) => {
    try {
        const emailLogs = await EmailLog.find()
            .sort({ sentAt: -1 })
            .limit(50)
            .lean();

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
        let query = { isActive: true, email: { $exists: true, $ne: '' } };

        if (type === 'all') {
            // Todos os jogadores com email
        } else if (type === 'newsletter') {
            query.newsletter = true;
        } else if (type === 'vip') {
            query.level = { $in: ['VIP', 'Gold', 'Platinum', 'Diamond'] };
        } else if (type === 'active') {
            const thirtyDaysAgo = new Date();
            thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
            query.lastLogin = { $gte: thirtyDaysAgo };
        }

        const players = await User.find(query)
            .select('_id username email firstName lastName level lastLogin')
            .limit(500)
            .lean();

        res.json({
            success: true,
            players: players.map(player => ({
                _id: player._id,
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
        const skip = (page - 1) * limit;
        
        const filters = {};
        if (req.query.user) filters['user._id'] = req.query.user;
        if (req.query.action) filters.action = req.query.action;
        if (req.query.module) filters.module = req.query.module;
        if (req.query.search) {
            filters.$or = [
                { 'user.name': { $regex: req.query.search, $options: 'i' } },
                { message: { $regex: req.query.search, $options: 'i' } },
                { ip: { $regex: req.query.search, $options: 'i' } }
            ];
        }
        
        if (req.query.dateFrom || req.query.dateTo) {
            filters.timestamp = {};
            if (req.query.dateFrom) {
                filters.timestamp.$gte = new Date(req.query.dateFrom);
            }
            if (req.query.dateTo) {
                const dateTo = new Date(req.query.dateTo);
                dateTo.setHours(23, 59, 59, 999);
                filters.timestamp.$lte = dateTo;
            }
        }
        
        const sortField = req.query.sort || 'timestamp';
        const sortOrder = req.query.order === 'asc' ? 1 : -1;
        const sort = { [sortField]: sortOrder };
        
        const unreadLogs = await SystemLog.countDocuments({ read: false });
        
        const logs = await SystemLog.find(filters)
            .sort(sort)
            .skip(skip)
            .limit(limit)
            .lean();
        
        const totalLogs = await SystemLog.countDocuments(filters);
        const totalPages = Math.ceil(totalLogs / limit);
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const stats = {
            total: totalLogs,
            today: await SystemLog.countDocuments({ timestamp: { $gte: today } }),
            byAction: await SystemLog.aggregate([
                { $group: { _id: '$action', count: { $sum: 1 } } },
                { $sort: { count: -1 } }
            ]),
            byModule: await SystemLog.aggregate([
                { $group: { _id: '$module', count: { $sum: 1 } } },
                { $sort: { count: -1 } }
            ])
        };
        
        const users = await SystemLog.distinct('user', { 'user._id': { $exists: true } });
        
        const actionOptions = ['login', 'logout', 'create', 'update', 'delete', 'view', 'approve', 'reject', 'system'];
        const moduleOptions = ['auth', 'players', 'withdrawals', 'payments', 'staff', 'support', 'settings', 'system', 'email', 'dashboard'];
        
        const notifications = await UserNotification.find({ 
            userId: req.session.staff.id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();

        res.render('logs', {
            title: 'Logs do Sistema',
            breadcrumb: 'Logs',
            logs,
            stats,
            users: users.filter(u => u && u.name),
            actionOptions,
            moduleOptions,
            currentPage: page,
            totalPages,
            limit,
            filters: req.query,
            user: req.session.staff,
            unreadLogs,
            notifications: {
                unreadCount: await UserNotification.countDocuments({ 
                    userId: req.session.staff.id,
                    read: false 
                }),
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar logs:', error);
        req.flash('error', 'Erro ao carregar logs');
        
        res.render('logs', {
            title: 'Logs do Sistema',
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
// ROTAS DE DEFINIÇÕES
// ==============================

app.get('/settings', requireAuth, requirePermission('view_settings'), async (req, res) => {
    try {
        const settings = await SystemSetting.find().lean();
        
        const settingsByCategory = {};
        settings.forEach(setting => {
            if (!settingsByCategory[setting.category]) {
                settingsByCategory[setting.category] = [];
            }
            settingsByCategory[setting.category].push(setting);
        });
        
        const categories = ['general', 'email', 'security', 'payment', 'withdrawal', 'notification'];
        
        const notifications = await UserNotification.find({ 
            userId: req.session.staff.id 
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();

        res.render('settings', {
            title: 'Definições do Sistema',
            breadcrumb: 'Definições',
            settingsByCategory,
            categories,
            user: req.session.staff,
            notifications: {
                unreadCount: await UserNotification.countDocuments({ 
                    userId: req.session.staff.id,
                    read: false 
                }),
                notifications: notifications
            }
        });
    } catch (error) {
        console.error('Erro ao carregar definições:', error);
        req.flash('error', 'Erro ao carregar definições');
        
        res.render('settings', {
            title: 'Definições do Sistema',
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
        
        const updates = [];
        
        for (const [key, value] of Object.entries(settings)) {
            updates.push({
                updateOne: {
                    filter: { key },
                    update: { 
                        $set: { 
                            value,
                            updatedBy: staff.id,
                            updatedAt: new Date()
                        }
                    },
                    upsert: true
                }
            });
        }
        
        if (updates.length > 0) {
            await SystemSetting.bulkWrite(updates);
            
            await createSystemLog(
                staff.id,
                staff,
                'update',
                'settings',
                'Definições do sistema atualizadas',
                `Alteradas ${updates.length} definições`,
                req
            );
        }
        
        res.json({ success: true, message: 'Definições guardadas com sucesso' });
    } catch (error) {
        console.error('Erro ao guardar definições:', error);
        res.status(500).json({ success: false, error: 'Erro ao guardar definições' });
    }
});


// ==============================
// ROTAS ADICIONAIS E DE TESTE
// ==============================

app.get('/favicon.ico', (req, res) => {
    res.status(204).end();
});

app.use('/public', express.static(path.join(__dirname, 'public')));

app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
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
            <title>WebSocket Test</title>
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
            <h1>WebSocket Test</h1>
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
// HANDLERS DE ERRO
// ==============================

app.use((req, res) => {
    res.status(404).render('error', {
        title: 'Página Não Encontrada',
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
        title: 'Erro Interno',
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
    console.log(`🎰 CASINO B7UNO ADMIN DASHBOARD COMPLETO`);
    console.log(`=========================================`);
    console.log(`📡 Porta: ${PORT}`);
    console.log(`🌐 URL: http://localhost:${PORT}`);
    console.log(`📊 MongoDB Atlas: CONECTADO`);
    console.log(`📡 WebSocket: ws://localhost:${PORT}`);
    console.log(`📁 Uploads: ${uploadsDir}`);
    console.log(`=========================================`);
    console.log(`✅ SISTEMA MIGRADO PARA MONGODB ATLAS!`);
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