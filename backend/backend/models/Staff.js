const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const StaffSchema = new mongoose.Schema({
    // Informações básicas
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    
    // Permissões e funções
    role: {
        type: String,
        enum: ['admin', 'support_manager', 'support', 'finance', 'moderator', 'viewer'],
        default: 'support'
    },
    department: {
        type: String,
        default: 'Staff'
    },
    
    // Informações de perfil
    photo: {
        type: String,
        default: null
    },
    phone: {
        type: String,
        default: null
    },
    
    // Status e atividade
    isActive: {
        type: Boolean,
        default: true
    },
    isOnline: {
        type: Boolean,
        default: false
    },
    lastActive: {
        type: Date,
        default: Date.now
    },
    socketId: {
        type: String,
        default: null
    },
    
    // Datas importantes
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastLogin: {
        type: Date
    },
    
    // Permissões específicas
    permissions: [{
        type: String,
        enum: [
            'view_players',
            'edit_players',
            'view_withdrawals',
            'approve_withdrawals',
            'view_deposits',
            'process_deposits',
            'send_emails',
            'view_logs',
            'manage_staff',
            'manage_settings',
            'access_chat',
            'view_financial_reports',
            'manage_bonuses',
            'view_support_tickets',
            'manage_support_tickets'
        ]
    }],
    
    // Confidencialidade
    acceptedConfidentiality: {
        type: Boolean,
        default: false
    },
    confidentialityAcceptedAt: {
        type: Date
    },
    
    // Auditoria
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Staff'
    },
    updatedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Staff'
    },
    updatedAt: {
        type: Date
    },
    
    // Recuperação de password
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    
    // Configurações do usuário
    settings: {
        theme: {
            type: String,
            enum: ['light', 'dark', 'auto'],
            default: 'dark'
        },
        notifications: {
            email: {
                type: Boolean,
                default: true
            },
            chat: {
                type: Boolean,
                default: true
            },
            withdrawals: {
                type: Boolean,
                default: false
            },
            deposits: {
                type: Boolean,
                default: false
            }
        },
        language: {
            type: String,
            default: 'pt'
        },
        timezone: {
            type: String,
            default: 'Europe/Lisbon'
        }
    },
    
    // Estatísticas
    stats: {
        emailsSent: {
            type: Number,
            default: 0
        },
        withdrawalsProcessed: {
            type: Number,
            default: 0
        },
        depositsProcessed: {
            type: Number,
            default: 0
        },
        ticketsResolved: {
            type: Number,
            default: 0
        },
        lastActivity: {
            type: Date,
            default: Date.now
        }
    },
    
    // Status do chat
    chatStatus: {
        type: String,
        enum: ['available', 'busy', 'away', 'offline'],
        default: 'available'
    },
    chatAvailability: {
        workingHours: {
            start: {
                type: String,
                default: '09:00'
            },
            end: {
                type: String,
                default: '18:00'
            }
        },
        daysOfWeek: {
            type: [Number], // 0 = Domingo, 1 = Segunda, etc.
            default: [1, 2, 3, 4, 5] // Segunda a Sexta
        }
    },
    
    // Preferências de comunicação
    communicationPreferences: {
        internalChat: {
            type: Boolean,
            default: true
        },
        emailNotifications: {
            type: Boolean,
            default: true
        },
        pushNotifications: {
            type: Boolean,
            default: true
        },
        soundEnabled: {
            type: Boolean,
            default: true
        }
    },
    
    // Segurança
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: {
        type: Date
    },
    twoFactorEnabled: {
        type: Boolean,
        default: false
    },
    twoFactorSecret: {
        type: String
    }
}, { 
    collection: 'staffs',
    timestamps: false
});

// Método para comparar password
StaffSchema.methods.comparePassword = async function(password) {
    return await bcrypt.compare(password, this.password);
};

// Middleware para fazer hash da password antes de salvar
StaffSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Atualizar lastActive antes de salvar
StaffSchema.pre('save', function(next) {
    this.updatedAt = new Date();
    next();
});

// Método para obter informações públicas (sem dados sensíveis)
StaffSchema.methods.toPublicJSON = function() {
    const staffObject = this.toObject();
    
    // Remover dados sensíveis
    delete staffObject.password;
    delete staffObject.resetPasswordToken;
    delete staffObject.resetPasswordExpires;
    delete staffObject.twoFactorSecret;
    delete staffObject.loginAttempts;
    delete staffObject.lockUntil;
    
    return staffObject;
};

// Método para obter informações do chat
StaffSchema.methods.toChatJSON = function() {
    return {
        _id: this._id,
        name: this.name,
        email: this.email,
        role: this.role,
        department: this.department,
        photo: this.photo,
        isOnline: this.isOnline,
        lastActive: this.lastActive,
        chatStatus: this.chatStatus
    };
};

// Método para verificar se o staff tem uma permissão específica
StaffSchema.methods.hasPermission = function(permission) {
    if (this.role === 'admin') return true;
    
    // Permissões baseadas no role
    const rolePermissions = {
        'support_manager': [
            'view_players', 'edit_players', 'view_withdrawals', 'view_deposits',
            'send_emails', 'view_logs', 'manage_staff', 'access_chat',
            'view_support_tickets', 'manage_support_tickets'
        ],
        'support': [
            'view_players', 'view_withdrawals', 'view_deposits', 'send_emails',
            'view_logs', 'access_chat', 'view_support_tickets', 'manage_support_tickets'
        ],
        'finance': [
            'view_players', 'view_withdrawals', 'approve_withdrawals', 'view_deposits',
            'process_deposits', 'view_logs', 'access_chat', 'view_financial_reports'
        ],
        'moderator': [
            'view_players', 'edit_players', 'view_logs', 'access_chat'
        ],
        'viewer': [
            'view_players', 'view_withdrawals', 'view_deposits', 'view_logs'
        ]
    };
    
    // Verificar permissões do role
    if (rolePermissions[this.role] && rolePermissions[this.role].includes(permission)) {
        return true;
    }
    
    // Verificar permissões específicas
    return this.permissions.includes(permission);
};

// Método para verificar se o staff está atualmente disponível para chat
StaffSchema.methods.isAvailableForChat = function() {
    if (!this.isActive || !this.isOnline) return false;
    
    if (this.chatStatus === 'offline' || this.chatStatus === 'busy') {
        return false;
    }
    
    // Verificar horário de trabalho
    const now = new Date();
    const currentHour = now.getHours();
    const currentMinute = now.getMinutes();
    const currentDay = now.getDay();
    
    const [startHour, startMinute] = this.chatAvailability.workingHours.start.split(':').map(Number);
    const [endHour, endMinute] = this.chatAvailability.workingHours.end.split(':').map(Number);
    
    const currentTime = currentHour * 60 + currentMinute;
    const startTime = startHour * 60 + startMinute;
    const endTime = endHour * 60 + endMinute;
    
    return currentTime >= startTime && 
           currentTime <= endTime && 
           this.chatAvailability.daysOfWeek.includes(currentDay);
};

// Método para incrementar estatísticas
StaffSchema.methods.incrementStat = function(statName, amount = 1) {
    if (!this.stats[statName]) {
        this.stats[statName] = 0;
    }
    this.stats[statName] += amount;
    this.stats.lastActivity = new Date();
    return this.save();
};

// Método para atualizar status online
StaffSchema.methods.updateOnlineStatus = async function(isOnline, socketId = null) {
    this.isOnline = isOnline;
    this.lastActive = new Date();
    
    if (socketId) {
        this.socketId = socketId;
    }
    
    if (!isOnline) {
        this.socketId = null;
        this.chatStatus = 'offline';
    }
    
    return this.save();
};

// Índices para melhor performance
StaffSchema.index({ email: 1 }, { unique: true });
StaffSchema.index({ role: 1 });
StaffSchema.index({ isActive: 1 });
StaffSchema.index({ isOnline: 1 });
StaffSchema.index({ lastActive: -1 });
StaffSchema.index({ createdAt: -1 });
StaffSchema.index({ department: 1 });
StaffSchema.index({ 'settings.theme': 1 });
StaffSchema.index({ 'stats.lastActivity': -1 });
StaffSchema.index({ chatStatus: 1 });

// Virtual para nome completo
StaffSchema.virtual('fullName').get(function() {
    return this.name;
});

// Virtual para iniciais (para avatar)
StaffSchema.virtual('initials').get(function() {
    return this.name
        .split(' ')
        .map(n => n[0])
        .join('')
        .toUpperCase()
        .substring(0, 3);
});

// Método estático para buscar staff por role
StaffSchema.statics.findByRole = function(role) {
    return this.find({ role: role, isActive: true });
};

// Método estático para buscar staff online
StaffSchema.statics.findOnline = function() {
    return this.find({ 
        isOnline: true, 
        isActive: true,
        chatStatus: { $ne: 'offline' }
    });
};

// Método estático para buscar staff disponível para chat
StaffSchema.statics.findAvailableForChat = function() {
    return this.find({
        isActive: true,
        isOnline: true,
        chatStatus: 'available',
        'communicationPreferences.internalChat': true
    });
};

// Método estático para atualizar lastLogin
StaffSchema.statics.updateLastLogin = async function(staffId) {
    return this.findByIdAndUpdate(
        staffId,
        { 
            lastLogin: new Date(),
            lastActive: new Date(),
            loginAttempts: 0 // Resetar tentativas de login após login bem-sucedido
        },
        { new: true }
    );
};

// Método estático para incrementar tentativas de login falhadas
StaffSchema.statics.incrementFailedLogin = async function(staffId) {
    const staff = await this.findById(staffId);
    if (!staff) return null;
    
    staff.loginAttempts += 1;
    
    // Bloquear após 5 tentativas falhadas por 15 minutos
    if (staff.loginAttempts >= 5) {
        staff.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos
    }
    
    return staff.save();
};

// Método estático para verificar se conta está bloqueada
StaffSchema.statics.isAccountLocked = async function(staffId) {
    const staff = await this.findById(staffId);
    if (!staff) return true;
    
    if (staff.lockUntil && staff.lockUntil > new Date()) {
        return true;
    }
    
    return false;
};

// VERIFIQUE SE O MODELO JÁ EXISTE ANTES DE CRIAR
let Staff;
try {
    Staff = mongoose.model('Staff', StaffSchema, 'staffs');
} catch (error) {
    // Se já existe, use o modelo existente
    Staff = mongoose.model('Staff');
}

module.exports = Staff;