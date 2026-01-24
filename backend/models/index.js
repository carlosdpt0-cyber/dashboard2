// models/index.js (exemplo)
const Sequelize = require('sequelize');
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
    host: process.env.DB_HOST,
    dialect: 'mysql',
    logging: false
});

// Definir modelos
const Player = sequelize.define('Player', {
    id: { type: Sequelize.INTEGER, primaryKey: true, autoIncrement: true },
    player_id: { type: Sequelize.STRING, unique: true },
    username: { type: Sequelize.STRING },
    email: { type: Sequelize.STRING },
    balance: { type: Sequelize.DECIMAL(10, 2), defaultValue: 0 },
    status: { type: Sequelize.ENUM('active', 'suspended', 'inactive') },
    total_deposits: { type: Sequelize.DECIMAL(10, 2), defaultValue: 0 },
    total_withdrawals: { type: Sequelize.DECIMAL(10, 2), defaultValue: 0 },
    last_login: { type: Sequelize.DATE },
    country: { type: Sequelize.STRING },
    ip_address: { type: Sequelize.STRING }
});

const Transaction = sequelize.define('Transaction', {
    id: { type: Sequelize.INTEGER, primaryKey: true, autoIncrement: true },
    player_id: { type: Sequelize.STRING },
    type: { type: Sequelize.ENUM('deposit', 'withdrawal', 'bonus', 'game') },
    amount: { type: Sequelize.DECIMAL(10, 2) },
    status: { type: Sequelize.ENUM('pending', 'completed', 'failed', 'cancelled') },
    payment_method: { type: Sequelize.STRING },
    reference: { type: Sequelize.STRING },
    metadata: { type: Sequelize.JSON }
});

const Withdrawal = sequelize.define('Withdrawal', {
    id: { type: Sequelize.INTEGER, primaryKey: true, autoIncrement: true },
    player_id: { type: Sequelize.STRING },
    amount: { type: Sequelize.DECIMAL(10, 2) },
    status: { type: Sequelize.ENUM('pending', 'approved', 'rejected', 'processing') },
    payment_method: { type: Sequelize.STRING },
    casino_withdrawal_id: { type: Sequelize.STRING },
    processed_by: { type: Sequelize.STRING },
    processed_at: { type: Sequelize.DATE },
    rejection_reason: { type: Sequelize.TEXT }
});

const SupportTicket = sequelize.define('SupportTicket', {
    id: { type: Sequelize.INTEGER, primaryKey: true, autoIncrement: true },
    player_id: { type: Sequelize.STRING },
    subject: { type: Sequelize.STRING },
    message: { type: Sequelize.TEXT },
    status: { type: Sequelize.ENUM('open', 'in_progress', 'resolved', 'closed') },
    priority: { type: Sequelize.ENUM('low', 'medium', 'high', 'critical') },
    department: { type: Sequelize.ENUM('technical', 'financial', 'general') },
    assigned_to: { type: Sequelize.INTEGER }
});

const CasinoGame = sequelize.define('CasinoGame', {
    id: { type: Sequelize.INTEGER, primaryKey: true, autoIncrement: true },
    game_id: { type: Sequelize.STRING, unique: true },
    name: { type: Sequelize.STRING },
    provider: { type: Sequelize.STRING },
    type: { type: Sequelize.STRING },
    popularity: { type: Sequelize.INTEGER, defaultValue: 0 },
    total_bets: { type: Sequelize.DECIMAL(10, 2), defaultValue: 0 },
    total_wins: { type: Sequelize.DECIMAL(10, 2), defaultValue: 0 },
    payout_percentage: { type: Sequelize.DECIMAL(5, 2), defaultValue: 0 }
});

// Definir relações
Player.hasMany(Transaction, { foreignKey: 'player_id', as: 'transactions' });
Player.hasMany(Withdrawal, { foreignKey: 'player_id', as: 'withdrawals' });
Player.hasMany(SupportTicket, { foreignKey: 'player_id', as: 'tickets' });

Transaction.belongsTo(Player, { foreignKey: 'player_id', as: 'player' });
Withdrawal.belongsTo(Player, { foreignKey: 'player_id', as: 'player' });
SupportTicket.belongsTo(Player, { foreignKey: 'player_id', as: 'player' });

module.exports = {
    sequelize,
    Player,
    Transaction,
    Withdrawal,
    SupportTicket,
    CasinoGame
};