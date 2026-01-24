const mysql = require('mysql2/promise');

const pool = mysql.createPool({
    host: 'localhost',       // ou IP do servidor DB
    user: 'root',
    password: '',            // senha da DB
    database: 'casinoX',     // a mesma base do Casino X
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

module.exports = pool;

