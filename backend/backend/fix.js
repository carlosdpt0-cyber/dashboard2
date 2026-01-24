const mongoose = require('mongoose');

async function fixDatabase() {
    try {
        await mongoose.connect('mongodb://localhost:27017/casinox', {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });

        const db = mongoose.connection.db;
        const ticketsCollection = db.collection('support_tickets');
        
        // 1. Ver índices atuais
        console.log('Índices atuais:');
        const indexes = await ticketsCollection.indexes();
        console.log(indexes);
        
        // 2. Remover índice problemático
        try {
            await ticketsCollection.dropIndex('ticketId_1');
            console.log('✅ Índice ticketId_1 removido');
        } catch (err) {
            console.log('ℹ️ Índice já removido ou não existe');
        }
        
        // 3. Criar novo índice no _id (que é único por padrão)
        await ticketsCollection.createIndex({ _id: 1 });
        console.log('✅ Índice _id criado');
        
        // 4. Criar índice composto para busca por usuário
        await ticketsCollection.createIndex({ userId: 1, createdAt: -1 });
        console.log('✅ Índice userId + createdAt criado');
        
        // 5. Verificar estrutura
        const sample = await ticketsCollection.findOne({});
        if (sample) {
            console.log('📋 Estrutura do primeiro ticket:');
            console.log(Object.keys(sample));
        }
        
        console.log('🎯 Database corrigida com sucesso!');
        process.exit(0);
        
    } catch (error) {
        console.error('❌ Erro:', error);
        process.exit(1);
    }
}

fixDatabase();