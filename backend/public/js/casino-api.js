class CasinoAPI {
    constructor() {
        this.baseURL = window.CASINO_API.BASE_URL;
        this.token = window.CASINO_API.TOKEN;
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
    }

    // Headers para requisições
    getHeaders() {
        return {
            'Authorization': `Bearer ${this.token}`,
            'Content-Type': 'application/json',
            'X-Casino-API': 'dashboard-v1.0'
        };
    }

    // Métodos principais
    async getStats() {
        try {
            const response = await fetch(`${this.baseURL}/casino/stats`, {
                headers: this.getHeaders()
            });
            return await response.json();
        } catch (error) {
            console.error('Erro ao obter stats:', error);
            throw error;
        }
    }

    async getPlayers(params = {}) {
        try {
            const query = new URLSearchParams(params).toString();
            const response = await fetch(`${this.baseURL}/casino/players?${query}`, {
                headers: this.getHeaders()
            });
            return await response.json();
        } catch (error) {
            console.error('Erro ao obter jogadores:', error);
            throw error;
        }
    }

    async getWithdrawals(status = 'pending', page = 1) {
        try {
            const response = await fetch(`${this.baseURL}/casino/withdrawals?status=${status}&page=${page}`, {
                headers: this.getHeaders()
            });
            return await response.json();
        } catch (error) {
            console.error('Erro ao obter levantamentos:', error);
            throw error;
        }
    }

    async processWithdrawal(id, action, reason = '') {
        try {
            const response = await fetch(`${this.baseURL}/casino/withdrawals/${id}/process`, {
                method: 'POST',
                headers: this.getHeaders(),
                body: JSON.stringify({ action, reason })
            });
            return await response.json();
        } catch (error) {
            console.error('Erro ao processar levantamento:', error);
            throw error;
        }
    }

    async getSupportTickets(params = {}) {
        try {
            const query = new URLSearchParams(params).toString();
            const response = await fetch(`${this.baseURL}/casino/support/tickets?${query}`, {
                headers: this.getHeaders()
            });
            return await response.json();
        } catch (error) {
            console.error('Erro ao obter tickets:', error);
            throw error;
        }
    }

    async updateTicket(id, updates) {
        try {
            const response = await fetch(`${this.baseURL}/casino/support/tickets/${id}`, {
                method: 'PUT',
                headers: this.getHeaders(),
                body: JSON.stringify(updates)
            });
            return await response.json();
        } catch (error) {
            console.error('Erro ao atualizar ticket:', error);
            throw error;
        }
    }

    async getLogs(params = {}) {
        try {
            const query = new URLSearchParams(params).toString();
            const response = await fetch(`${this.baseURL}/casino/logs?${query}`, {
                headers: this.getHeaders()
            });
            return await response.json();
        } catch (error) {
            console.error('Erro ao obter logs:', error);
            throw error;
        }
    }

    // WebSocket
    connectWebSocket() {
        const wsURL = window.CASINO_API.SOCKET_URL.replace('http', 'ws');
        
        this.socket = new WebSocket(`${wsURL}/dashboard`);
        
        this.socket.onopen = () => {
            console.log('✅ Conectado ao WebSocket do Casino');
            this.reconnectAttempts = 0;
            
            // Autenticar
            this.socket.send(JSON.stringify({
                type: 'auth',
                token: this.token,
                userId: window.CASINO_API.USER.id
            }));
            
            // Atualizar status
            document.getElementById('socketStatus').className = 'status-dot online';
            document.getElementById('socketStatusText').textContent = 'Conectado';
        };
        
        this.socket.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleSocketMessage(data);
        };
        
        this.socket.onclose = () => {
            console.log('❌ WebSocket desconectado');
            document.getElementById('socketStatus').className = 'status-dot offline';
            document.getElementById('socketStatusText').textContent = 'Desconectado';
            
            // Tentar reconectar
            this.reconnect();
        };
        
        this.socket.onerror = (error) => {
            console.error('Erro WebSocket:', error);
        };
    }
    
    handleSocketMessage(data) {
        switch (data.type) {
            case 'player_joined':
                this.updatePlayerCount(data.count);
                this.addRealtimeUpdate(`🎮 Novo jogador: ${data.username}`);
                break;
                
            case 'withdrawal_requested':
                this.updateWithdrawalCount(data.count);
                this.addRealtimeUpdate(`💸 Novo levantamento: €${data.amount} de ${data.username}`);
                break;
                
            case 'deposit_made':
                this.updateRevenue(data.amount);
                this.addRealtimeUpdate(`💰 Depósito: €${data.amount} de ${data.username}`);
                break;
                
            case 'support_ticket':
                this.updateTicketCount(data.count);
                this.addRealtimeUpdate(`🎫 Novo ticket: ${data.username} - ${data.subject}`);
                break;
                
            case 'alert':
                showAlert(data.message);
                break;
                
            case 'stats_update':
                this.updateDashboardStats(data.stats);
                break;
        }
    }
    
    addRealtimeUpdate(message) {
        const feed = document.getElementById('realtimeFeed');
        if (feed) {
            const update = document.createElement('div');
            update.className = 'update-item';
            update.innerHTML = `
                <div class="update-time">${new Date().toLocaleTimeString()}</div>
                <div class="update-message">${message}</div>
            `;
            
            feed.insertBefore(update, feed.firstChild);
            
            // Limitar a 10 itens
            if (feed.children.length > 10) {
                feed.removeChild(feed.lastChild);
            }
        }
    }
    
    reconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = Math.min(1000 * this.reconnectAttempts, 10000);
            
            console.log(`Tentando reconectar em ${delay/1000}s...`);
            
            setTimeout(() => {
                this.connectWebSocket();
            }, delay);
        }
    }
    
    // Métodos de atualização da UI
    updateDashboardStats(stats) {
        // Atualizar cards
        if (stats.withdrawals) {
            document.getElementById('withdrawalsValue').textContent = stats.withdrawals.count;
        }
        
        if (stats.players) {
            document.getElementById('onlineValue').textContent = stats.players.online;
        }
        
        if (stats.revenue) {
            document.getElementById('revenueValue').textContent = `€${stats.revenue.today.toLocaleString('pt-PT')}`;
        }
    }
    
    updatePlayerCount(count) {
        const element = document.getElementById('onlineValue');
        if (element) {
            element.textContent = count;
        }
    }
    
    updateWithdrawalCount(count) {
        const element = document.getElementById('withdrawalsValue');
        if (element) {
            element.textContent = count;
        }
    }
    
    updateRevenue(amount) {
        // Atualizar gráfico de receitas
        if (window.revenueChart) {
            // Adicionar novo ponto ao gráfico
            // Implementação específica do Chart.js
        }
    }
    
    updateTicketCount(count) {
        const element = document.getElementById('alertsValue');
        if (element) {
            element.textContent = count;
        }
        
        // Atualizar badge
        const badge = document.getElementById('supportBadge');
        if (badge) {
            badge.textContent = count;
            badge.style.display = count > 0 ? 'flex' : 'none';
        }
    }
}

// Instância global
window.casinoAPI = new CasinoAPI();

// Inicializar quando a página carregar
document.addEventListener('DOMContentLoaded', function() {
    if (window.casinoAPI.token) {
        window.casinoAPI.connectWebSocket();
        
        // Carregar dados iniciais
        loadInitialData();
    }
});

async function loadInitialData() {
    try {
        // Carregar stats
        const stats = await window.casinoAPI.getStats();
        updateDashboardWithStats(stats);
        
        // Carregar atividades recentes
        const activities = await window.casinoAPI.getRecentActivity();
        displayRecentActivities(activities);
        
        // Carregar jogadores recentes
        const players = await window.casinoAPI.getPlayers({ limit: 5 });
        displayRecentPlayers(players);
        
    } catch (error) {
        console.error('Erro ao carregar dados iniciais:', error);
        showToast('Erro ao carregar dados do casino', 'error');
    }
}