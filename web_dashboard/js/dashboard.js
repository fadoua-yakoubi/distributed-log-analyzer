// Configuration
const MASTER_URL = "http://127.0.0.1:5000";
let autoRefreshInterval = null;

// Mise à jour de l'heure
function updateLastUpdateTime() {
    const now = new Date();
    const timeString = now.toLocaleTimeString('fr-FR');
    const elem = document.getElementById('updateTime');
    if (elem) elem.textContent = timeString;
}

// Récupérer les données du master
async function fetchDataFromMaster() {
    try {
        const response = await fetch(`${MASTER_URL}/`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        console.log('✅ Données reçues:', data.logs_history?.length || 0, 'logs');
        return data.logs_history || [];
    } catch (error) {
        console.error('❌ Erreur:', error);
        updateConnectionStatus('error', 'Déconnecté');
        return [];
    }
}

// Analyser les logs
function analyzeLogs(logsHistory) {
    const stats = {
        totalLogs: 0,
        totalAttacks: 0,
        attackTypes: {
            'SQLi': 0,
            'XSS': 0,
            'CommandInjection': 0,
            'PathTraversal': 0,
            'SuspiciousUA': 0
        },
        recentAttacks: [],
        workers: {},
        performance: {
            totalProcessingTime: 0,
            correctPredictions: 0,
            logsWithResults: 0
        },
        timeline: []
    };

    if (!logsHistory || !Array.isArray(logsHistory)) return stats;

    const validLogs = logsHistory.filter(log => log && log.log);
    stats.totalLogs = validLogs.length;

    validLogs.forEach(entry => {
        const log = entry.log;
        const prediction = entry.prediction || log.real_category;
        const workerUrl = entry.worker || 'Unknown';
        const workerName = getWorkerName(workerUrl);
        
        // Initialiser le worker
        if (!stats.workers[workerName]) {
            stats.workers[workerName] = {
                logs: 0,
                attacks: 0,
                processingTimes: [],
                lastHeartbeat: entry.sent_at || new Date().toISOString()
            };
        }
        
        stats.workers[workerName].logs++;
        
        // Compter les logs avec résultats
        if (entry.prediction && entry.confidence !== undefined) {
            stats.performance.logsWithResults++;
        }

        // Détecter les attaques (tout sauf Normal)
        const isAttack = prediction && prediction !== 'Normal';
        
        if (isAttack) {
            stats.totalAttacks++;
            stats.workers[workerName].attacks++;
            
            // Types d'attaques
            if (stats.attackTypes[prediction] !== undefined) {
                stats.attackTypes[prediction]++;
            }
            
            // Attaques récentes (max 10)
            if (stats.recentAttacks.length < 10) {
                stats.recentAttacks.push({
                    type: prediction,
                    description: log.payload || log.endpoint || 'Pas de payload',
                    worker: workerName,
                    confidence: entry.confidence || 0,
                    isCorrect: entry.is_correct,
                    processingTime: entry.processing_time
                });
            }
        }

        // Performance
        if (entry.processing_time) {
            stats.performance.totalProcessingTime += entry.processing_time;
            stats.workers[workerName].processingTimes.push(entry.processing_time);
        }
        
        if (entry.is_correct === true) {
            stats.performance.correctPredictions++;
        }

        // Timeline
        if (log.timestamp || entry.sent_at) {
            stats.timeline.push({
                timestamp: new Date(log.timestamp || entry.sent_at)
            });
        }
    });

    // Trier les attaques par timestamp
    stats.recentAttacks.sort((a, b) => {
        return new Date('1970-01-01 ' + b.timestamp) - new Date('1970-01-01 ' + a.timestamp);
    });

    return stats;
}

// Obtenir un nom de worker lisible
function getWorkerName(workerUrl) {
    if (!workerUrl) return 'Worker Inconnu';
    
    if (workerUrl.includes('127.0.0.1')) return 'Worker Local';
    
    const hostname = workerUrl.split('/')[2] || '';
    if (hostname.includes('unlikably-unremissible-yamileth')) return 'Worker 1';
    if (hostname.includes('nonduplicative-monet-vividly')) return 'Worker 2';
    
    return hostname.split('.')[0] || 'Worker';
}

// Calculer les métriques
function calculateMetrics(stats) {
    // Logs par seconde
    if (stats.timeline.length >= 2) {
        const sorted = [...stats.timeline].sort((a, b) => a.timestamp - b.timestamp);
        const timeDiff = (sorted[sorted.length - 1].timestamp - sorted[0].timestamp) / 1000;
        stats.logsPerSecond = timeDiff > 0 ? (stats.totalLogs / timeDiff).toFixed(1) : stats.totalLogs;
    } else {
        stats.logsPerSecond = stats.totalLogs;
    }
    
    // Taux de détection
    if (stats.performance.logsWithResults > 0) {
        stats.detectionRate = ((stats.performance.correctPredictions / stats.performance.logsWithResults) * 100).toFixed(1);
    } else {
        stats.detectionRate = 0;
    }
  
    return stats;
}

// Mettre à jour le dashboard
async function refreshData() {
    console.log('🔄 Actualisation...');
    
    try {
        const logsHistory = await fetchDataFromMaster();
        const rawStats = analyzeLogs(logsHistory);
        const stats = calculateMetrics(rawStats);
        
        updateMainMetrics(stats);
        updateWorkersDisplay(stats.workers);
        updateAttackTypesDisplay(stats.attackTypes, stats.totalAttacks);
        updateRecentAttacksDisplay(stats.recentAttacks);
        updatePerformanceDisplay(stats);
        
        updateLastUpdateTime();
        updateConnectionStatus('connected', `Connecté - ${stats.totalLogs} logs`);
        
    } catch (error) {
        console.error('❌ Erreur:', error);
        updateConnectionStatus('error', 'Déconnecté');
    }
}

// Mettre à jour les métriques principales
function updateMainMetrics(stats) {
    const elems = {
        totalLogs: document.getElementById('totalLogs'),
        totalAttacks: document.getElementById('totalAttacks'),
        logsPerSecond: document.getElementById('logsPerSecond'),
        detectionRate: document.getElementById('detectionRate')
    };
    
    if (elems.totalLogs) elems.totalLogs.textContent = stats.totalLogs.toLocaleString();
    if (elems.totalAttacks) elems.totalAttacks.textContent = stats.totalAttacks;
    if (elems.logsPerSecond) elems.logsPerSecond.textContent = stats.logsPerSecond;
    if (elems.detectionRate) elems.detectionRate.textContent = `${stats.detectionRate}%`;
}

// Mettre à jour les workers
function updateWorkersDisplay(workers) {
    const grid = document.getElementById('workersGrid');
    if (!grid) return;
    
    grid.innerHTML = '';
    
    if (Object.keys(workers).length === 0) {
        grid.innerHTML = `
            <div class="worker-card offline">
                <div class="worker-header">
                    <h3>👷 Aucun Worker</h3>
                    <span class="status-badge offline">Hors ligne</span>
                </div>
            </div>
        `;
        return;
    }
    
    Object.entries(workers).forEach(([workerName, data]) => {
        const isOnline = data.logs > 0;
        const lastHeartbeat = new Date(data.lastHeartbeat).toLocaleTimeString('fr-FR');
        
        const card = document.createElement('div');
        card.className = `worker-card ${isOnline ? 'online' : 'offline'}`;
        card.innerHTML = `
            <div class="worker-header">
                <h3>🔧 ${workerName}</h3>
                <span class="status-badge ${isOnline ? 'online' : 'offline'}">
                    ${isOnline ? 'En ligne' : 'Hors ligne'}
                </span>
            </div>
            <div class="worker-stats">
                <div class="stat">
                    <label>Logs traités:</label>
                    <span class="stat-value">${data.logs}</span>
                </div>
                <div class="stat">
                    <label>Attaques:</label>
                    <span class="stat-value">${data.attacks}</span>
                </div>
                
                <div class="stat">
                    <label>Temps moyen:</label>
                    <span class="stat-value">${data.avgProcessingTime ? data.avgProcessingTime.toFixed(0) + 'ms' : 'N/A'}</span>
                </div>
                <div class="stat" style="grid-column: 1 / -1;">
                    <label>Dernière activité:</label>
                    <span class="stat-value">${lastHeartbeat}</span>
                </div>
            </div>
        `;
        grid.appendChild(card);
    });
}

// Mettre à jour les types d'attaques
function updateAttackTypesDisplay(attackTypes, totalAttacks) {
    const typeMapping = {
        'SQLi': 'sqlCount',
        'XSS': 'xssCount', 
        'CommandInjection': 'cmdCount',
        'PathTraversal': 'pathCount',
        'SuspiciousUA': 'uaCount'
    };
    
    // Mettre à jour les compteurs
    Object.entries(typeMapping).forEach(([type, elementId]) => {
        const count = attackTypes[type] || 0;
        const elem = document.getElementById(elementId);
        if (elem) elem.textContent = count;
    });
    
    // Mettre à jour les barres
    if (totalAttacks > 0) {
        const fills = {
            'sql': ((attackTypes.SQLi || 0) / totalAttacks * 100),
            'xss': ((attackTypes.XSS || 0) / totalAttacks * 100),
            'cmd': ((attackTypes.CommandInjection || 0) / totalAttacks * 100),
            'path': ((attackTypes.PathTraversal || 0) / totalAttacks * 100),
            'ua': ((attackTypes.SuspiciousUA || 0) / totalAttacks * 100)
        };
        
        Object.entries(fills).forEach(([type, width]) => {
            const fill = document.querySelector(`.attack-fill.${type}`);
            if (fill) {
                const percent = Math.max(1, width);
                fill.style.width = `${percent}%`;
            }
        });
    } else {
        document.querySelectorAll('.attack-fill').forEach(fill => {
            fill.style.width = '0%';
        });
    }
}

// Mettre à jour les attaques récentes
function updateRecentAttacksDisplay(recentAttacks) {
    const container = document.getElementById('recentAttacks');
    if (!container) return;
    
    container.innerHTML = '';
    
    if (recentAttacks.length === 0) {
        container.innerHTML = `
            <div class="no-attacks">
                <div class="empty-state">
                    <div style="font-size: 2em; margin-bottom: 10px;">🛡️</div>
                    <h3>Aucune attaque détectée</h3>
                    <p>Tous les logs sont normaux pour le moment</p>
                </div>
            </div>
        `;
        return;
    }
    
    recentAttacks.forEach(attack => {
        const entry = document.createElement('div');
        entry.className = 'attack-entry';
        
        const typeClass = attack.type.toLowerCase()
            .replace('sqli', 'sql')
            .replace('commandinjection', 'cmd')
            .replace('pathtraversal', 'path')
            .replace('suspiciousua', 'ua');
        
        const confidencePercent = (attack.confidence * 100).toFixed(1);
        const confidenceClass = confidencePercent > 90 ? 'high' : confidencePercent > 70 ? 'medium' : 'low';
        
        entry.innerHTML = `
            <div class="attack-type-badge ${typeClass}">${attack.type}</div>
            <div class="attack-details">
                <div class="attack-description">
                    ${escapeHtml(attack.description.substring(0, 80))}${attack.description.length > 80 ? '...' : ''}
                </div>
                <div class="attack-meta">
                    <span class="worker">${attack.worker}</span>
                    <span class="confidence ${confidenceClass}">${confidencePercent}%</span>
                    ${attack.isCorrect !== undefined ? `<span>${attack.isCorrect ? '✅' : '❌'}</span>` : ''}
                </div>
            </div>
        `;
        container.appendChild(entry);
    });
}

// Mettre à jour les performances
function updatePerformanceDisplay(stats) {
    const avgTime = stats.performance.logsWithResults > 0 ? 
        (stats.performance.totalProcessingTime / stats.performance.logsWithResults).toFixed(0) : 0;
    
    const elem1 = document.getElementById('avgProcessingTime');
    if (elem1) elem1.textContent = `${avgTime}ms`;
    
    // Efficacité du load balancing
    let loadBalance = 100;
    const workerLoads = Object.values(stats.workers).map(w => w.logs);
    if (workerLoads.length > 1) {
        const max = Math.max(...workerLoads);
        const min = Math.min(...workerLoads);
        if (max > 0) loadBalance = 100 - ((max - min) / max * 50);
    }
    
    const elem2 = document.getElementById('loadBalanceEfficiency');
    if (elem2) elem2.textContent = `${loadBalance.toFixed(0)}%`;
    
    // Uptime
    if (stats.timeline.length > 0) {
        const firstLog = stats.timeline[0].timestamp;
        const uptimeMs = Date.now() - firstLog;
        const hours = Math.floor(uptimeMs / (1000 * 60 * 60));
        const minutes = Math.floor((uptimeMs % (1000 * 60 * 60)) / (1000 * 60));
        
        const elem3 = document.getElementById('systemUptime');
        if (elem3) elem3.textContent = `${hours}h ${minutes}m`;
    }
    
    // Logs en attente (ceux sans résultat)
    const pending = stats.totalLogs - stats.performance.logsWithResults;
    const elem4 = document.getElementById('pendingLogs');
    if (elem4) elem4.textContent = pending;
    
    // Distribution de la charge
    updateLoadDistribution(stats.workers);
}

// Distribution de charge
function updateLoadDistribution(workers) {
    const container = document.getElementById('loadBars');
    if (!container) return;
    
    container.innerHTML = '';
    
    Object.entries(workers).forEach(([workerName, data]) => {
        
        const bar = document.createElement('div');
        bar.className = 'load-bar';
        bar.innerHTML = `
            <label>${workerName}</label>
            <div class="load-fill" style="width: ${load}%">${load}%</div>
        `;
        container.appendChild(bar);
    });
}

// Statut de connexion
function updateConnectionStatus(status, message) {
    const indicator = document.getElementById('connectionStatus');
    if (!indicator) return;
    
    indicator.innerHTML = `
        <span class="status-dot ${status}"></span>
        <span class="status-text">${message}</span>
    `;
}

// Échapper le HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialisation
document.addEventListener('DOMContentLoaded', function() {
    console.log('✅ Dashboard initialisé');
    console.log(`📡 Master: ${MASTER_URL}`);
    
    updateLastUpdateTime();
    updateConnectionStatus('connecting', 'Connexion...');
    
    refreshData();
    autoRefreshInterval = setInterval(refreshData, 5000);
});