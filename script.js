const API_URL = 'http://localhost:3000';

let severityChart = null;
let mitreChart = null;
let forecastChart = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    loadDashboardData();
    setupEventListeners();
    
    // Auto-refresh every 10 seconds
    setInterval(loadDashboardData, 10000);
});

function initializeCharts() {
    // Severity Distribution Chart
    const severityCtx = document.getElementById('severityChart').getContext('2d');
    severityChart = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#EF4444', '#F59E0B', '#3B82F6', '#10B981'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#E5E7EB' }
                }
            }
        }
    });

    // MITRE ATT&CK Chart
    const mitreCtx = document.getElementById('mitreChart').getContext('2d');
    mitreChart = new Chart(mitreCtx, {
        type: 'bar',
        data: {
            labels: ['Reconnaissance', 'Initial Access', 'Execution', 'Privilege Escalation', 'C&C', 'Exfiltration'],
            datasets: [{
                label: 'Attack Stages',
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: '#8B5CF6',
                borderColor: '#A78BFA',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: '#E5E7EB' },
                    grid: { color: '#374151' }
                },
                x: {
                    ticks: { color: '#E5E7EB' },
                    grid: { color: '#374151' }
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#E5E7EB' }
                }
            }
        }
    });

    // Threat Forecast Chart
    const forecastCtx = document.getElementById('forecastChart').getContext('2d');
    forecastChart = new Chart(forecastCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Predicted Threats',
                data: [],
                borderColor: '#EF4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: '#E5E7EB' },
                    grid: { color: '#374151' }
                },
                x: {
                    ticks: { color: '#E5E7EB' },
                    grid: { color: '#374151' }
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#E5E7EB' }
                }
            }
        }
    });
}

async function loadDashboardData() {
    try {
        // Load all dashboard data in parallel
        const [alerts, forecast, stats] = await Promise.all([
            fetch(`${API_URL}/alerts`).then(r => r.json()),
            fetch(`${API_URL}/forecast`).then(r => r.json()),
            fetch(`${API_URL}/stats`).then(r => r.json())
        ]);

        updateStats(stats);
        updateAlertFeed(alerts);
        updateSeverityChart(alerts);
        updateMitreChart(alerts);
        updateForecastChart(forecast);
        updateTopAttackers(alerts);
        updateNetworkGraph(alerts);
        updateGeoHeatmap(alerts);
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        updateSystemStatus(false);
    }
}

function updateStats(stats) {
    document.getElementById('totalAlerts').textContent = stats.total_alerts || 0;
    document.getElementById('criticalAlerts').textContent = stats.critical_alerts || 0;
    document.getElementById('activeIndicators').textContent = stats.active_indicators || 0;
    document.getElementById('avgRiskScore').textContent = (stats.avg_risk_score || 0).toFixed(1);
    updateSystemStatus(true);
}

function updateAlertFeed(alerts) {
    const feedElement = document.getElementById('alertFeed');
    
    if (!alerts || alerts.length === 0) {
        feedElement.innerHTML = '<p class="text-gray-500 text-center py-8">No alerts detected</p>';
        return;
    }

    const recentAlerts = alerts.slice(0, 10);
    
    feedElement.innerHTML = recentAlerts.map(alert => {
        const severityColors = {
            'Critical': 'bg-red-600',
            'High': 'bg-orange-600',
            'Medium': 'bg-blue-600',
            'Low': 'bg-green-600'
        };
        
        const severityColor = severityColors[alert.severity] || 'bg-gray-600';
        
        return `
            <div class="bg-gray-900 border border-gray-700 rounded-lg p-4 hover:border-gray-600 transition duration-200">
                <div class="flex items-start justify-between">
                    <div class="flex-1">
                        <div class="flex items-center space-x-2 mb-2">
                            <span class="px-2 py-1 ${severityColor} text-white text-xs font-bold rounded">${alert.severity}</span>
                            <span class="px-2 py-1 bg-gray-700 text-gray-300 text-xs rounded">${alert.mitre_stage || 'Unknown'}</span>
                        </div>
                        <p class="text-white font-medium mb-1">${alert.indicator_value || 'Unknown'}</p>
                        <p class="text-gray-400 text-sm">${alert.event_type || 'Unknown event'}</p>
                    </div>
                    <div class="text-right">
                        <div class="text-2xl font-bold text-white">${alert.final_risk_score ? alert.final_risk_score.toFixed(0) : '0'}</div>
                        <div class="text-xs text-gray-500">Risk Score</div>
                    </div>
                </div>
                <div class="mt-3 pt-3 border-t border-gray-800 grid grid-cols-3 gap-2 text-xs">
                    <div>
                        <span class="text-gray-500">Rule:</span>
                        <span class="text-gray-300 ml-1">${alert.rule_score ? alert.rule_score.toFixed(0) : '0'}</span>
                    </div>
                    <div>
                        <span class="text-gray-500">ML:</span>
                        <span class="text-gray-300 ml-1">${alert.ml_score ? alert.ml_score.toFixed(0) : '0'}</span>
                    </div>
                    <div>
                        <span class="text-gray-500">Graph:</span>
                        <span class="text-gray-300 ml-1">${alert.graph_score ? alert.graph_score.toFixed(0) : '0'}</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function updateSeverityChart(alerts) {
    if (!alerts || alerts.length === 0) return;
    
    const severityCounts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0
    };
    
    alerts.forEach(alert => {
        if (severityCounts.hasOwnProperty(alert.severity)) {
            severityCounts[alert.severity]++;
        }
    });
    
    severityChart.data.datasets[0].data = Object.values(severityCounts);
    severityChart.update();
}

function updateMitreChart(alerts) {
    if (!alerts || alerts.length === 0) return;
    
    const mitreCounts = {
        'Reconnaissance': 0,
        'Initial Access': 0,
        'Execution': 0,
        'Privilege Escalation': 0,
        'Command and Control': 0,
        'Exfiltration': 0
    };
    
    alerts.forEach(alert => {
        if (alert.mitre_stage && mitreCounts.hasOwnProperty(alert.mitre_stage)) {
            mitreCounts[alert.mitre_stage]++;
        }
    });
    
    mitreChart.data.datasets[0].data = Object.values(mitreCounts);
    mitreChart.update();
}

function updateForecastChart(forecast) {
    if (!forecast || !forecast.predictions) return;
    
    forecastChart.data.labels = forecast.predictions.map(p => p.date);
    forecastChart.data.datasets[0].data = forecast.predictions.map(p => p.predicted_count);
    forecastChart.update();
}

function updateTopAttackers(alerts) {
    const attackersElement = document.getElementById('topAttackers');
    
    if (!alerts || alerts.length === 0) {
        attackersElement.innerHTML = '<p class="text-gray-500 text-center py-8">No data available</p>';
        return;
    }
    
    // Group by indicator_value and sum risk scores
    const attackerMap = {};
    alerts.forEach(alert => {
        const key = alert.indicator_value;
        if (!attackerMap[key]) {
            attackerMap[key] = {
                value: key,
                totalRisk: 0,
                count: 0,
                maxSeverity: alert.severity
            };
        }
        attackerMap[key].totalRisk += alert.final_risk_score || 0;
        attackerMap[key].count++;
    });
    
    // Sort by total risk and take top 5
    const topAttackers = Object.values(attackerMap)
        .sort((a, b) => b.totalRisk - a.totalRisk)
        .slice(0, 5);
    
    attackersElement.innerHTML = topAttackers.map((attacker, index) => {
        const avgRisk = (attacker.totalRisk / attacker.count).toFixed(0);
        const barWidth = (avgRisk / 100) * 100;
        
        return `
            <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
                <div class="flex items-center justify-between mb-2">
                    <div class="flex items-center space-x-2">
                        <span class="text-gray-500 font-mono text-sm">#${index + 1}</span>
                        <span class="text-white font-medium font-mono">${attacker.value}</span>
                    </div>
                    <span class="text-red-500 font-bold">${avgRisk}</span>
                </div>
                <div class="w-full bg-gray-800 rounded-full h-2">
                    <div class="bg-red-600 h-2 rounded-full" style="width: ${barWidth}%"></div>
                </div>
                <div class="mt-2 text-xs text-gray-500">${attacker.count} events detected</div>
            </div>
        `;
    }).join('');
}

function updateNetworkGraph(alerts) {
    const graphElement = document.getElementById('networkGraph');
    graphElement.innerHTML = '';
    
    if (!alerts || alerts.length === 0) return;
    
    const width = graphElement.clientWidth;
    const height = 320;
    
    // Create simple network graph with D3
    const svg = d3.select('#networkGraph')
        .append('svg')
        .attr('width', width)
        .attr('height', height);
    
    // Sample network data from alerts
    const nodes = [];
    const links = [];
    const nodeMap = new Map();
    
    alerts.slice(0, 20).forEach((alert, i) => {
        if (!nodeMap.has(alert.indicator_value)) {
            nodes.push({
                id: alert.indicator_value,
                group: alert.severity === 'Critical' ? 1 : alert.severity === 'High' ? 2 : 3,
                risk: alert.final_risk_score || 0
            });
            nodeMap.set(alert.indicator_value, nodes.length - 1);
        }
        
        // Create links between consecutive nodes
        if (i > 0 && alerts[i - 1]) {
            links.push({
                source: alert.indicator_value,
                target: alerts[i - 1].indicator_value
            });
        }
    });
    
    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(50))
        .force('charge', d3.forceManyBody().strength(-100))
        .force('center', d3.forceCenter(width / 2, height / 2));
    
    const link = svg.append('g')
        .selectAll('line')
        .data(links)
        .enter().append('line')
        .attr('stroke', '#4B5563')
        .attr('stroke-width', 1);
    
    const node = svg.append('g')
        .selectAll('circle')
        .data(nodes)
        .enter().append('circle')
        .attr('r', d => Math.max(5, Math.min(15, d.risk / 10)))
        .attr('fill', d => {
            if (d.group === 1) return '#EF4444';
            if (d.group === 2) return '#F59E0B';
            return '#3B82F6';
        })
        .attr('stroke', '#1F2937')
        .attr('stroke-width', 2);
    
    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);
        
        node
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);
    });
}

function updateGeoHeatmap(alerts) {
    const heatmapElement = document.getElementById('geoHeatmap');
    
    if (!alerts || alerts.length === 0) {
        heatmapElement.innerHTML = '<p class="text-gray-500 text-center py-8 col-span-full">No geographic data</p>';
        return;
    }
    
    const geoCounts = {};
    alerts.forEach(alert => {
        if (alert.geo_location) {
            geoCounts[alert.geo_location] = (geoCounts[alert.geo_location] || 0) + 1;
        }
    });
    
    const sortedGeos = Object.entries(geoCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 16);
    
    heatmapElement.innerHTML = sortedGeos.map(([geo, count]) => {
        const intensity = Math.min(100, (count / alerts.length) * 500);
        const color = intensity > 70 ? 'bg-red-600' : intensity > 40 ? 'bg-orange-600' : 'bg-yellow-600';
        
        return `
            <div class="${color} rounded-lg p-4 text-center">
                <div class="text-2xl font-bold text-white">${geo}</div>
                <div class="text-xs text-gray-200 mt-1">${count} threats</div>
            </div>
        `;
    }).join('');
}

function updateSystemStatus(isOnline) {
    const statusElement = document.getElementById('systemStatus');
    const statusText = statusElement.nextElementSibling;
    
    if (isOnline) {
        statusElement.className = 'w-2 h-2 bg-green-500 rounded-full animate-pulse';
        statusText.className = 'text-sm font-medium text-green-500';
        statusText.textContent = 'Operational';
    } else {
        statusElement.className = 'w-2 h-2 bg-red-500 rounded-full';
        statusText.className = 'text-sm font-medium text-red-500';
        statusText.textContent = 'Offline';
    }
}

function setupEventListeners() {
    const analyzeBtn = document.getElementById('analyzeBtn');
    const eventInput = document.getElementById('eventInput');
    const analysisResult = document.getElementById('analysisResult');
    
    analyzeBtn.addEventListener('click', async () => {
        try {
            const eventData = JSON.parse(eventInput.value);
            
            analyzeBtn.disabled = true;
            analyzeBtn.textContent = 'Analyzing...';
            analysisResult.innerHTML = '<p class="text-gray-500">Processing event...</p>';
            
            const response = await fetch(`${API_URL}/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(eventData)
            });
            
            const result = await response.json();
            
            analysisResult.innerHTML = `
                <div class="space-y-3">
                    <div class="border-b border-gray-700 pb-2">
                        <div class="text-lg font-bold ${result.severity === 'Critical' ? 'text-red-500' : result.severity === 'High' ? 'text-orange-500' : 'text-blue-500'}">
                            ${result.severity} Severity
                        </div>
                        <div class="text-3xl font-bold text-white mt-1">${result.final_risk_score.toFixed(0)}</div>
                        <div class="text-sm text-gray-500">Final Risk Score</div>
                    </div>
                    
                    <div class="grid grid-cols-3 gap-2">
                        <div>
                            <div class="text-sm text-gray-500">Rule Score</div>
                            <div class="text-xl font-bold text-white">${result.rule_score.toFixed(0)}</div>
                        </div>
                        <div>
                            <div class="text-sm text-gray-500">ML Score</div>
                            <div class="text-xl font-bold text-white">${result.ml_score.toFixed(0)}</div>
                        </div>
                        <div>
                            <div class="text-sm text-gray-500">Graph Score</div>
                            <div class="text-xl font-bold text-white">${result.graph_score.toFixed(0)}</div>
                        </div>
                    </div>
                    
                    <div class="border-t border-gray-700 pt-2">
                        <div class="text-sm text-gray-500">MITRE ATT&CK Stage</div>
                        <div class="text-lg font-medium text-purple-400">${result.mitre_stage}</div>
                    </div>
                    
                    <div class="border-t border-gray-700 pt-2">
                        <div class="text-sm text-gray-500 mb-1">Triggered Rules</div>
                        <div class="space-y-1">
                            ${result.triggered_rules.map(rule => `
                                <div class="text-xs text-gray-300 bg-gray-800 px-2 py-1 rounded">${rule}</div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            `;
            
            // Reload dashboard to show new alert
            setTimeout(loadDashboardData, 1000);
            
        } catch (error) {
            analysisResult.innerHTML = `<p class="text-red-500">Error: ${error.message}</p>`;
        } finally {
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = 'Analyze Event';
        }
    });
}