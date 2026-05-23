document.addEventListener('DOMContentLoaded', () => {
    const API_BASE = '/api';
    const alertsList = document.getElementById('alertsList');
    const logsList = document.getElementById('activityLogsList');

    // ==========================================
    // 0. FETCH & RENDER DASHBOARD STATS
    // ==========================================
    async function fetchDashboardStats() {
        const statCards = document.querySelector('.stat-cards-grid');
        if (!statCards) return;

        try {
            const response = await fetch(`${API_BASE}/stats`);
            if (!response.ok) throw new Error('Failed to fetch stats');
            const data = await response.json();

            // I-update ang values sa UI base sa mapping ng order sa CSS
            const values = document.querySelectorAll('.stat-card-mini .card-info .value');
            if (values.length >= 4) {
                values[0].innerText = data.total_alerts || 0;
                values[1].innerText = data.blocked_threats || 0;
                values[2].innerText = data.active_policies || 0;
                values[3].innerText = data.total_devices || 0;
            }

            // I-update din ang Incident Count display kung nandoon (Incident Page)
            const bigNumber = document.querySelector('.big-number');
            if (bigNumber) bigNumber.innerText = data.total_alerts || 0;

        } catch (error) {
            console.error('Error updating dashboard stats:', error);
        }
    }

    // ==========================================
    // 1. FETCH & RENDER ALERTS FROM DATABASE
    // ==========================================
    async function fetchAlerts() {
        if (!alertsList) return;
        try {
            const response = await fetch(`${API_BASE}/alerts`);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const alerts = await response.json();
            renderAlerts(alerts);
        } catch (error) {
            console.error('Error fetching alerts from MySQL:', error);
        }
    }

    function renderAlerts(alerts) {
        if (!alertsList) return;
        alertsList.innerHTML = '';
        
        if (!alerts || alerts.length === 0) {
            alertsList.innerHTML = '<li><p class="meta" style="padding: 10px;">No real-time security anomalies monitored.</p></li>';
            return;
        }

        alerts.forEach(alert => {
            const li = document.createElement('li');
            
            // Tukuyin ang kulay ng indicator base sa status value mula sa database
            const statusLower = (alert.status || '').toLowerCase();
            const color = statusLower === 'blocked' ? 'red' : (statusLower === 'prompted' ? 'orange' : 'green');
            
            li.innerHTML = `
                <div class="alert-icon" style="background-color: var(--accent-${color})">${alert.id}</div>
                <div class="alert-info">
                    <h4 style="color: var(--accent-${color})">${alert.activity} - ${alert.risk || 'Low Risk'}</h4>
                    <p style="font-size: 11px; color: #777; margin: 2px 0;">
                        Source: ${alert.source || 'N/A'} | User: ${alert.user || 'System'}
                    </p>
                    <span class="meta">${alert.time}</span>
                </div>
            `;
            alertsList.appendChild(li);
        });
    }

    // Render Activity Logs (for Dashboard View)
    async function fetchLogs() {
        if (!logsList) return;
        try {
            const response = await fetch(`${API_BASE}/logs`);
            if (!response.ok) throw new Error('Failed to fetch logs');
            const logs = await response.json();
            
            logsList.innerHTML = '';
            if (logs.length === 0) {
                logsList.innerHTML = '<li class="meta">No recent activity.</li>';
                return;
            }

            logs.forEach(log => {
            const li = document.createElement('li');
            li.innerHTML = `
                <i class="fas ${log.icon}" style="color: #1e3a5f; width: 20px;"></i>
                <div class="alert-info" style="flex: 1; display: flex; justify-content: space-between;">
                    <h4 style="font-weight: 500;">${log.activity}</h4>
                    <span class="meta">${log.time}</span>
                </div>
            `;
            logsList.appendChild(li);
            });
        } catch (error) {
            console.error('Error loading logs:', error);
        }
    }

    // ==========================================
    // 2. DYNAMIC THREAT LINE CHART (DASHBOARD)
    // ==========================================
    function initLineChart() {
        const chartElement = document.getElementById('threatLineChart');
        if (!chartElement) return;
        const ctx = chartElement.getContext('2d');
        
        if (window.threatChart) window.threatChart.destroy();

        const gradient = ctx.createLinearGradient(0, 0, 0, 150);
        gradient.addColorStop(0, 'rgba(33, 150, 243, 0.5)');
        gradient.addColorStop(1, 'rgba(33, 150, 243, 0)');

        window.threatChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'],
                datasets: [{
                    label: 'Threats',
                    data: [1, 3, 2, 4, 6], 
                    borderColor: '#2196f3',
                    borderWidth: 3,
                    fill: true,
                    backgroundColor: gradient,
                    tension: 0.4,
                    pointRadius: 4,
                    pointBackgroundColor: '#2196f3'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, max: 6, ticks: { stepSize: 2, color: '#aaa', font: { size: 10 } } },
                    x: { ticks: { color: '#aaa', font: { size: 10 } } }
                }
            }
        });
    }

    // ==========================================
    // 3. DYNAMIC THREAT DISTRIBUTION CHART (THREAT ANALYTICS)
    // ==========================================
    async function initDistributionChart() {
        const chartElement = document.getElementById('threatDistributionChart');
        if (!chartElement) return;
        const ctx = chartElement.getContext('2d');

        if (window.distributionChart) window.distributionChart.destroy();

        const colorMapping = {
            'Malware': '#d32f2f',
            'Phishing': '#f57c00',
            'Data Leaks': '#fbc02d',
            'Unauthorized Access': '#2196f3',
            'Policy Violations': '#388e3c'
        };

        try {
            const response = await fetch(`${API_BASE}/threat-distribution`);
            if (!response.ok) throw new Error('Network response was not ok');
            const dataFromDB = await response.json();

            const labels = dataFromDB.map(item => item.threat_type);
            const totals = dataFromDB.map(item => item.total);
            const backgroundColors = labels.map(label => colorMapping[label] || '#9e9e9e');

            window.distributionChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels.length > 0 ? labels : ['No Data'],
                    datasets: [{
                        label: 'Total Detected',
                        data: totals.length > 0 ? totals : [0],
                        backgroundColor: backgroundColors
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { beginAtZero: true, ticks: { stepSize: 1 } },
                        x: { grid: { display: false } }
                    }
                }
            });

        } catch (error) {
            console.error('Error fetching threat distribution configuration:', error);
        }
    }

    // ==========================================
    // 4. TOP THREAT ACTORS (THREAT ANALYTICS)
    // ==========================================
    async function fetchTopActors() {
        const actorsListContainer = document.querySelector('.alerts-list');
        const pageTitle = document.querySelector('.page-title-section h1');
        
        // Gamitan ng .trim() at .includes() para iwas collision sa any whitespace/nested elements sa H1 header
        if (!actorsListContainer || !pageTitle || !pageTitle.innerText.trim().includes("Threat Analytics")) return;

        try {
            const response = await fetch(`${API_BASE}/top-actors`);
            if (!response.ok) throw new Error('Failed to fetch threat actors');
            const actors = await response.json();

            actorsListContainer.innerHTML = '';
            
            if (!actors || actors.length === 0) {
                actorsListContainer.innerHTML = '<li><p class="meta">No threat actors recorded yet.</p></li>';
                return;
            }

            actors.forEach((actor, index) => {
                const li = document.createElement('li');
                const badgeColor = actor.max_risk === 'High Risk' ? 'var(--accent-red)' : 'var(--accent-orange)';
                
                li.innerHTML = `
                    <div class="alert-icon" style="background-color: ${badgeColor}">${index + 1}</div>
                    <div class="alert-info">
                        <h4>Target/Actor: ${actor.threat_actor}</h4>
                        <span class="meta">${actor.incidents} detected system breaches (${actor.max_risk})</span>
                    </div>
                `;
                actorsListContainer.appendChild(li);
            });
        } catch (error) {
            console.error('Error fetching Top Threat Actors:', error);
        }
    }

    // ==========================================
    // 5. LIVE POLICY MANAGEMENT FUNCTIONS
    // ==========================================
    async function loadActivePolicies() {
        const tbody = document.getElementById('dynamicPolicyTableBody');
        if (!tbody) return;

        try {
            const res = await fetch(`${API_BASE}/policies`);
            if (!res.ok) throw new Error('Failed to load system policies');
            const policies = await res.json();

            tbody.innerHTML = '';

            if (!policies || policies.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">No operational policies configured in dlp_db database.</td></tr>`;
                return;
            }

            policies.forEach(p => {
                const tr = document.createElement('tr');
                
                let statusSpan = `<span class="status-green">Active</span>`;
                if (p.status === 'Alert Only') {
                    statusSpan = `<span class="status-green" style="color: var(--accent-orange)">Alert Only</span>`;
                } else if (p.status === 'Disabled') {
                    statusSpan = `<span style="color: var(--text-muted); font-weight: 500;">Disabled</span>`;
                }

                tr.innerHTML = `
                    <td style="font-weight: 600; color: #1e3a5f;">${p.policy_name}</td>
                    <td><span style="background: #e2e8f0; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 500;">${p.category}</span></td>
                    <td>${statusSpan}</td>
                    <td>${p.last_modified || 'N/A'}</td>
                    <td style="text-align: right; padding-right: 20px;">
                        <button class="btn-blue-outline edit-policy-btn" data-id="${p.id}" style="padding: 4px 10px; font-size: 0.8rem;">Edit</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });

            // Re-bind listeners para sa mga dynamic buttons
            document.querySelectorAll('.edit-policy-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const policyId = e.target.getAttribute('data-id');
                    alert(`Loading active structural attributes for Policy ID: ${policyId}`);
                });
            });

        } catch (err) {
            console.error('Failed to communicate with API Server endpoint:', err);
        }
    }

    function initPolicyManagement() {
        const createBtn = document.getElementById('createNewPolicyBtn');
        const overlayModal = document.getElementById('policyModalOverlay');
        const dismissBtn = document.getElementById('dismissModalBtn');
        const entryForm = document.getElementById('policyDeploymentForm');

        // I-load ang listahan ng records kung nasa tamang page view window
        if (document.getElementById('dynamicPolicyTableBody')) {
            loadActivePolicies();
        }

        if (!createBtn || !overlayModal) return;

        createBtn.addEventListener('click', () => {
            overlayModal.style.display = 'flex';
        });

        if (dismissBtn) {
            dismissBtn.addEventListener('click', () => {
                overlayModal.style.display = 'none';
                if (entryForm) entryForm.reset();
            });
        }

        if (entryForm) {
            entryForm.addEventListener('submit', async (e) => {
                e.preventDefault();

                const payload = {
                    policy_name: document.getElementById('policyFormName').value,
                    category: document.getElementById('policyFormCategory').value,
                    status: document.getElementById('policyFormStatus').value
                };

                try {
                    const res = await fetch(`${API_BASE}/policies`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });

                    if (res.ok) {
                        overlayModal.style.display = 'none';
                        entryForm.reset();
                        loadActivePolicies(); 
                    } else {
                        const errData = await res.json();
                        alert(`Deployment Error: ${errData.error || 'Server rejected request layer execution.'}`);
                    }
                } catch (err) {
                    console.error('API endpoint transmission failure:', err);
                }
            });
        }
    }

    // ==========================================
    // 6. ENCRYPTION CONTROL PANEL (ENCRYPTION)
    // ==========================================
    function initEncryptionControl() {
        const grid = document.querySelector('.encryption-settings-grid');
        if (!grid) return;

        const addFolderBtn = grid.querySelector('.card:nth-child(1) .btn-blue');
        if (addFolderBtn) {
            addFolderBtn.addEventListener('click', () => {
                const newPath = prompt('Enter absolute path directory to apply automated encryption rule:');
                if (newPath && newPath.trim() !== "") {
                    const violationsList = grid.querySelector('.violations-list');
                    if (violationsList) {
                        const li = document.createElement('li');
                        li.innerHTML = `<i class="fas fa-folder" style="color: var(--accent-yellow)"></i> ${newPath.trim()}`;
                        violationsList.appendChild(li);
                    }
                }
            });
        }

        const manageKeysBtn = grid.querySelector('.card:nth-child(2) .btn-blue');
        if (manageKeysBtn) {
            manageKeysBtn.addEventListener('click', () => {
                alert('Redirecting to Key Management Console...\nAccessing Cloud KMS integration layer.');
            });
        }
    }

    // ==========================================
    // 7. INCIDENT RESPONSE SUBMODULE
    // ==========================================
    function initIncidentResponse() {
        const pageTitle = document.querySelector('.page-title-section h1');
        if (!pageTitle || !pageTitle.innerText.trim().includes("Incident Response")) return;

        const incidentTable = document.querySelector('.policy-table');
        if (!incidentTable) return;

        incidentTable.addEventListener('click', (e) => {
            const target = e.target;
            if (target.classList.contains('btn-red') || target.classList.contains('btn-blue')) {
                const row = target.closest('tr');
                const incidentID = row.cells[0].innerText;
                const description = row.cells[1].innerText;

                if (target.classList.contains('btn-red')) {
                    const actionChosen = confirm(`[CRITICAL] System breach detected on ${incidentID}.\nDescription: ${description}\n\nClick OK to isolate the host/database immediately, or Cancel to skip.`);
                    if (actionChosen) {
                        alert(`${incidentID} containment protocol activated. Connection isolated.`);
                        row.cells[3].innerText = "Mitigated";
                        target.disabled = true;
                        target.style.opacity = "0.5";
                        target.innerText = "Isolated";
                    }
                } else if (target.classList.contains('btn-blue')) {
                    alert(`Opening Incident logs for ${incidentID}...\nReviewing: "${description}"`);
                }
            }
        });
    }

    // ==========================================
    // 8. REPORTS SECURE DOWNLOADERS
    // ==========================================
    function initReportsPage() {
        const pageTitle = document.querySelector('.page-title-section h1');
        if (!pageTitle || !pageTitle.innerText.trim().includes("Reports")) return;

        const downloadButtons = document.querySelectorAll('.btn-text-blue');
        downloadButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const button = e.target;
                const listItem = button.closest('li');
                const fileName = listItem.textContent.replace('Download', '').trim();

                button.innerText = "Downloading...";
                button.style.pointerEvents = "none";
                button.style.opacity = "0.6";

                setTimeout(() => {
                    alert(`Success: "${fileName}" has been downloaded securely to your local machine.`);
                    button.innerText = "Download";
                    button.style.pointerEvents = "auto";
                    button.style.opacity = "1";
                }, 1200);
            });
        });
    }

    // ==========================================
    // 9. LOGS AUDIT TRAIL DATA EXPORTER
    // ==========================================
    function initActivityLogsPage() {
        const pageTitle = document.querySelector('.page-title-section h1');
        if (!pageTitle || !pageTitle.innerText.trim().includes("Activity Logs")) return;

        const exportBtn = document.querySelector('.action-buttons .btn-blue-outline');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                const logRows = document.querySelectorAll('.policy-table tbody tr');
                const logCount = logRows.length;

                exportBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Exporting...';
                exportBtn.style.pointerEvents = "none";

                setTimeout(() => {
                    alert(`Audit Trail Exported Successfully!\nGenerated security_logs.csv containing ${logCount} event rows.`);
                    exportBtn.innerHTML = '<i class="fas fa-download"></i> Export CSV';
                    exportBtn.style.pointerEvents = "auto";
                }, 1500);
            });
        }
    }

    // ==========================================
    // 10. SYSTEM SETTINGS PANEL RULES
    // ==========================================
    function initSettingsPage() {
        const pageTitle = document.querySelector('.page-title-section h1');
        if (!pageTitle || !pageTitle.innerText.trim().includes("System Settings")) return;

        const grid = document.querySelector('.middle-grid');
        if (!grid) return;

        const generalCard = grid.querySelector('.card:nth-child(1)');
        if (generalCard) {
            const updateGeneralBtn = generalCard.querySelector('.btn-blue');
            const nameValueSpan = generalCard.querySelector('.detail-item:nth-child(1) .value');

            if (updateGeneralBtn && nameValueSpan) {
                updateGeneralBtn.addEventListener('click', () => {
                    const currentName = nameValueSpan.innerText;
                    const newName = prompt('Enter new System Name identifier:', currentName);
                    if (newName && newName.trim() !== "") {
                        nameValueSpan.innerText = newName.trim().toUpperCase();
                        alert('System configuration updated successfully.');
                    }
                });
            }
        }

        const securityCard = grid.querySelector('.card:nth-child(2)');
        if (securityCard) {
            const manageSecurityBtn = securityCard.querySelector('.btn-blue');
            const statusSpan = securityCard.querySelector('.detail-item:nth-child(1) .value');

            if (manageSecurityBtn && statusSpan) {
                manageSecurityBtn.addEventListener('click', () => {
                    const toggle2FA = confirm('Security Action Requested:\nDo you want to toggle or re-configure Multi-Factor Authentication (2FA) rules?');
                    if (toggle2FA) {
                        if (statusSpan.classList.contains('status-green')) {
                            statusSpan.classList.remove('status-green');
                            statusSpan.style.color = 'var(--accent-red)';
                            statusSpan.innerText = 'Disabled';
                            alert('Security Warning: 2FA Authentication has been disabled.');
                        } else {
                            statusSpan.classList.add('status-green');
                            statusSpan.removeAttribute('style');
                            statusSpan.innerText = 'Enabled';
                            alert('Success: 2FA Authentication is now fully operational.');
                        }
                    }
                });
            }
        }
    }

    // ==========================================
    // GLOBAL UI CONTROLS
    // ==========================================
    const closeIcon = document.querySelector(".close-icon");
    if (closeIcon) {
        closeIcon.addEventListener("click", function () {
            const chartCard = closeIcon.closest(".chart-card");
            if (chartCard) {
                chartCard.style.transition = "opacity 0.3s ease";
                chartCard.style.opacity = "0";
                setTimeout(() => chartCard.style.display = "none", 300);
            }
        });
    }

    const notificationIcon = document.querySelector(".notification-icon");
    if (notificationIcon) {
        notificationIcon.addEventListener("click", () => {
            alert("Notification: 1 unread security alert pending review.");
        });
    }

    // ==========================================
    // ELEMENT-BASED ROUTER EXECUTION
    // ==========================================
    if (document.getElementById('threatLineChart')) {
        initLineChart();
    }
    // I-load ang stats sa main dashboard
    if (document.querySelector('.stat-cards-grid')) {
        fetchDashboardStats();
    }
    if (alertsList) {
        fetchAlerts();
    }
    fetchLogs();

    if (document.getElementById('threatDistributionChart')) {
        initDistributionChart();
        fetchTopActors();
    }

    // AUTO-REFRESH: Tuwing 10 segundo para magmukhang live ang data
    if (document.querySelector('.stat-cards-grid') || alertsList) {
        setInterval(() => {
            fetchDashboardStats();
            if (alertsList) fetchAlerts();
            fetchLogs();
        }, 10000);
    }

    initPolicyManagement();

    if (document.querySelector('.encryption-settings-grid')) {
        initEncryptionControl();
    }
    initIncidentResponse();
    initReportsPage();
    initActivityLogsPage();
    initSettingsPage();
});