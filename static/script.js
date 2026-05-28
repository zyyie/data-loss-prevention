document.addEventListener('DOMContentLoaded', () => {
    // ==========================================
    // SIDEBAR TOGGLE FUNCTIONALITY
    // ==========================================
    const sidebar = document.querySelector('.sidebar');
    const sidebarToggle = document.getElementById('sidebarToggle');
    
    if (sidebar && sidebarToggle) {
        // I-load ang saved state mula sa localStorage
        const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
        if (isCollapsed) {
            sidebar.classList.add('collapsed');
        }

        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
            // I-save ang state sa localStorage
            localStorage.setItem('sidebarCollapsed', sidebar.classList.contains('collapsed'));
        });
    }

    const API_BASE = '/api';
    const alertsList = document.getElementById('alertsList');
    const logsList = document.getElementById('activityLogsList');

    // ==========================================
    // 0. DASHBOARD STAT CARDS (CLICKABLE)
    // ==========================================
    function initDashboardStatCardLinks() {
        document.querySelectorAll('.stat-card-link').forEach((card) => {
            const target = card.getAttribute('data-href') || card.getAttribute('href');
            if (!target) return;
            card.setAttribute('tabindex', '0');
            const navigate = () => window.location.assign(target);
            card.addEventListener('click', navigate);
            card.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    navigate();
                }
            });
        });
    }

    // ==========================================
    // 0b. FETCH & RENDER DASHBOARD STATS
    // ==========================================
    async function fetchDashboardStats() {
        const statCards = document.querySelector('.stat-cards-grid');
        if (!statCards) return;

        try {
            const response = await fetch(`${API_BASE}/stats`);
            if (!response.ok) throw new Error('Failed to fetch stats');
            const data = await response.json();

            const filesSecuredEl = document.getElementById('filesSecured');
            const threatsBlockedEl = document.getElementById('threatsBlocked');
            const incidentsDetectedEl = document.getElementById('incidentsDetected');
            const complianceStatusEl = document.getElementById('complianceStatus');

            if (filesSecuredEl) filesSecuredEl.innerText = data.files_secured ?? 0;
            if (threatsBlockedEl) threatsBlockedEl.innerText = data.blocked_threats ?? 0;
            if (incidentsDetectedEl) incidentsDetectedEl.innerText = data.incidents_detected ?? 0;
            if (complianceStatusEl) {
                complianceStatusEl.innerText = data.compliance_status || 'Unknown';
                complianceStatusEl.classList.remove('green', 'status-green', 'status-red');
                if (data.compliance_class === 'status-green') {
                    complianceStatusEl.classList.add('green', 'status-green');
                } else if (data.compliance_class === 'status-red') {
                    complianceStatusEl.classList.add('status-red');
                }
            }

            const incidentBigCount = document.getElementById('incidentBigCount');
            if (incidentBigCount) incidentBigCount.innerText = data.incidents_detected ?? 0;

            const threatCredentialCount = document.getElementById('threatCredentialCount');
            const threatPolicyCount = document.getElementById('threatPolicyCount');
            const threatExposureCount = document.getElementById('threatExposureCount');
            if (threatCredentialCount) threatCredentialCount.innerText = data.credential_misuse ?? 0;
            if (threatPolicyCount) threatPolicyCount.innerText = data.policy_bypass ?? 0;
            if (threatExposureCount) threatExposureCount.innerText = data.data_exposure ?? 0;

            const filesEncryptedCount = document.getElementById('filesEncryptedCount');
            const encryptionComplianceStatus = document.getElementById('encryptionComplianceStatus');
            if (filesEncryptedCount) filesEncryptedCount.innerText = data.files_secured ?? 0;
            if (encryptionComplianceStatus) {
                encryptionComplianceStatus.innerText = data.encryption_compliance || 'Pending';
                encryptionComplianceStatus.classList.remove('text-green', 'text-orange');
                encryptionComplianceStatus.classList.add(
                    data.encryption_compliance_class || 'text-orange'
                );
            }

        } catch (error) {
            console.error('Error updating dashboard stats:', error);
        }
    }

    async function fetchPolicyViolations() {
        const violationsList = document.getElementById('policyViolationsList');
        if (!violationsList) return;

        try {
            const response = await fetch(`${API_BASE}/alerts`);
            if (!response.ok) throw new Error('Failed to fetch policy violations');
            const alerts = await response.json();
            const violations = (alerts || []).filter((alert) => {
                const status = (alert.status || '').toLowerCase();
                const activity = (alert.activity || '').toLowerCase();
                const threatType = (alert.threat_type || '').toLowerCase();
                return (
                    status === 'prompted' ||
                    status === 'tagged' ||
                    threatType.includes('policy') ||
                    activity.includes('policy') ||
                    activity.includes('pii') ||
                    activity.includes('export') ||
                    activity.includes('usb')
                );
            }).slice(0, 5);

            if (violations.length === 0) {
                violationsList.innerHTML = '<li class="meta">No active policy violations detected.</li>';
                return;
            }

            violationsList.innerHTML = violations.map((alert) => {
                const label = alert.activity || alert.details || 'Policy violation detected';
                return `<li><input type="checkbox" checked disabled> ${label}</li>`;
            }).join('');
        } catch (error) {
            console.error('Error loading policy violations:', error);
            violationsList.innerHTML = '<li class="meta">Unable to load policy violations.</li>';
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
                    <i class="fas ${log.icon || 'fa-clipboard-list'}" style="color: #1e3a5f; width: 20px;"></i>
                    <div class="alert-info" style="flex: 1;">
                        <h4 style="font-weight: 500; margin: 0 0 4px 0;">${log.activity}</h4>
                        <p class="meta" style="margin: 0;">${log.source || 'System'} · ${log.user || 'System'}</p>
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
    async function initLineChart() {
        const chartElement = document.getElementById('threatLineChart');
        if (!chartElement) return;
        const ctx = chartElement.getContext('2d');

        if (window.threatChart) window.threatChart.destroy();

        const gradient = ctx.createLinearGradient(0, 0, 0, 150);
        gradient.addColorStop(0, 'rgba(33, 150, 243, 0.5)');
        gradient.addColorStop(1, 'rgba(33, 150, 243, 0)');

        let labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'];
        let values = [0, 0, 0, 0, 0];

        try {
            const response = await fetch(`${API_BASE}/threat-trend`);
            if (response.ok) {
                const trendData = await response.json();
                labels = trendData.labels || labels;
                values = trendData.data || values;
            }
        } catch (error) {
            console.error('Error loading threat trend:', error);
        }

        const maxValue = Math.max(...values, 1);

        window.threatChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Threats',
                    data: values,
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
                    y: {
                        beginAtZero: true,
                        suggestedMax: maxValue + 1,
                        ticks: { stepSize: 1, color: '#aaa', font: { size: 10 }, precision: 0 }
                    },
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
                const actorName = actor.actor || actor.threat_actor || 'Unknown Actor';
                
                li.innerHTML = `
                    <div class="alert-icon" style="background-color: ${badgeColor}">${index + 1}</div>
                    <div class="alert-info">
                        <h4>Target/Actor: ${actorName}</h4>
                        <span class="meta">${actor.incidents} detected system breaches (${actor.max_risk})</span>
                    </div>
                `;
                actorsListContainer.appendChild(li);
            });
        } catch (error) {
            console.error('Error fetching Top Threat Actors:', error);
        }
    }

    async function initThreatInsights() {
        const totalAlertsEl = document.getElementById('threatTotalAlerts');
        if (!totalAlertsEl) return;

        const highRiskEl = document.getElementById('threatHighRisk');
        const topTypeEl = document.getElementById('threatTopType');
        const topActorEl = document.getElementById('threatTopActor');
        const summaryEl = document.getElementById('threatSummaryText');
        const riskListEl = document.getElementById('riskInterpretationList');
        const actionsListEl = document.getElementById('recommendedActionsList');

        try {
            const [alertsRes, distRes, actorsRes] = await Promise.all([
                fetch(`${API_BASE}/alerts`),
                fetch(`${API_BASE}/threat-distribution`),
                fetch(`${API_BASE}/top-actors`),
            ]);

            if (!alertsRes.ok || !distRes.ok || !actorsRes.ok) {
                throw new Error('Failed to load threat intelligence data.');
            }

            const alerts = await alertsRes.json();
            const distribution = await distRes.json();
            const actors = await actorsRes.json();

            const totalAlerts = alerts.length;
            const highRisk = alerts.filter((a) => (a.risk || '').toLowerCase().includes('high')).length;
            const blocked = alerts.filter((a) => (a.status || '').toLowerCase() === 'blocked').length;
            const blockedRate = totalAlerts > 0 ? Math.round((blocked / totalAlerts) * 100) : 0;

            const topTypeItem = distribution.reduce((max, item) => {
                if (!max || item.total > max.total) return item;
                return max;
            }, null);

            const topActor = actors[0]?.actor || actors[0]?.threat_actor || 'No actor data';
            const topActorIncidents = actors[0]?.incidents || 0;
            const topType = topTypeItem?.threat_type || 'No type data';
            const topTypeCount = topTypeItem?.total || 0;

            totalAlertsEl.textContent = String(totalAlerts);
            highRiskEl.textContent = String(highRisk);
            topTypeEl.textContent = topType;
            topActorEl.textContent = topActor;

            summaryEl.textContent = `Current telemetry shows ${totalAlerts} total alerts, with ${highRisk} high-risk incidents and a ${blockedRate}% automatic block rate. The dominant pattern is ${topType} (${topTypeCount} events), while ${topActor} is currently the most active threat actor.`;

            riskListEl.innerHTML = `
                <li>${highRisk > 0 ? `${highRisk} high-risk incidents require immediate triage and containment.` : 'No high-risk incidents recorded in this cycle.'}</li>
                <li>${topType !== 'No type data' ? `${topType} is the leading threat class, indicating concentrated pressure on a single attack path.` : 'Threat type signals are still building; continue collecting telemetry.'}</li>
                <li>${topActorIncidents > 0 ? `${topActor} has ${topActorIncidents} linked events and should be added to watchlist monitoring.` : 'No persistent actor identified yet.'}</li>
            `;

            actionsListEl.innerHTML = `
                <li>Prioritize detections and containment rules for ${topType !== 'No type data' ? topType : 'high-frequency threat categories'}.</li>
                <li>Run targeted investigation and access review for ${topActor !== 'No actor data' ? topActor : 'newly emerging actors'}.</li>
                <li>Harden controls for repeated high-risk paths and validate response playbooks with the incident team.</li>
            `;
        } catch (error) {
            console.error('Error loading threat insights:', error);
            if (summaryEl) {
                summaryEl.textContent = 'Threat intelligence summary is temporarily unavailable. Please retry after data refresh.';
            }
            if (riskListEl) {
                riskListEl.innerHTML = '<li>Risk interpretation is unavailable while telemetry is loading.</li>';
            }
            if (actionsListEl) {
                actionsListEl.innerHTML = '<li>Recommended actions will appear once telemetry is available.</li>';
            }
        }
    }

    // ==========================================
    // 5. LIVE POLICY MANAGEMENT FUNCTIONS
    // ==========================================
    async function loadActivePolicies(onEdit) {
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
            document.querySelectorAll('.edit-policy-btn').forEach((btn) => {
                btn.addEventListener('click', (e) => {
                    const policyId = Number(e.currentTarget.getAttribute('data-id'));
                    const policy = policies.find((item) => Number(item.id) === policyId);
                    if (policy && typeof onEdit === 'function') {
                        onEdit(policy);
                    }
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
        const cancelBtn = document.getElementById('cancelModalBtn');
        const deleteBtn = document.getElementById('deleteModalBtn');
        const entryForm = document.getElementById('policyDeploymentForm');
        const modalTitle = overlayModal?.querySelector('.card-header h3');
        const submitBtn = entryForm?.querySelector('button[type="submit"]');
        let editingPolicyId = null;

        function setCreateMode() {
            editingPolicyId = null;
            if (modalTitle) modalTitle.textContent = 'Deploy New Policy';
            if (submitBtn) submitBtn.textContent = 'Deploy Rule';
            if (deleteBtn) deleteBtn.style.display = 'none';
        }

        function startEditMode(policy) {
            if (!entryForm || !overlayModal) return;
            editingPolicyId = policy.id;
            document.getElementById('policyFormName').value = policy.policy_name || '';
            document.getElementById('policyFormCategory').value = policy.category || 'DLP';
            document.getElementById('policyFormStatus').value = policy.status || 'Active';
            if (modalTitle) modalTitle.textContent = `Edit Policy #${policy.id}`;
            if (submitBtn) submitBtn.textContent = 'Save Changes';
            if (deleteBtn) deleteBtn.style.display = 'inline-block';
            overlayModal.style.display = 'flex';
        }

        // I-load ang listahan ng records kung nasa tamang page view window
        if (document.getElementById('dynamicPolicyTableBody')) {
            loadActivePolicies(startEditMode);
        }

        // Don't require create button; edit flow should still work.
        if (!overlayModal || !entryForm) return;

        if (createBtn) {
            createBtn.addEventListener('click', () => {
                setCreateMode();
                entryForm.reset();
                overlayModal.style.display = 'flex';
            });
        }

        if (dismissBtn) {
            dismissBtn.addEventListener('click', () => {
                overlayModal.style.display = 'none';
                entryForm.reset();
                setCreateMode();
            });
        }
        if (cancelBtn) {
            cancelBtn.addEventListener('click', () => {
                overlayModal.style.display = 'none';
                entryForm.reset();
                setCreateMode();
            });
        }

        // Click outside modal closes it
        overlayModal.addEventListener('click', (e) => {
            if (e.target !== overlayModal) return;
            overlayModal.style.display = 'none';
            entryForm.reset();
            setCreateMode();
        });

        // ESC closes modal
        document.addEventListener('keydown', (e) => {
            if (e.key !== 'Escape') return;
            if (overlayModal.style.display !== 'flex') return;
            overlayModal.style.display = 'none';
            entryForm.reset();
            setCreateMode();
        });
        if (deleteBtn) {
            deleteBtn.addEventListener('click', async () => {
                if (editingPolicyId === null) return;
                const shouldDelete = confirm('Delete this policy permanently?');
                if (!shouldDelete) return;
                if (entryForm.dataset.submitting === 'true') return;
                entryForm.dataset.submitting = 'true';

                try {
                    const res = await fetch(`${API_BASE}/policies/${editingPolicyId}`, {
                        method: 'DELETE',
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        alert(data.error || 'Failed to delete policy.');
                        return;
                    }
                    overlayModal.style.display = 'none';
                    if (entryForm) entryForm.reset();
                    setCreateMode();
                    loadActivePolicies(startEditMode);
                } catch (err) {
                    console.error('Policy deletion failed:', err);
                    alert('Network error while deleting policy.');
                } finally {
                    entryForm.dataset.submitting = 'false';
                }
            });
        }

        entryForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (entryForm.dataset.submitting === 'true') return;
            entryForm.dataset.submitting = 'true';

                const payload = {
                    policy_name: document.getElementById('policyFormName').value,
                    category: document.getElementById('policyFormCategory').value,
                    status: document.getElementById('policyFormStatus').value
                };

            try {
                const isEdit = editingPolicyId !== null;
                const endpoint = isEdit ? `${API_BASE}/policies/${editingPolicyId}` : `${API_BASE}/policies`;
                const method = isEdit ? 'PUT' : 'POST';
                const res = await fetch(endpoint, {
                    method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                if (res.ok) {
                    overlayModal.style.display = 'none';
                    entryForm.reset();
                    setCreateMode();
                    loadActivePolicies(startEditMode);
                } else {
                    const errData = await res.json();
                    alert(`Deployment Error: ${errData.error || 'Server rejected request layer execution.'}`);
                }
            } catch (err) {
                console.error('API endpoint transmission failure:', err);
            } finally {
                entryForm.dataset.submitting = 'false';
            }
        });
    }

    // ==========================================
    // 6. ENCRYPTION CONTROL PANEL (ENCRYPTION)
    // ==========================================
    function initEncryptionControl() {
        const grid = document.querySelector('.encryption-settings-grid');
        if (!grid) return;

        // Encryption page has its own modal workflow. Skip legacy prompt/alert bindings.
        if (document.getElementById('folderModalOverlay') || document.getElementById('folderConfigForm')) {
            return;
        }

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

        // Incident page has its own modal + API workflow in incident.html.
        if (document.getElementById('incidentResponseForm')) return;

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
                    // Replace blocking popup with inline visual feedback.
                    row.style.backgroundColor = '#f8fafc';
                    row.cells[3].innerText = row.cells[3].innerText.trim() || 'Reviewing';
                    target.innerText = 'Reviewed';
                    target.style.opacity = '0.85';
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
        const pageTitle = document.querySelector('.top-nav.top-nav-title-only .page-title-section h1');
        if (!pageTitle || !pageTitle.innerText.trim().includes('Activity Logs')) return;
        // Export flow is handled in logs.html (no browser alert / auto-download).
    }

    // ==========================================
    // 9b. SIDEBAR DROPDOWN TOGGLE
    // ==========================================
    function initSidebarDropdowns() {
        document.querySelectorAll('.has-dropdown > a').forEach((link) => {
            const chevron = link.querySelector('.fa-chevron-down');
            if (!chevron) return;
            link.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const currentDropdown = link.closest('.has-dropdown');
                if (!currentDropdown) return;
                const shouldOpen = !currentDropdown.classList.contains('open');

                // Close siblings at the same level before opening the current one.
                const siblingDropdowns = currentDropdown.parentElement?.querySelectorAll(':scope > .has-dropdown.open') || [];
                siblingDropdowns.forEach((item) => {
                    if (item !== currentDropdown) item.classList.remove('open');
                });

                currentDropdown.classList.toggle('open', shouldOpen);
            });
        });
    }

    // ==========================================
    // 9c. ACCOUNT SETTINGS DROPDOWN
    // ==========================================
    function initPasswordToggles() {
        document.querySelectorAll('.password-toggle').forEach((btn) => {
            btn.addEventListener('click', () => {
                const input = document.getElementById(btn.dataset.target);
                const icon = btn.querySelector('i');
                if (!input || !icon) return;

                const show = input.type === 'password';
                input.type = show ? 'text' : 'password';
                icon.classList.toggle('fa-eye', !show);
                icon.classList.toggle('fa-eye-slash', show);
            });
        });
    }

    function initChangePasswordForm() {
        const form = document.getElementById('changePasswordForm');
        if (!form) return;

        initPasswordToggles();

        if (window.location.hash === '#change-password') {
            document.getElementById('changePasswordPanel')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        const isResetFlow = form.dataset.passwordReset === 'true';

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const newPass = document.getElementById('newPassword')?.value || '';
            const confirmPass = document.getElementById('confirmPassword')?.value || '';
            const currentPass = document.getElementById('currentPassword')?.value || '';

            if (newPass !== confirmPass) {
                alert('New password and confirmation do not match.');
                return;
            }

            const payload = {
                new_password: newPass,
                confirm_password: confirmPass,
            };
            if (!isResetFlow) {
                payload.current_password = currentPass;
            }

            const submitBtn = form.querySelector('.change-password-submit');
            if (submitBtn) submitBtn.disabled = true;

            try {
                const res = await fetch('/api/change-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                const data = await res.json();
                if (!res.ok || !data.success) {
                    alert(data.error || 'Could not update password.');
                    return;
                }
                alert(data.message || 'Password updated successfully.');
                if (isResetFlow) {
                    window.location.href = '/';
                    return;
                }
                form.reset();
                document.querySelectorAll('.password-toggle i').forEach((icon) => {
                    icon.classList.add('fa-eye');
                    icon.classList.remove('fa-eye-slash');
                });
            } catch {
                alert('Network error. Please try again.');
            } finally {
                if (submitBtn) submitBtn.disabled = false;
            }
        });
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

    function initUserManagementPage() {
        const usersPanel = document.querySelector('.users-settings-panel');
        if (!usersPanel) return;

        const usersList = document.getElementById('usersList');
        const addNewUserBtn = document.getElementById('addNewUserBtn');
        const reviewRolesBtn = document.getElementById('reviewRolesBtn');
        const totalCountEl = document.getElementById('usersTotalCount');
        const activeCountEl = document.getElementById('usersActiveCount');
        const adminsCountEl = document.getElementById('usersAdminsCount');
        const addUserModal = document.getElementById('addUserModalOverlay');
        const addUserForm = document.getElementById('addUserForm');
        const closeAddUserModal = document.getElementById('closeAddUserModal');
        const cancelAddUserModal = document.getElementById('cancelAddUserModal');
        const newUserNameInput = document.getElementById('newUserName');
        const newUserRoleInput = document.getElementById('newUserRole');
        const newUserStatusSelect = document.getElementById('newUserStatus');
        const reviewRolesModal = document.getElementById('reviewRolesModalOverlay');
        const reviewRolesForm = document.getElementById('reviewRolesForm');
        const closeReviewRolesModal = document.getElementById('closeReviewRolesModal');
        const cancelReviewRolesModal = document.getElementById('cancelReviewRolesModal');
        const reviewUserSelect = document.getElementById('reviewUserSelect');
        const reviewRoleSelect = document.getElementById('reviewRoleSelect');
        const reviewStatusSelect = document.getElementById('reviewStatusSelect');

        if (!usersList || !addNewUserBtn) return;

        function refreshUserStats() {
            const rows = Array.from(usersList.querySelectorAll('.user-row'));
            const activeUsers = rows.filter((row) => row.querySelector('.user-status')?.classList.contains('active')).length;
            const adminUsers = rows.filter((row) => {
                const roleText = (row.querySelector('.user-main p')?.innerText || '').toLowerCase();
                return roleText.includes('admin');
            }).length;

            if (totalCountEl) totalCountEl.textContent = String(rows.length);
            if (activeCountEl) activeCountEl.textContent = String(activeUsers);
            if (adminsCountEl) adminsCountEl.textContent = String(adminUsers);
        }

        function closeUserModal() {
            if (!addUserModal || !addUserForm) return;
            addUserModal.classList.remove('show');
            addUserForm.reset();
            if (newUserStatusSelect) newUserStatusSelect.value = 'active';
        }

        function getUserRows() {
            return Array.from(usersList.querySelectorAll('.user-row'));
        }

        function closeReviewModal() {
            if (!reviewRolesModal || !reviewRolesForm) return;
            reviewRolesModal.classList.remove('show');
            reviewRolesForm.reset();
            if (reviewUserSelect) reviewUserSelect.innerHTML = '';
        }

        function syncReviewFormFromSelectedUser() {
            if (!reviewUserSelect || !reviewRoleSelect || !reviewStatusSelect) return;
            const selectedIndex = Number(reviewUserSelect.value);
            const rows = getUserRows();
            const row = rows[selectedIndex];
            if (!row) return;

            const roleText = row.querySelector('.user-main p')?.innerText?.trim() || 'Security Analyst';
            const isPending = row.querySelector('.user-status')?.classList.contains('pending');
            reviewRoleSelect.value = roleText;
            reviewStatusSelect.value = isPending ? 'pending' : 'active';
        }

        addNewUserBtn.addEventListener('click', () => {
            if (!addUserModal) return;
            addUserModal.classList.add('show');
            if (newUserNameInput) {
                newUserNameInput.disabled = false;
                newUserNameInput.removeAttribute('readonly');
                setTimeout(() => {
                    newUserNameInput.focus();
                    newUserNameInput.click();
                }, 10);
            }
        });

        if (closeAddUserModal) {
            closeAddUserModal.addEventListener('click', closeUserModal);
        }

        if (cancelAddUserModal) {
            cancelAddUserModal.addEventListener('click', closeUserModal);
        }

        if (addUserModal) {
            addUserModal.addEventListener('click', (e) => {
                if (e.target === addUserModal) closeUserModal();
            });
        }

        if (addUserForm) {
            addUserForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const name = (newUserNameInput?.value || '').trim();
                const role = (newUserRoleInput?.value || '').trim() || 'Security Analyst';
                const statusClass = (newUserStatusSelect?.value || 'active') === 'pending' ? 'pending' : 'active';
                const statusText = statusClass === 'pending' ? 'Pending Invite' : 'Active';

                if (!name) return;

                const row = document.createElement('div');
                row.className = 'user-row';
                row.innerHTML = `
                    <div class="user-main">
                        <h4>${name}</h4>
                        <p>${role}</p>
                    </div>
                    <span class="user-status ${statusClass}">${statusText}</span>
                `;
                usersList.appendChild(row);
                refreshUserStats();
                closeUserModal();
            });
        }

        if (reviewRolesBtn) {
            reviewRolesBtn.addEventListener('click', () => {
                if (!reviewRolesModal || !reviewUserSelect) return;
                const rows = getUserRows();
                reviewUserSelect.innerHTML = rows.map((row, index) => {
                    const name = row.querySelector('.user-main h4')?.innerText?.trim() || `User ${index + 1}`;
                    return `<option value="${index}">${name}</option>`;
                }).join('');

                reviewRolesModal.classList.add('show');
                syncReviewFormFromSelectedUser();
            });
        }

        if (reviewUserSelect) {
            reviewUserSelect.addEventListener('change', syncReviewFormFromSelectedUser);
        }

        if (closeReviewRolesModal) {
            closeReviewRolesModal.addEventListener('click', closeReviewModal);
        }

        if (cancelReviewRolesModal) {
            cancelReviewRolesModal.addEventListener('click', closeReviewModal);
        }

        if (reviewRolesModal) {
            reviewRolesModal.addEventListener('click', (e) => {
                if (e.target === reviewRolesModal) closeReviewModal();
            });
        }

        if (reviewRolesForm) {
            reviewRolesForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const selectedIndex = Number(reviewUserSelect?.value || 0);
                const rows = getUserRows();
                const targetRow = rows[selectedIndex];
                if (!targetRow) return;

                const selectedRole = reviewRoleSelect?.value || 'Security Analyst';
                const selectedStatus = reviewStatusSelect?.value === 'pending' ? 'pending' : 'active';
                const statusText = selectedStatus === 'pending' ? 'Pending Invite' : 'Active';

                const roleEl = targetRow.querySelector('.user-main p');
                const statusEl = targetRow.querySelector('.user-status');

                if (roleEl) roleEl.innerText = selectedRole;
                if (statusEl) {
                    statusEl.classList.remove('active', 'pending');
                    statusEl.classList.add(selectedStatus);
                    statusEl.innerText = statusText;
                }

                refreshUserStats();
                closeReviewModal();
            });
        }
    }

    function initBackupSettingsPage() {
        const panel = document.querySelector('.backup-settings-panel');
        if (!panel) return;

        const runManualBackupBtn = document.getElementById('runManualBackupBtn');
        const exportBackupLogsBtn = document.getElementById('exportBackupLogsBtn');
        const backupLastRun = document.getElementById('backupLastRun');
        const backupLogList = document.getElementById('backupLogList');

        if (runManualBackupBtn && backupLogList) {
            runManualBackupBtn.addEventListener('click', () => {
                const now = new Date();
                const pad = (v) => String(v).padStart(2, '0');
                const timeLabel = `${pad(now.getHours())}:${pad(now.getMinutes())}`;
                const dateLabel = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${timeLabel}`;

                const row = document.createElement('div');
                row.className = 'backup-log-row';
                row.innerHTML = `
                    <div>
                        <h4>Manual Backup Execution</h4>
                        <p>Completed • On-demand backup successfully created</p>
                    </div>
                    <span class="backup-log-time">${timeLabel}</span>
                `;
                backupLogList.insertBefore(row, backupLogList.firstChild);
                if (backupLastRun) backupLastRun.textContent = dateLabel;
            });
        }

        if (exportBackupLogsBtn) {
            exportBackupLogsBtn.addEventListener('click', async () => {
                const now = new Date();
                const pad = (v) => String(v).padStart(2, '0');
                const timeLabel = `${pad(now.getHours())}:${pad(now.getMinutes())}`;
                const dateLabel = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${timeLabel}`;

                if (backupLogList) {
                    const row = document.createElement('div');
                    row.className = 'backup-log-row';
                    row.innerHTML = `
                        <div>
                            <h4>Audit Log Export</h4>
                            <p>Completed • Security logs packaged for internal review (${dateLabel})</p>
                        </div>
                        <span class="backup-log-time">${timeLabel}</span>
                    `;
                    backupLogList.insertBefore(row, backupLogList.firstChild);
                }
            });
        }
    }

    // ==========================================
    // 11. SUPPORT PAGE (LIVE CHAT + EMAIL)
    // ==========================================
    function initOllamaChatWidget() {
        const overlay = document.getElementById('supportChatOverlay');
        const closeBtn = document.getElementById('closeLiveChatBtn');
        const form = document.getElementById('supportChatForm');
        const input = document.getElementById('supportChatMessage');
        const body = document.getElementById('supportChatBody');
        const openButtons = [
            document.getElementById('openLiveChatBtn'),
            document.getElementById('dashboardChatFab'),
        ].filter(Boolean);

        if (!overlay || !closeBtn || !form || !input || !body || openButtons.length === 0) return;

        const setOpen = (open) => {
            overlay.classList.toggle('show', open);
            overlay.setAttribute('aria-hidden', open ? 'false' : 'true');
            if (open) {
                setTimeout(() => input.focus(), 50);
                body.scrollTop = body.scrollHeight;
            }
        };

        const addBubble = (text, who) => {
            const div = document.createElement('div');
            div.className = `support-chat-bubble ${who}`;
            div.textContent = text;
            body.appendChild(div);
            body.scrollTop = body.scrollHeight;
        };

        let isSending = false;
        let chatHistory = [];

        const initialAgentBubble = body.querySelector('.support-chat-bubble.agent');
        if (initialAgentBubble?.textContent?.trim()) {
            chatHistory.push({
                role: 'assistant',
                content: initialAgentBubble.textContent.trim()
            });
        }

        openButtons.forEach((btn) => btn.addEventListener('click', () => setOpen(true)));
        closeBtn.addEventListener('click', () => setOpen(false));

        // Click outside closes modal
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) setOpen(false);
        });

        // ESC closes modal
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && overlay.classList.contains('show')) setOpen(false);
        });

        form.addEventListener('submit', (e) => {
            e.preventDefault();
            if (isSending) return;

            const msg = (input.value || '').trim();
            if (!msg) return;

            addBubble(msg, 'user');
            chatHistory.push({ role: 'user', content: msg });
            input.value = '';
            isSending = true;
            input.disabled = true;

            const typingEl = document.createElement('div');
            typingEl.className = 'support-chat-bubble agent';
            typingEl.textContent = 'Thinking... (first reply may take 1-2 minutes on slower PCs)';
            body.appendChild(typingEl);
            body.scrollTop = body.scrollHeight;

            const slowHintTimer = setTimeout(() => {
                if (typingEl.isConnected) {
                    typingEl.textContent = 'Still working... loading llama3 on your machine. Please wait.';
                }
            }, 20000);

            fetch('/api/support/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: msg,
                    messages: chatHistory.filter((m) => m.role === 'assistant' || m.role === 'user').slice(0, -1)
                })
            })
                .then(async (res) => {
                    const rawText = await res.text();
                    let data = {};
                    try {
                        data = rawText ? JSON.parse(rawText) : {};
                    } catch {
                        data = {};
                    }

                    if (!res.ok || !data.success) {
                        // If session expired/login redirect happened, Flask may return HTML.
                        if (!data.error && rawText && rawText.includes('<!DOCTYPE html')) {
                            throw new Error('Session expired. Please log in again and retry chat.');
                        }
                        throw new Error(data.error || data.message || `Support chat failed (${res.status}).`);
                    }
                    return data.reply || '';
                })
                .then((reply) => {
                    clearTimeout(slowHintTimer);
                    typingEl.remove();
                    addBubble(reply || 'No reply received.', 'agent');
                    chatHistory.push({ role: 'assistant', content: reply || 'No reply received.' });
                })
                .catch((err) => {
                    clearTimeout(slowHintTimer);
                    typingEl.textContent = `Error: ${err.message || 'Unable to reach support chat service.'}`;
                    typingEl.style.color = '#ef4444';
                })
                .finally(() => {
                    clearTimeout(slowHintTimer);
                    isSending = false;
                    input.disabled = false;
                    input.focus();
                });
        });
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

    function ensureNotificationMenu(icon) {
        let menu = icon.querySelector('.notification-menu');
        if (!menu) {
            icon.insertAdjacentHTML('beforeend', `
                <div class="notification-menu" id="dashboardNotificationMenu">
                    <div class="notification-menu-title">Recent Activity</div>
                    <ul id="notificationList">
                        <li class="notification-empty">Loading activity...</li>
                    </ul>
                    <a href="/logs" class="notification-menu-footer">View all in Activity Logs <i class="fas fa-arrow-right"></i></a>
                </div>
            `);
            menu = icon.querySelector('.notification-menu');
        }
        if (!icon.querySelector('.badge')) {
            const bell = icon.querySelector('i');
            const badgeHtml = '<span class="badge is-hidden" id="notificationBadge">0</span>';
            if (bell) bell.insertAdjacentHTML('afterend', badgeHtml);
            else icon.insertAdjacentHTML('beforeend', badgeHtml);
        }
        return menu;
    }

    let latestNotificationId = 0;

    function updateNotificationBadge(unreadCount) {
        const badge = document.getElementById('notificationBadge');
        if (!badge) return;
        const unread = Number(unreadCount) || 0;
        if (unread <= 0) {
            badge.classList.add('is-hidden');
            badge.textContent = '0';
            return;
        }
        badge.classList.remove('is-hidden');
        badge.textContent = unread > 9 ? '9+' : String(unread);
    }

    function renderNotifications(payload) {
        const list = document.getElementById('notificationList');
        if (!list) return;

        const items = Array.isArray(payload) ? payload : (payload?.items || []);
        const unreadCount = Array.isArray(payload) ? 0 : (payload?.unread_count || 0);
        if (!Array.isArray(payload) && payload?.latest_id) {
            latestNotificationId = payload.latest_id;
        }

        updateNotificationBadge(unreadCount);

        if (!items || items.length === 0) {
            list.innerHTML = '<li class="notification-empty">No activity recorded yet.</li>';
            return;
        }

        list.innerHTML = items.map((item) => `
            <li class="${item.is_unread ? 'notification-unread' : ''}">
                <a class="notification-item-link" href="${item.href || '/logs'}">
                    <div class="notification-item">
                        <i class="fas ${item.icon || 'fa-clipboard-list'}"></i>
                        <div class="notification-item-content">
                            <div class="notification-item-category">${item.category || 'System Event'}</div>
                            <div class="notification-item-message">${item.message || ''}</div>
                            <div class="notification-item-meta">${item.user || 'System'} · ${item.status || 'logged'}</div>
                            <div class="notification-item-time">${item.time || ''}</div>
                        </div>
                    </div>
                </a>
            </li>
        `).join('');
    }

    async function markNotificationsRead() {
        try {
            await fetch('/api/notifications/mark-read', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ last_id: latestNotificationId }),
            });
            updateNotificationBadge(0);
            document.querySelectorAll('#notificationList .notification-unread').forEach((el) => {
                el.classList.remove('notification-unread');
            });
        } catch (error) {
            console.error('Mark notifications read error:', error);
        }
    }

    async function fetchNotifications() {
        const list = document.getElementById('notificationList');
        if (!list) return null;

        try {
            const response = await fetch('/api/notifications');
            if (!response.ok) throw new Error('Failed to load notifications');
            const data = await response.json();
            renderNotifications(data);
            return data;
        } catch (error) {
            console.error('Notification fetch error:', error);
            list.innerHTML = '<li class="notification-empty">Unable to load activity feed.</li>';
            updateNotificationBadge(0);
            return null;
        }
    }

    function initDashboardNotifications() {
        const notificationIcon = document.getElementById('dashboardNotificationIcon');
        if (!notificationIcon) return;

        ensureNotificationMenu(notificationIcon);
        fetchNotifications();

        const notificationMenu = notificationIcon.querySelector('.notification-menu');
        notificationIcon.addEventListener('click', async (e) => {
            if (e.target.closest('.notification-item-link, .notification-menu-footer')) {
                return;
            }
            e.stopPropagation();
            const willOpen = !notificationMenu?.classList.contains('show');
            if (willOpen) {
                closeDashboardMenus(notificationMenu);
            }
            notificationMenu?.classList.toggle('show');
            if (willOpen) {
                const data = await fetchNotifications();
                if (data) {
                    await markNotificationsRead();
                }
            }
        });

        notificationMenu?.addEventListener('click', (e) => {
            if (e.target.closest('.notification-item-link, .notification-menu-footer')) {
                notificationMenu.classList.remove('show');
                markNotificationsRead();
            }
        });
    }

    function closeDashboardMenus(exceptMenu = null) {
        document.querySelectorAll('.notification-menu.show, .user-menu.show').forEach((menu) => {
            if (menu === exceptMenu) return;
            menu.classList.remove('show');
        });
        const userPill = document.getElementById('dashboardUserPill');
        if (userPill && (!exceptMenu || !exceptMenu.classList.contains('user-menu'))) {
            userPill.classList.remove('is-open');
            userPill.setAttribute('aria-expanded', 'false');
        }
    }

    function initDashboardUserMenu() {
        const userPill = document.getElementById('dashboardUserPill');
        const userMenu = document.getElementById('dashboardUserMenu');
        if (!userPill || !userMenu) return;

        const setOpen = (open) => {
            userMenu.classList.toggle('show', open);
            userPill.classList.toggle('is-open', open);
            userPill.setAttribute('aria-expanded', open ? 'true' : 'false');
        };

        const toggleMenu = (e) => {
            if (e.target.closest('.user-menu a')) return;
            e.stopPropagation();
            const willOpen = !userMenu.classList.contains('show');
            closeDashboardMenus(willOpen ? userMenu : null);
            setOpen(willOpen);
        };

        userPill.addEventListener('click', toggleMenu);
        userPill.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                toggleMenu(e);
            }
            if (e.key === 'Escape') {
                setOpen(false);
            }
        });

        userMenu.addEventListener('click', (e) => {
            if (e.target.closest('a')) {
                setOpen(false);
            }
        });
    }

    document.addEventListener('click', (e) => {
        const notificationMenu = document.querySelector('.notification-menu.show');
        if (notificationMenu) {
            const icon = notificationMenu.closest('.notification-icon');
            if (icon && !icon.contains(e.target) && !e.target.closest('#dashboardUserPill')) {
                notificationMenu.classList.remove('show');
            }
        }

        const userMenu = document.querySelector('.user-menu.show');
        if (userMenu) {
            const pill = document.getElementById('dashboardUserPill');
            if (pill && !pill.contains(e.target)) {
                closeDashboardMenus();
            }
        }
    });

    initDashboardNotifications();
    initDashboardUserMenu();

    // ==========================================
    // ELEMENT-BASED ROUTER EXECUTION
    // ==========================================
    if (document.getElementById('threatLineChart')) {
        initLineChart();
    }
    if (document.querySelector('.stat-cards-grid')) {
        initDashboardStatCardLinks();
        fetchDashboardStats();
        fetchPolicyViolations();
    }
    if (alertsList) {
        fetchAlerts();
    }
    fetchLogs();

    if (document.getElementById('threatDistributionChart')) {
        initDistributionChart();
        fetchTopActors();
        initThreatInsights();
    }

    // AUTO-REFRESH: Tuwing 10 segundo para magmukhang live ang data
    if (document.querySelector('.stat-cards-grid') || alertsList || logsList) {
        setInterval(() => {
            fetchDashboardStats();
            if (document.getElementById('policyViolationsList')) fetchPolicyViolations();
            if (alertsList) fetchAlerts();
            if (logsList) fetchLogs();
            if (document.getElementById('notificationList')) fetchNotifications();
            if (document.getElementById('threatLineChart') && window.threatChart) {
                initLineChart();
            }
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
    initUserManagementPage();
    initBackupSettingsPage();
    initSidebarDropdowns();
    initChangePasswordForm();
    initOllamaChatWidget();
});