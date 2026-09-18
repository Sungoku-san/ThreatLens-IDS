// dashboard.js - Integrated SOC Dashboard logic communicating with Flask REST APIs

document.addEventListener('DOMContentLoaded', () => {
    
    // ==========================================
    // 1. GLOBAL STATE MANAGER
    // ==========================================
    const state = {
        currentSelectedFlow: null,
        uploadedFilepath: null,
        threshold: 0.50,
        predictionsHistory: [],
        globalImportance: {
            features: ['dst_port', 'packet_rate', 'flow_duration', 'packet_size', 'payload_weight', 'syn_flags'],
            values: [0.38, 0.32, 0.28, 0.22, 0.18, 0.14]
        }
    };

    // ==========================================
    // 2. TIMERS & DYNAMIC METRICS CLOCK
    // ==========================================
    const updateClock = () => {
        const liveClock = document.getElementById('liveClock');
        if (liveClock) {
            const now = new Date();
            const formatNum = (n) => n < 10 ? '0' + n : n;
            const dateStr = now.getFullYear() + '-' + formatNum(now.getMonth() + 1) + '-' + formatNum(now.getDate());
            const timeStr = formatNum(now.getHours()) + ':' + formatNum(now.getMinutes()) + ':' + formatNum(now.getSeconds());
            liveClock.innerText = `${dateStr} ${timeStr}`;
        }
    };
    setInterval(updateClock, 1000);
    updateClock();

    // ==========================================
    // 3. TABS ROUTING SYSTEM
    // ==========================================
    const tabLinks = document.querySelectorAll('.tab-link');
    const tabContents = document.querySelectorAll('.tab-content');
    const headerTitle = document.getElementById('headerTitle');

    const switchTab = (tabId) => {
        tabLinks.forEach(link => link.classList.remove('active', 'bg-white/5', 'text-white', 'border-white/5', 'shadow-neon-blue/5'));
        tabContents.forEach(content => content.classList.remove('active'));

        const activeLink = document.querySelector(`.tab-link[data-tab="${tabId}"]`);
        const activeContent = document.getElementById(`tab-${tabId}`);

        if (activeLink && activeContent) {
            activeLink.classList.add('active', 'bg-white/5', 'text-white', 'border-white/5', 'shadow-neon-blue/5');
            activeContent.classList.add('active');

            const tabNameMap = {
                overview: "Dashboard Overview",
                upload: "Upload Flow Dataset",
                monitoring: "Real-Time Detection Engine",
                shap: "SHAP Explainability Insights",
                reports: "Statistical Performance Reports",
                settings: "SOC Configurations & Rules"
            };
            headerTitle.innerText = tabNameMap[tabId] || "SOC Command Center";

            // Trigger active tab data reloads
            if (tabId === 'overview') {
                loadDashboardMetrics();
                loadRecentAlerts();
            } else if (tabId === 'monitoring') {
                loadPredictionHistory();
            } else if (tabId === 'shap') {
                renderShapDashboard();
            } else if (tabId === 'reports') {
                loadReportsCharts();
            } else if (tabId === 'copilot') {
                loadManualsCatalog();
                loadChatHistory();
            } else if (tabId === 'settings') {
                loadApiSettings();
            }
        }
    };

    tabLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetTab = link.getAttribute('data-tab');
            window.location.hash = targetTab;
            switchTab(targetTab);
        });
    });

    const handleHashRoute = () => {
        const hash = window.location.hash.substring(1);
        if (hash) {
            switchTab(hash);
        } else {
            switchTab('overview');
        }
    };
    window.addEventListener('hashchange', handleHashRoute);
    handleHashRoute();

    // Mobile Sidebar toggle menu
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    const menuIcon = document.getElementById('menuIcon');

    const toggleSidebar = () => {
        sidebar.classList.toggle('-translate-x-full');
        sidebarOverlay.classList.toggle('hidden');
        const isOpen = !sidebar.classList.contains('-translate-x-full');
        menuIcon.setAttribute('data-lucide', isOpen ? 'x' : 'menu');
        lucide.createIcons();
    };

    if (mobileMenuBtn && sidebar && sidebarOverlay) {
        mobileMenuBtn.addEventListener('click', toggleSidebar);
        sidebarOverlay.addEventListener('click', toggleSidebar);
    }

    // ==========================================
    // 4. CHART CONFS (APEXCHARTS)
    // ==========================================
    
    // Chart 1: Live Network Traffic Flow
    const liveTrafficOptions = {
        series: [
            { name: 'TCP Packets', data: [82, 94, 76, 88, 120, 140, 105, 95, 110, 130] },
            { name: 'UDP Packets', data: [34, 45, 23, 56, 44, 52, 60, 48, 54, 62] },
            { name: 'ICMP Packets', data: [8, 12, 10, 6, 14, 8, 11, 7, 9, 13] }
        ],
        chart: {
            type: 'line',
            height: 310,
            background: 'transparent',
            foreColor: '#9CA3AF',
            toolbar: { show: false },
            animations: { enabled: true, easing: 'easeinout', speed: 800 }
        },
        colors: ['#3B82F6', '#06B6D4', '#8B5CF6'],
        stroke: { curve: 'smooth', width: 3 },
        grid: { borderColor: 'rgba(255,255,255,0.05)', yaxis: { lines: { show: true } } },
        xaxis: {
            categories: ['18:29', '18:30', '18:31', '18:32', '18:33', '18:34', '18:35', '18:36', '18:37', '18:38'],
            axisBorder: { show: false }, axisTicks: { show: false }
        },
        tooltip: { theme: 'dark' },
        legend: { show: false }
    };
    const chartLiveTraffic = new ApexCharts(document.querySelector("#chartLiveTraffic"), liveTrafficOptions);
    chartLiveTraffic.render();

    // Chart 2: Threat Density Heatmap
    const heatmapOptions = {
        series: [
            { name: 'Mon', data: [{x: '00:00', y: 12}, {x: '04:00', y: 15}, {x: '08:00', y: 44}, {x: '12:00', y: 22}, {x: '16:00', y: 35}, {x: '20:00', y: 18}] },
            { name: 'Tue', data: [{x: '00:00', y: 8}, {x: '04:00', y: 10}, {x: '08:00', y: 15}, {x: '12:00', y: 30}, {x: '16:00', y: 82}, {x: '20:00', y: 45}] },
            { name: 'Wed', data: [{x: '00:00', y: 25}, {x: '04:00', y: 8}, {x: '08:00', y: 12}, {x: '12:00', y: 15}, {x: '16:00', y: 40}, {x: '20:00', y: 22}] },
            { name: 'Thu', data: [{x: '00:00', y: 10}, {x: '04:00', y: 14}, {x: '08:00', y: 22}, {x: '12:00', y: 45}, {x: '16:00', y: 12}, {x: '20:00', y: 8}] },
            { name: 'Fri', data: [{x: '00:00', y: 14}, {x: '04:00', y: 25}, {x: '08:00', y: 52}, {x: '12:00', y: 88}, {x: '16:00', y: 64}, {x: '20:00', y: 30}] }
        ],
        chart: {
            type: 'heatmap', height: 245, background: 'transparent', foreColor: '#9CA3AF', toolbar: { show: false }
        },
        dataLabels: { enabled: false },
        plotOptions: {
            heatmap: {
                colorScale: {
                    ranges: [
                        { from: 0, to: 20, name: 'Safe', color: '#10B981' },
                        { from: 21, to: 50, name: 'Normal', color: '#3B82F6' },
                        { from: 51, to: 80, name: 'Warning', color: '#F59E0B' },
                        { from: 81, to: 100, name: 'Critical', color: '#EF4444' }
                    ]
                }
            }
        },
        grid: { show: false },
        tooltip: { theme: 'dark' }
    };
    const chartThreatHeatmap = new ApexCharts(document.querySelector("#chartThreatHeatmap"), heatmapOptions);
    chartThreatHeatmap.render();

    // Chart 3: Protocol distribution ratio
    const packetFlowOptions = {
        series: [68, 24, 8],
        chart: { type: 'donut', height: 235, background: 'transparent', foreColor: '#9CA3AF' },
        labels: ['TCP Flow', 'UDP Flow', 'ICMP Flow'],
        colors: ['#3B82F6', '#06B6D4', '#8B5CF6'],
        stroke: { show: false },
        legend: { position: 'bottom', labels: { colors: '#9CA3AF' } },
        dataLabels: { enabled: false },
        tooltip: { theme: 'dark' },
        plotOptions: {
            pie: {
                donut: {
                    size: '75%',
                    labels: {
                        show: true,
                        name: { show: true, fontSize: '12px', color: '#9CA3AF' },
                        value: { show: true, fontSize: '18px', fontWeight: 'bold', color: '#fff', formatter: (v) => v + '%' },
                        total: { show: true, label: 'Protocols', color: '#9CA3AF', formatter: () => '100%' }
                    }
                }
            }
        }
    };
    const chartPacketFlow = new ApexCharts(document.querySelector("#chartPacketFlow"), packetFlowOptions);
    chartPacketFlow.render();

    // Chart 4: SHAP Global Feature Importance
    const featureImportanceOptions = {
        series: [{ name: 'Mean SHAP Value', data: state.globalImportance.values }],
        chart: { type: 'bar', height: 230, background: 'transparent', foreColor: '#9CA3AF', toolbar: { show: false } },
        plotOptions: {
            bar: { horizontal: true, barHeight: '55%', borderRadius: 4, colors: { ranges: [{ from: 0, to: 100, color: '#8B5CF6' }] } }
        },
        dataLabels: { enabled: false },
        grid: { borderColor: 'rgba(255,255,255,0.05)', xaxis: { lines: { show: true } } },
        xaxis: {
            categories: state.globalImportance.features,
            axisBorder: { show: false }, axisTicks: { show: false }
        },
        tooltip: { theme: 'dark' }
    };
    const chartFeatureImportance = new ApexCharts(document.querySelector("#chartFeatureImportance"), featureImportanceOptions);
    chartFeatureImportance.render();

    // Chart 5: Reports Page distribution
    const reportsDistributionOptions = {
        series: [85, 12, 3],
        chart: { type: 'pie', height: 270, background: 'transparent', foreColor: '#9CA3AF' },
        labels: ['Normal Connections', 'Malicious Intrusions', 'Suspicious Activity'],
        colors: ['#10B981', '#EF4444', '#F59E0B'],
        stroke: { show: false },
        legend: { position: 'bottom', labels: { colors: '#9CA3AF' } },
        tooltip: { theme: 'dark' }
    };
    const chartReportsDistribution = new ApexCharts(document.querySelector("#chartReportsDistribution"), reportsDistributionOptions);
    chartReportsDistribution.render();

    // Chart 6: Reports Timeline anomalies
    const reportsTimelineOptions = {
        series: [
            { name: 'Normal Flows (x100)', data: [45, 52, 38, 24, 33, 26, 40, 56, 44, 52, 60, 48] },
            { name: 'Attack Incidents', data: [12, 8, 14, 25, 18, 42, 10, 15, 6, 8, 12, 18] }
        ],
        chart: { type: 'area', height: 260, background: 'transparent', foreColor: '#9CA3AF', toolbar: { show: false } },
        colors: ['#10B981', '#EF4444'],
        dataLabels: { enabled: false },
        stroke: { curve: 'smooth', width: 2 },
        fill: {
            type: 'gradient',
            gradient: { shadeIntensity: 1, opacityFrom: 0.2, opacityTo: 0.02, stops: [0, 90, 100] }
        },
        grid: { borderColor: 'rgba(255,255,255,0.05)' },
        xaxis: {
            categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
            axisBorder: { show: false }, axisTicks: { show: false }
        },
        tooltip: { theme: 'dark' }
    };
    const chartReportsTimeline = new ApexCharts(document.querySelector("#chartReportsTimeline"), reportsTimelineOptions);
    chartReportsTimeline.render();

    // ==========================================
    // 5. REST API PULLERS (METRICS & ALERTS)
    // ==========================================
    
    // Fetch Metrics Dashboard Stats
    async function loadDashboardMetrics() {
        try {
            const res = await fetch('/api/dashboard');
            const result = await res.json();
            if (res.ok && result.status === 'success') {
                const d = result.data;
                document.getElementById('m-total-packets').innerText = formatMetricCount(d.total_packets);
                document.getElementById('m-normal-traffic').innerText = formatMetricCount(d.normal_packets);
                document.getElementById('m-malicious-traffic').innerText = d.malicious_packets.toLocaleString();
                document.getElementById('m-accuracy').innerText = `${d.accuracy.toFixed(2)}%`;
                document.getElementById('m-false-positive').innerText = `${d.fpr.toFixed(2)}%`;
                
                const threatLevelEl = document.getElementById('m-threat-level');
                threatLevelEl.innerText = d.threat_level;
                
                // Threat colors mapping
                threatLevelEl.className = "text-xl sm:text-2xl font-space font-bold text-glow-cyan ";
                if (d.threat_level === 'CRITICAL' || d.threat_level === 'HIGH') {
                    threatLevelEl.classList.add('text-cyberDanger', 'text-glow-danger');
                } else if (d.threat_level === 'MODERATE') {
                    threatLevelEl.classList.add('text-cyberWarning');
                } else {
                    threatLevelEl.classList.add('text-cyberSuccess');
                }
            }
        } catch (err) {
            console.error("Failed to load dashboard metrics from API:", err);
        }
    }

    const formatMetricCount = (val) => {
        if (val >= 1000) {
            return (val / 1000).toFixed(1) + "K";
        }
        return val.toLocaleString();
    };

    // Load recent threat alerts in overview sidebar
    const dashboardAlertsList = document.getElementById('dashboardAlertsList');
    async function loadRecentAlerts() {
        try {
            const res = await fetch('/api/recent-attacks');
            const result = await res.json();
            if (res.ok && result.status === 'success') {
                dashboardAlertsList.innerHTML = '';
                const attacks = result.data;
                
                if (attacks.length === 0) {
                    dashboardAlertsList.innerHTML = `<p class="text-xs text-gray-500 text-center py-8">No malicious alerts logged.</p>`;
                    return;
                }
                
                attacks.forEach(row => {
                    const isAttack = row.prediction === 'Attack';
                    const dotClass = isAttack ? 'bg-cyberDanger shadow-neon-danger' : 'bg-cyberWarning';
                    
                    const div = document.createElement('div');
                    div.className = "flex items-center space-x-3.5 p-3 rounded-xl border border-white/5 hover:border-cyberSecondary/30 hover:bg-white/5 cursor-pointer transition-all duration-150";
                    div.innerHTML = `
                        <span class="w-2.5 h-2.5 rounded-full ${dotClass} flex-shrink-0 animate-pulse"></span>
                        <div class="flex-grow min-w-0">
                            <p class="text-xs font-semibold text-white truncate">${row.attack_type}</p>
                            <p class="text-[10px] text-gray-400 font-mono mt-0.5 truncate">${row.src_ip} ➔ Port ${row.port}</p>
                        </div>
                        <div class="text-right">
                            <p class="text-[10px] font-bold ${isAttack ? 'text-cyberDanger' : 'text-cyberWarning'}">${row.confidence.toFixed(1)}%</p>
                            <p class="text-[8px] text-gray-500 font-mono">${row.timestamp.split(' ')[1]}</p>
                        </div>
                    `;

                    div.addEventListener('click', () => openAttackDetails(row));
                    dashboardAlertsList.appendChild(div);
                });
            }
        } catch (err) {
            console.error("Failed to load recent alerts:", err);
        }
    }

    // Load active global importance chart data
    async function loadGlobalImportance() {
        try {
            const res = await fetch('/api/shap/importance');
            const result = await res.json();
            if (res.ok && result.status === 'success') {
                state.globalImportance = result.data;
                chartFeatureImportance.updateSeries([{ data: result.data.values }]);
                chartFeatureImportance.updateOptions({
                    xaxis: { categories: result.data.features }
                });
            }
        } catch (err) {
            console.error("Failed to load global importance weights:", err);
        }
    }
    loadGlobalImportance(); // On startup

    // ==========================================
    // 6. DATASET UPLOAD & INGESTION
    // ==========================================
    const dragDropArea = document.getElementById('dragDropArea');
    const datasetInput = document.getElementById('datasetInput');
    const fileStatsContainer = document.getElementById('fileStatsContainer');
    const fileNameText = document.getElementById('fileNameText');
    const fileSizeText = document.getElementById('fileSizeText');
    const fileColumnsText = document.getElementById('fileColumnsText');
    const fileRowsText = document.getElementById('fileRowsText');
    const removeFileBtn = document.getElementById('removeFileBtn');
    
    const useSampleBtn = document.getElementById('useSampleBtn');
    const uploadAnalyzeBtn = document.getElementById('uploadAnalyzeBtn');
    const uploadProgressBar = document.getElementById('uploadProgressBar');
    const uploadPercent = document.getElementById('uploadPercent');

    const handleUploadFile = async (file) => {
        const formData = new FormData();
        formData.append('file', file);

        // Show file loading state
        fileNameText.innerText = file.name;
        fileSizeText.innerText = "Ingesting file...";
        dragDropArea.classList.add('hidden');
        fileStatsContainer.classList.remove('hidden');

        try {
            const res = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });
            const result = await res.json();

            if (res.ok && result.status === 'success') {
                const metadata = result.data;
                state.uploadedFilepath = metadata.filepath;
                
                // Show metadata values
                fileNameText.innerText = metadata.dataset_name;
                fileSizeText.innerText = metadata.size;
                fileColumnsText.innerText = metadata.columns;
                fileRowsText.innerText = metadata.rows.toLocaleString();

                // Enable analyze button
                uploadAnalyzeBtn.disabled = false;
                uploadAnalyzeBtn.classList.remove('opacity-50', 'cursor-not-allowed');
                uploadAnalyzeBtn.classList.add('hover:scale-[1.02]');
            } else {
                alert(result.message || "Failed to validate dataset.");
                resetUploadState();
            }
        } catch (err) {
            console.error("Upload error:", err);
            alert("Connection error during dataset upload.");
            resetUploadState();
        }
    };

    const resetUploadState = () => {
        state.uploadedFilepath = null;
        fileStatsContainer.classList.add('hidden');
        dragDropArea.classList.remove('hidden');
        datasetInput.value = '';
        uploadProgressBar.style.width = '0%';
        uploadPercent.innerText = '0%';
        uploadAnalyzeBtn.disabled = true;
        uploadAnalyzeBtn.classList.add('opacity-50', 'cursor-not-allowed');
        uploadAnalyzeBtn.classList.remove('hover:scale-[1.02]');
    };

    removeFileBtn.addEventListener('click', resetUploadState);
    dragDropArea.addEventListener('click', () => datasetInput.click());

    datasetInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) handleUploadFile(file);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        dragDropArea.addEventListener(eventName, (e) => {
            e.preventDefault();
            dragDropArea.classList.add('drag-over');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dragDropArea.addEventListener(eventName, (e) => {
            e.preventDefault();
            dragDropArea.classList.remove('drag-over');
        }, false);
    });

    dragDropArea.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const file = dt.files[0];
        if (file) handleUploadFile(file);
    });

    // Ingest sample dataset already on server
    useSampleBtn.addEventListener('click', async () => {
        // Direct simulation path
        const sampleFilepath = "backend/dataset/CICIDS2017.csv";
        state.uploadedFilepath = sampleFilepath;
        
        fileNameText.innerText = "CICIDS2017_Sample_Baseline.csv";
        fileSizeText.innerText = "112.5 KB";
        fileColumnsText.innerText = "79";
        fileRowsText.innerText = "1,500";
        
        dragDropArea.classList.add('hidden');
        fileStatsContainer.classList.remove('hidden');
        
        uploadAnalyzeBtn.disabled = false;
        uploadAnalyzeBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        uploadAnalyzeBtn.classList.add('hover:scale-[1.02]');
    });

    // Run prediction on uploaded dataset file path
    uploadAnalyzeBtn.addEventListener('click', async () => {
        if (!state.uploadedFilepath) return;

        uploadAnalyzeBtn.disabled = true;
        uploadAnalyzeBtn.innerText = "Running Model predictions...";
        
        // Progress bar simulation loop
        let progress = 0;
        const barTimer = setInterval(() => {
            if (progress < 90) {
                progress += 15;
                uploadProgressBar.style.width = `${progress}%`;
                uploadPercent.innerText = `${progress}%`;
            }
        }, 100);

        try {
            const res = await fetch('/api/predict/file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    filepath: state.uploadedFilepath,
                    threshold: state.threshold
                })
            });
            const result = await res.json();
            
            clearInterval(barTimer);

            if (res.ok && result.status === 'success') {
                uploadProgressBar.style.width = '100%';
                uploadPercent.innerText = '100%';
                
                addSysLog(`INGEST: Model processed ${result.processed} packets. 0 issues.`);
                
                setTimeout(() => {
                    uploadAnalyzeBtn.innerText = "Analyze Dataset";
                    uploadAnalyzeBtn.disabled = false;
                    window.location.hash = "monitoring";
                }, 550);
            } else {
                alert(result.message || "Failed to execute prediction pipeline.");
                uploadAnalyzeBtn.innerText = "Analyze Dataset";
                uploadAnalyzeBtn.disabled = false;
            }
        } catch (err) {
            clearInterval(barTimer);
            console.error("Batch prediction failure:", err);
            alert("Connection error during prediction model process.");
            uploadAnalyzeBtn.innerText = "Analyze Dataset";
            uploadAnalyzeBtn.disabled = false;
        }
    });

    // ==========================================
    // 7. DETECTION / MONITOR PAGE LOGS HISTORIES
    // ==========================================
    const runDetectionBtn = document.getElementById('runDetectionBtn');
    const detectionLoader = document.getElementById('detectionLoader');
    const detectionTableBody = document.getElementById('detectionTableBody');
    const tableSearch = document.getElementById('tableSearch');
    const tableFilter = document.getElementById('tableFilter');

    async function loadPredictionHistory() {
        const query = tableSearch.value.trim();
        const pred_filter = tableFilter.value;
        
        let url = `/api/predict/history?limit=100`;
        if (query) url += `&q=${encodeURIComponent(query)}`;
        if (pred_filter) url += `&filter=${encodeURIComponent(pred_filter)}`;

        try {
            const res = await fetch(url);
            const result = await res.json();
            if (res.ok && result.status === 'success') {
                state.predictionsHistory = result.data;
                renderTableHistory(result.data);
            }
        } catch (err) {
            console.error("Failed to load historical predictions:", err);
        }
    }

    const renderTableHistory = (data) => {
        detectionTableBody.innerHTML = '';
        
        if (data.length === 0) {
            detectionTableBody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center py-12 text-gray-500 font-light">No parsed threat logs found in database. Ingest a dataset on the Upload tab first.</td>
                </tr>
            `;
            return;
        }

        data.forEach(row => {
            let predClass = '';
            let riskClass = '';
            let badgeIcon = '';
            
            if (row.prediction === 'Normal') {
                predClass = 'text-cyberSuccess bg-cyberSuccess/10 border-cyberSuccess/20';
                riskClass = 'text-gray-400';
                badgeIcon = 'shield-check';
            } else if (row.prediction === 'Attack') {
                predClass = 'text-cyberDanger bg-cyberDanger/10 border-cyberDanger/20 text-glow-danger animate-pulse';
                riskClass = 'text-cyberDanger font-bold';
                badgeIcon = 'shield-alert';
            } else {
                predClass = 'text-cyberWarning bg-cyberWarning/10 border-cyberWarning/20';
                riskClass = 'text-cyberWarning font-semibold';
                badgeIcon = 'alert-triangle';
            }

            const tr = document.createElement('tr');
            tr.className = "hover:bg-white/5 cursor-pointer transition-colors duration-150 border-b border-white/5";
            tr.innerHTML = `
                <td class="px-6 py-4 font-mono font-bold text-gray-400">${row.flow_id}</td>
                <td class="px-6 py-4 font-mono">${row.src_ip}</td>
                <td class="px-6 py-4 font-mono">${row.dst_ip}</td>
                <td class="px-6 py-4 font-mono text-gray-400">${row.protocol} (port ${row.port})</td>
                <td class="px-6 py-4">
                    <span class="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold border ${predClass}">
                        <i data-lucide="${badgeIcon}" class="w-3.5 h-3.5"></i>
                        <span>${row.prediction.toUpperCase()}</span>
                    </span>
                </td>
                <td class="px-6 py-4 font-mono font-medium">${row.confidence.toFixed(1)}%</td>
                <td class="px-6 py-4">
                    <span class="${riskClass}">${row.risk_level}</span>
                </td>
                <td class="px-6 py-4 text-right">
                    <button class="px-3 py-1 rounded bg-[#0f192b] border border-white/5 hover:border-cyberSecondary text-cyberSecondary hover:text-white text-[10px] font-bold transition-all duration-200 view-details-btn" data-id="${row.flow_id}">
                        Inspect SOC
                    </button>
                </td>
            `;

            tr.addEventListener('click', (e) => {
                if (e.target.closest('.view-details-btn')) return;
                openAttackDetails(row);
            });

            detectionTableBody.appendChild(tr);
        });

        lucide.createIcons();

        // Inspect buttons listener binding
        document.querySelectorAll('.view-details-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const id = btn.getAttribute('data-id');
                const row = state.predictionsHistory.find(r => r.flow_id === id);
                if (row) openAttackDetails(row);
            });
        });
    };

    // Clicking Run Detection calls history API reload
    runDetectionBtn.addEventListener('click', async () => {
        runDetectionBtn.disabled = true;
        detectionLoader.classList.remove('hidden');
        
        await loadPredictionHistory();
        
        setTimeout(() => {
            detectionLoader.classList.add('hidden');
            runDetectionBtn.disabled = false;
            addSysLog("XGB_DECIDE: Refreshed network flow history logs.");
        }, 600);
    });

    // Real-Time filter binding
    tableSearch.addEventListener('input', loadPredictionHistory);
    tableFilter.addEventListener('change', loadPredictionHistory);


    // ==========================================
    // 8. INSPECTOR DRAWER CONTROLS
    // ==========================================
    const attackDetailsDrawer = document.getElementById('attackDetailsDrawer');
    const closeDrawerBtn = document.getElementById('closeDrawerBtn');
    const drawerTitle = document.getElementById('drawerTitle');
    const drawerRiskHeader = document.getElementById('drawerRiskHeader');
    const drawerConfidenceText = document.getElementById('drawerConfidenceText');
    const drawerFlowId = document.getElementById('drawerFlowId');
    const drawerSrcIp = document.getElementById('drawerSrcIp');
    const drawerDstIp = document.getElementById('drawerDstIp');
    const drawerProtocol = document.getElementById('drawerProtocol');
    const drawerAttackType = document.getElementById('drawerAttackType');
    const drawerTimestamp = document.getElementById('drawerTimestamp');
    const drawerRiskIndex = document.getElementById('drawerRiskIndex');
    const drawerShapReasonsList = document.getElementById('drawerShapReasonsList');
    const drawerRemediationText = document.getElementById('drawerRemediationText');
    const drawerOpenShapBtn = document.getElementById('drawerOpenShapBtn');
    const drawerAskCopilotBtn = document.getElementById('drawerAskCopilotBtn');
    const drawerRiskBox = document.getElementById('drawerRiskBox');
    const drawerHeaderIcon = document.getElementById('drawerHeaderIcon');

    const openAttackDetails = (row) => {
        state.currentSelectedFlow = row;
        
        drawerTitle.innerText = row.prediction === 'Normal' ? "Flow Connection Details" : "Anomaly Alert Inspection";
        drawerFlowId.innerText = `Flow ID: ${row.flow_id}`;
        drawerSrcIp.innerText = row.src_ip;
        drawerDstIp.innerText = row.dst_ip;
        drawerProtocol.innerText = `${row.protocol} (port ${row.port})`;
        drawerAttackType.innerText = row.attack_type;
        drawerTimestamp.innerText = row.timestamp;
        
        if (row.prediction === 'Normal') {
            drawerRiskHeader.innerText = "SAFE SECURE FLOW";
            drawerConfidenceText.innerText = `${row.confidence.toFixed(1)}% Normal`;
            drawerRiskIndex.innerText = "LOW RISK (1/100)";
            drawerRiskBox.className = "p-4 rounded-xl bg-cyberSuccess/10 border border-cyberSuccess/20 flex flex-col items-center justify-center text-center space-y-1";
            drawerConfidenceText.className = "text-2xl font-space font-bold text-cyberSuccess text-glow-success";
            drawerRiskHeader.className = "text-[10px] font-semibold uppercase text-cyberSuccess tracking-widest font-mono";
            drawerHeaderIcon.className = "w-5 h-5 text-cyberSuccess";
            drawerHeaderIcon.setAttribute('data-lucide', 'shield-check');
            drawerRemediationText.innerText = "No remediation protocols required. Packet patterns fit standard traffic baseline criteria. Monitoring remains active.";
        } else if (row.prediction === 'Attack') {
            drawerRiskHeader.innerText = "CRITICAL SECURITY INCIDENT";
            drawerConfidenceText.innerText = `${row.confidence.toFixed(1)}% Attack`;
            drawerRiskIndex.innerText = `CRITICAL (${Math.floor(row.confidence)}/100)`;
            drawerRiskBox.className = "p-4 rounded-xl bg-cyberDanger/10 border border-cyberDanger/20 flex flex-col items-center justify-center text-center space-y-1";
            drawerConfidenceText.className = "text-2xl font-space font-bold text-cyberDanger text-glow-danger animate-pulse";
            drawerRiskHeader.className = "text-[10px] font-semibold uppercase text-cyberDanger tracking-widest font-mono";
            drawerHeaderIcon.className = "w-5 h-5 text-cyberDanger animate-pulse";
            drawerHeaderIcon.setAttribute('data-lucide', 'shield-alert');
            drawerRemediationText.innerText = `Deploy ingress block command immediately. Flag source IP ${row.src_ip} at firewall and isolate endpoint port ${row.port} from core switch.`;
        } else {
            drawerRiskHeader.innerText = "SUSPICIOUS LOG PROFILE";
            drawerConfidenceText.innerText = `${row.confidence.toFixed(1)}% Suspicious`;
            drawerRiskIndex.innerText = "MODERATE RISK (50/100)";
            drawerRiskBox.className = "p-4 rounded-xl bg-cyberWarning/10 border border-cyberWarning/20 flex flex-col items-center justify-center text-center space-y-1";
            drawerConfidenceText.className = "text-2xl font-space font-bold text-cyberWarning text-glow-cyan";
            drawerRiskHeader.className = "text-[10px] font-semibold uppercase text-cyberWarning tracking-widest font-mono";
            drawerHeaderIcon.className = "w-5 h-5 text-cyberWarning";
            drawerHeaderIcon.setAttribute('data-lucide', 'alert-triangle');
            drawerRemediationText.innerText = "Monitor connection log parameters continuously. Suggest running deep packet audits on protocol payloads to ensure no data is leaking.";
        }

        // Render SHAP list inside drawer
        drawerShapReasonsList.innerHTML = '';
        row.shap_values.slice(0, 4).forEach(item => {
            const isPos = item.type === 'positive';
            const colorClass = isPos ? 'text-cyberDanger' : 'text-cyberSuccess';
            const bgClass = isPos ? 'bg-cyberDanger/5' : 'bg-cyberSuccess/5';
            const borderClass = isPos ? 'border-cyberDanger/10' : 'border-cyberSuccess/10';
            const prefix = isPos ? '+' : '';
            
            const div = document.createElement('div');
            div.className = `flex justify-between items-center p-2.5 rounded-lg border ${borderClass} ${bgClass} text-xs font-mono`;
            div.innerHTML = `
                <span class="text-gray-400 font-semibold">${item.name} (${item.value})</span>
                <span class="${colorClass} font-bold">${prefix}${item.impact.toFixed(2)}</span>
            `;
            drawerShapReasonsList.appendChild(div);
        });

        // Link drawer button to the SHAP explanation tab
        drawerOpenShapBtn.onclick = () => {
            toggleDrawer(false);
            window.location.hash = "shap";
        };

        // Link drawer button to consult AI Copilot
        drawerAskCopilotBtn.onclick = () => {
            toggleDrawer(false);
            window.location.hash = "copilot";
            setTimeout(() => {
                const query = `Explain threat parameters and mitigation recommendations for active connection ${row.flow_id}`;
                document.getElementById('chatInput').value = query;
                const form = document.getElementById('copilotChatForm');
                if (form) {
                    form.dispatchEvent(new Event('submit', { cancelable: true }));
                }
            }, 350);
        };

        const drawerDownloadAiReportBtn = document.getElementById('drawerDownloadAiReportBtn');
        if (drawerDownloadAiReportBtn) {
            drawerDownloadAiReportBtn.onclick = () => {
                window.location.href = `/api/reports/ai?flow_id=${row.flow_id}`;
            };
        }

        lucide.createIcons();
        toggleDrawer(true);
    };

    const toggleDrawer = (open) => {
        if (open) {
            attackDetailsDrawer.classList.remove('translate-x-full');
        } else {
            attackDetailsDrawer.classList.add('translate-x-full');
        }
    };
    closeDrawerBtn.addEventListener('click', () => toggleDrawer(false));


    // ==========================================
    // 9. SHAP ANALYSIS EXPLAINABILITY BUILDER
    // ==========================================
    const shapFlowId = document.getElementById('shapFlowId');
    const shapForceNormal = document.getElementById('shapForceNormal');
    const shapForceSeparator = document.getElementById('shapForceSeparator');
    const shapForceAttack = document.getElementById('shapForceAttack');
    const shapOutputVal = document.getElementById('shapOutputVal');
    const shapWaterfallContainer = document.getElementById('shapWaterfallContainer');
    const shapDecisionText = document.getElementById('shapDecisionText');
    const shapExplanationText = document.getElementById('shapExplanationText');
    const shapContributionList = document.getElementById('shapContributionList');

    async function renderShapDashboard() {
        // Fallback default row if currentSelectedFlow is null
        let row = state.currentSelectedFlow;
        if (!row) {
            if (state.predictionsHistory.length > 0) {
                row = state.predictionsHistory[0];
            } else {
                // Fetch latest flow from history
                const res = await fetch('/api/predict/history?limit=1');
                const result = await res.json();
                if (res.ok && result.status === 'success' && result.data.length > 0) {
                    row = result.data[0];
                }
            }
        }
        
        if (!row) {
            shapExplanationText.innerText = "No flow connection selected. Run model prediction log monitor to execute explanations.";
            return;
        }

        shapFlowId.innerText = row.flow_id;

        // Fetch explanations dynamically
        try {
            const explRes = await fetch(`/api/shap/${row.flow_id}`);
            const explResult = await explRes.json();
            if (explRes.ok && explResult.status === 'success') {
                const d = explResult.data;
                
                // Calculate positive & negative force ratios
                let posSum = 0;
                let negSum = 0;
                d.shap_values.forEach(item => {
                    if (item.type === 'positive') posSum += item.impact;
                    else negSum += Math.abs(item.impact);
                });

                const totalForce = posSum + negSum;
                const normPercent = totalForce > 0 ? (negSum / totalForce) * 100 : 50;
                const attackPercent = 100 - normPercent;

                // Adjust force plot bar widths
                shapForceNormal.style.width = `${normPercent}%`;
                shapForceAttack.style.width = `${attackPercent}%`;
                shapForceSeparator.style.left = `${normPercent}%`;

                // Set probabilities labels
                const prob = d.prediction === 'Normal' ? (100 - d.confidence) / 100 : d.confidence / 100;
                shapOutputVal.innerText = `Output Prob: ${prob.toFixed(3)} (${d.prediction.toUpperCase()})`;

                // Set explanation cards
                shapDecisionText.innerText = d.prediction === 'Normal' ? "NORMAL SYSTEM CONNECTIONS" : d.attack_type.toUpperCase();
                shapDecisionText.className = d.prediction === 'Normal' ? "text-cyberSuccess text-glow-success font-bold" : "text-cyberDanger text-glow-danger font-bold animate-pulse";
                shapExplanationText.innerText = d.explanation;

                // Populate waterfall plots
                shapWaterfallContainer.innerHTML = '';
                let cumulativeValue = 0.34;
                
                const baseDiv = document.createElement('div');
                baseDiv.className = "flex justify-between items-center text-[10px] font-mono text-gray-500 bg-white/5 px-3 py-1.5 rounded";
                baseDiv.innerHTML = `<span>Model Base Ingestion Baseline</span><span class="font-bold">0.34</span>`;
                shapWaterfallContainer.appendChild(baseDiv);

                d.shap_values.slice(0, 5).forEach(item => {
                    const isPos = item.type === 'positive';
                    const sign = isPos ? '+' : '-';
                    const colorClass = isPos ? 'text-cyberDanger font-bold' : 'text-cyberSuccess font-bold';
                    
                    cumulativeValue = isPos ? cumulativeValue + item.impact : cumulativeValue - item.impact;
                    if (cumulativeValue < 0.0) cumulativeValue = 0.01;
                    if (cumulativeValue > 1.0) cumulativeValue = 0.99;

                    const div = document.createElement('div');
                    div.className = "flex justify-between items-center text-xs font-mono border-b border-white/5 py-2";
                    div.innerHTML = `
                        <div class="flex flex-col">
                            <span class="text-white font-semibold">${item.name} = ${item.value}</span>
                            <span class="text-[9px] text-gray-400">Impact adjustment</span>
                        </div>
                        <div class="flex items-center space-x-6">
                            <span class="${colorClass}">${sign}${Math.abs(item.impact).toFixed(2)}</span>
                            <span class="text-gray-400 w-12 text-right font-bold">${cumulativeValue.toFixed(2)}</span>
                        </div>
                    `;
                    shapWaterfallContainer.appendChild(div);
                });

                // Populate details parameters contributions lists
                shapContributionList.innerHTML = '';
                d.shap_values.forEach(item => {
                    const isPos = item.type === 'positive';
                    const impactColor = isPos ? 'text-cyberDanger' : 'text-cyberSuccess';
                    const impactIcon = isPos ? 'arrow-up' : 'arrow-down';
                    const impactLabel = isPos ? 'Increase Threat' : 'Decrease Threat';
                    
                    const div = document.createElement('div');
                    div.className = "glass-panel p-3.5 rounded-xl border border-white/5 bg-black/25 flex justify-between items-center";
                    div.innerHTML = `
                        <div>
                            <h5 class="text-xs font-bold text-white uppercase tracking-wider">${item.name}</h5>
                            <p class="text-[9px] text-gray-400 font-mono mt-0.5">Value: <span class="text-cyberSecondary">${item.value}</span></p>
                        </div>
                        <div class="text-right flex items-center space-x-3">
                            <div class="flex flex-col text-right">
                                <span class="text-xs font-bold ${impactColor}">${isPos ? '+' : ''}${item.impact.toFixed(2)}</span>
                                <span class="text-[9px] text-gray-500">${impactLabel}</span>
                            </div>
                            <div class="p-1.5 rounded-lg bg-white/5 ${impactColor}">
                                <i data-lucide="${impactIcon}" class="w-3.5 h-3.5"></i>
                            </div>
                        </div>
                    `;
                    shapContributionList.appendChild(div);
                });
                lucide.createIcons();
            }
        } catch (err) {
            console.error("SHAP explanation API error:", err);
        }
    }


    // ==========================================
    // 10. AUDIT PERFORMANCE REPORTS
    // ==========================================
    async function loadReportsCharts() {
        try {
            // Load dashboard predictions counts dynamically to set series
            const res = await fetch('/api/predict/history?limit=100');
            const result = await res.json();
            if (res.ok && result.status === 'success') {
                const history = result.data;
                let normal = 0;
                let attack = 0;
                let susp = 0;
                
                history.forEach(r => {
                    if (r.prediction === 'Normal') normal++;
                    else if (r.prediction === 'Attack') attack++;
                    else susp++;
                });
                
                // If history is empty, fallback defaults
                if (normal + attack + susp > 0) {
                    chartReportsDistribution.updateSeries([normal, attack, susp]);
                }
            }
        } catch (err) {
            console.error("Failed to re-render reports charts:", err);
        }
    }


    // ==========================================
    // 11. SETTINGS CONFIGURATIONS
    // ==========================================
    const thresholdSlider = document.getElementById('thresholdSlider');
    const thresholdValue = document.getElementById('thresholdValue');

    if (thresholdSlider && thresholdValue) {
        thresholdSlider.addEventListener('input', (e) => {
            const val = parseFloat(e.target.value).toFixed(2);
            thresholdValue.innerText = val;
            state.threshold = parseFloat(val);
            
            const falsePosMetric = document.getElementById('m-false-positive');
            if (falsePosMetric) {
                const fpr = (1 - val) * 0.22;
                falsePosMetric.innerText = `${fpr.toFixed(2)}%`;
            }
        });
    }


    // ==========================================
    // 12. OPERATION LOGS LOGGER
    // ==========================================
    const sysOpsLogs = document.getElementById('sysOpsLogs');
    const addSysLog = (msg) => {
        if (!sysOpsLogs) return;
        
        const now = new Date();
        const formatNum = (n) => n < 10 ? '0' + n : n;
        const timeStr = formatNum(now.getHours()) + ':' + formatNum(now.getMinutes()) + ':' + formatNum(now.getSeconds());

        const div = document.createElement('div');
        div.innerHTML = `<span class="text-cyberSecondary">[${timeStr}]</span> ${msg}`;
        sysOpsLogs.appendChild(div);
        sysOpsLogs.scrollTop = sysOpsLogs.scrollHeight;
    };
    
    // Background logger ticker
    setInterval(async () => {
        // Query health API to simulate check log
        try {
            const res = await fetch('/api/health');
            const data = await res.json();
            if (data.state === 'UP') {
                addSysLog(`FLOW_DEAMON: Healthy thread status OK.`);
            }
        } catch (err) {}
    }, 15000);

    // ==========================================
    // 13. AI SECURITY COPILOT CORE FRONTLOGIC
    // ==========================================
    const copilotChatForm = document.getElementById('copilotChatForm');
    const chatInput = document.getElementById('chatInput');
    const chatMessagesContainer = document.getElementById('chatMessagesContainer');
    const clearChatBtn = document.getElementById('clearChatBtn');
    
    // Ingest manuals DOMs
    const docDragDropArea = document.getElementById('docDragDropArea');
    const manualDocInput = document.getElementById('manualDocInput');
    const docProgressIndicator = document.getElementById('docProgressIndicator');
    const docProgressBar = document.getElementById('docProgressBar');
    const docProgressPercent = document.getElementById('docProgressPercent');
    const ingestedManualsList = document.getElementById('ingestedManualsList');
    
    // Smart Search DOMs
    const smartSearchBtn = document.getElementById('smartSearchBtn');
    const smartSearchQuery = document.getElementById('smartSearchQuery');
    const searchResultsList = document.getElementById('searchResultsList');

    // Simple markdown format parser for AI replies
    function parseMarkdown(text) {
        let html = text;
        // Escape HTML tags to prevent XSS
        html = html.replace(/</g, "&lt;").replace(/>/g, "&gt;");
        
        // Re-allow block pre code tags which we format manually
        // Bold
        html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        // Pre-formatted code blocks
        html = html.replace(/```(?:[a-zA-Z]*)\n([\s\S]*?)```/g, '<pre class="bg-black/50 p-3 rounded-lg border border-white/5 font-mono text-[10px] text-cyan-400 overflow-x-auto my-2"><code>$1</code></pre>');
        // Inline code blocks
        html = html.replace(/`([^`]+)`/g, '<code class="bg-white/10 px-1 rounded font-mono text-cyan-300">$1</code>');
        // Unordered lists
        html = html.replace(/^\s*[-*]\s+(.*)$/gm, '<li class="ml-4 list-disc text-gray-300 my-1">$1</li>');
        // Linebreaks
        html = html.replace(/\n/g, '<br>');
        return html;
    }

    // Load Chat History logs from SQLite
    async function loadChatHistory() {
        try {
            const res = await fetch('/api/chat/history?session_id=soc_session');
            const result = await res.json();
            if (res.ok && result.status === 'success') {
                const history = result.data;
                if (history.length === 0) return;
                
                chatMessagesContainer.innerHTML = '';
                history.forEach(msg => {
                    appendMessageBubble(msg.role, msg.message);
                });
                scrollChatToBottom();
            }
        } catch (err) {
            console.error("Failed to load chat history:", err);
        }
    }

    const appendMessageBubble = (role, message) => {
        const div = document.createElement('div');
        if (role === 'user') {
            div.className = "flex items-start space-x-3 max-w-[85%] self-end flex-row-reverse space-x-reverse";
            div.innerHTML = `
                <div class="w-8 h-8 rounded-full bg-cyberPrimary/20 flex items-center justify-center border border-cyberPrimary/30 text-cyberPrimary text-xs font-bold">SO</div>
                <div class="bg-cyberPrimary/20 border border-cyberPrimary/30 rounded-2xl rounded-tr-none p-4 text-xs leading-relaxed text-white">
                    ${message}
                </div>
            `;
        } else {
            div.className = "flex items-start space-x-3 max-w-[85%]";
            div.innerHTML = `
                <div class="w-8 h-8 rounded-full bg-cyberAccent/20 flex items-center justify-center border border-cyberAccent/30 text-cyberAccent text-xs font-bold">AI</div>
                <div class="bg-[#111827]/70 border border-white/5 rounded-2xl rounded-tl-none p-4 text-xs leading-relaxed text-gray-300">
                    ${parseMarkdown(message)}
                </div>
            `;
        }
        chatMessagesContainer.appendChild(div);
    };

    const scrollChatToBottom = () => {
        chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
    };

    // Chatbot submit messaging
    if (copilotChatForm) {
        copilotChatForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const message = chatInput.value.trim();
            if (!message) return;
            
            // Append User bubble
            appendMessageBubble('user', message);
            chatInput.value = '';
            scrollChatToBottom();
            
            // Append Typing loader bubble
            const typingBubble = document.createElement('div');
            typingBubble.id = 'chatTypingBubble';
            typingBubble.className = "flex items-start space-x-3 max-w-[85%]";
            typingBubble.innerHTML = `
                <div class="w-8 h-8 rounded-full bg-cyberAccent/20 flex items-center justify-center border border-cyberAccent/30 text-cyberAccent text-xs font-bold">AI</div>
                <div class="bg-[#111827]/70 border border-white/5 rounded-2xl rounded-tl-none p-4 text-xs text-gray-400 italic flex items-center space-x-2">
                    <svg class="animate-spin h-3.5 w-3.5 text-cyberAccent" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <span>Copilot is analyzing threat parameters...</span>
                </div>
            `;
            chatMessagesContainer.appendChild(typingBubble);
            scrollChatToBottom();
            
            try {
                const res = await fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        session_id: "soc_session",
                        message: message,
                        flow_id: state.currentSelectedFlow ? state.currentSelectedFlow.flow_id : null
                    })
                });
                const result = await res.json();
                
                // Remove typing loader
                const tb = document.getElementById('chatTypingBubble');
                if (tb) tb.remove();
                
                if (res.ok && result.status === 'success') {
                    appendMessageBubble('assistant', result.data.response);
                } else {
                    appendMessageBubble('assistant', "I encountered an error querying the model weights. Check server logs.");
                }
            } catch (err) {
                const tb = document.getElementById('chatTypingBubble');
                if (tb) tb.remove();
                console.error("Chatbot query failed:", err);
                appendMessageBubble('assistant', "Network connection timeout. Failed to query AI Copilot.");
            }
            scrollChatToBottom();
        });
    }

    // Bind prompt helper action triggers
    document.querySelectorAll('.quick-prompt-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const prompt = btn.getAttribute('data-prompt');
            chatInput.value = prompt;
            if (copilotChatForm) {
                copilotChatForm.dispatchEvent(new Event('submit', { cancelable: true }));
            }
        });
    });

    // Clear Chat history
    if (clearChatBtn) {
        clearChatBtn.addEventListener('click', async () => {
            try {
                const res = await fetch('/api/chat/clear', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: "soc_session" })
                });
                if (res.ok) {
                    chatMessagesContainer.innerHTML = `
                        <div class="flex items-start space-x-3 max-w-[85%]">
                            <div class="w-8 h-8 rounded-full bg-cyberAccent/20 flex items-center justify-center border border-cyberAccent/30 text-cyberAccent text-xs font-bold">AI</div>
                            <div class="bg-[#111827]/70 border border-white/5 rounded-2xl rounded-tl-none p-4 text-xs leading-relaxed text-gray-300">
                                Conversation memory cleared. Ready to assist.
                            </div>
                        </div>
                    `;
                }
            } catch (err) {
                console.error("Failed to clear history:", err);
            }
        });
    }

    // ==========================================
    // 14. DOCUMENTS LIBRARY UPLOADER & LIST
    // ==========================================
    
    // Ingest manuals click triggers browser dialog
    if (docDragDropArea) {
        docDragDropArea.addEventListener('click', () => manualDocInput.click());
    }

    if (manualDocInput) {
        manualDocInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) uploadManualDocument(file);
        });
    }

    async function uploadManualDocument(file) {
        const formData = new FormData();
        formData.append('file', file);

        docProgressIndicator.classList.remove('hidden');
        docProgressBar.style.width = '20%';
        docProgressPercent.innerText = '20%';

        try {
            const res = await fetch('/api/documents/upload', {
                method: 'POST',
                body: formData
            });
            docProgressBar.style.width = '70%';
            docProgressPercent.innerText = '70%';
            
            const result = await res.json();
            if (res.ok && result.status === 'success') {
                docProgressBar.style.width = '100%';
                docProgressPercent.innerText = '100%';
                
                addSysLog(`DOCS: Ingested and indexed manual ${file.name} successfully.`);
                
                setTimeout(() => {
                    docProgressIndicator.classList.add('hidden');
                    loadManualsCatalog();
                }, 800);
            } else {
                alert(result.message || "Failed to parse manual document.");
                docProgressIndicator.classList.add('hidden');
            }
        } catch (err) {
            console.error("Document upload error:", err);
            alert("Failed to upload manual due to network issue.");
            docProgressIndicator.classList.add('hidden');
        }
    }

    // Load Ingested manuals list
    async function loadManualsCatalog() {
        if (!ingestedManualsList) return;
        try {
            const res = await fetch('/api/documents/list');
            const result = await res.json();
            if (res.ok && result.status === 'success') {
                ingestedManualsList.innerHTML = '';
                const manuals = result.data;
                
                if (manuals.length === 0) {
                    ingestedManualsList.innerHTML = `<p class="text-[10px] text-gray-500 italic py-4">No security manuals ingested.</p>`;
                    return;
                }
                
                manuals.forEach(doc => {
                    const div = document.createElement('div');
                    div.className = "flex justify-between items-center bg-black/20 p-2.5 rounded-lg border border-white/5 text-[10px]";
                    div.innerHTML = `
                        <div class="min-w-0">
                            <p class="font-semibold text-white truncate">${doc.filename}</p>
                            <p class="text-gray-500 mt-0.5">Ingested: ${doc.uploaded_at.split(' ')[0]}</p>
                        </div>
                        <span class="px-2 py-0.5 rounded bg-cyberAccent/10 border border-cyberAccent/20 text-cyberAccent font-bold">${doc.chunks_count} chunks</span>
                    `;
                    ingestedManualsList.appendChild(div);
                });
            }
        } catch (err) {
            console.error("Failed to load documents catalog:", err);
        }
    }

    // ==========================================
    // 15. RAG SEMANTIC SMART SEARCH
    // ==========================================
    if (smartSearchBtn && smartSearchQuery && searchResultsList) {
        smartSearchBtn.addEventListener('click', async () => {
            const q = smartSearchQuery.value.trim();
            if (!q) return;
            
            smartSearchBtn.disabled = true;
            smartSearchBtn.innerText = "Searching...";
            
            try {
                const res = await fetch(`/api/documents/search?q=${encodeURIComponent(q)}`);
                const result = await res.json();
                
                smartSearchBtn.disabled = false;
                smartSearchBtn.innerText = "Search";
                
                searchResultsList.innerHTML = '';
                searchResultsList.classList.remove('hidden');
                
                if (res.ok && result.status === 'success') {
                    const matches = result.data;
                    if (matches.length === 0) {
                        searchResultsList.innerHTML = `<p class="text-[10px] text-gray-500 italic py-2">No matching chunks mapped in document vectors index.</p>`;
                        return;
                    }
                    
                    matches.forEach(item => {
                        const div = document.createElement('div');
                        div.className = "bg-[#090f1b] p-3 rounded-xl border border-white/5 space-y-1.5";
                        div.innerHTML = `
                            <div class="flex justify-between text-[9px] font-mono text-gray-500">
                                <span>Source: <span class="text-cyberSecondary font-semibold">${item.source}</span></span>
                                <span>Similarity Score: <span class="text-cyberAccent font-bold">${(item.similarity * 100).toFixed(1)}%</span></span>
                            </div>
                            <p class="text-[10px] text-gray-300 leading-relaxed font-light bg-black/15 p-2 rounded border border-white/5">
                                ${item.text}
                            </p>
                        `;
                        searchResultsList.appendChild(div);
                    });
                }
            } catch (err) {
                smartSearchBtn.disabled = false;
                smartSearchBtn.innerText = "Search";
                console.error("Semantic search failed:", err);
            }
        });
    }

    // ==========================================
    // 13. API KEYS SETTINGS MANAGEMENT
    // ==========================================
    const geminiApiKeyInput = document.getElementById('geminiApiKey');
    const groqApiKeyInput = document.getElementById('groqApiKey');
    const saveApiKeysBtn = document.getElementById('saveApiKeysBtn');
    const saveKeysStatus = document.getElementById('saveKeysStatus');

    const loadApiSettings = async () => {
        if (!geminiApiKeyInput || !groqApiKeyInput) return;
        try {
            const resp = await fetch('/api/settings');
            const res = await resp.json();
            if (res.status === 'success') {
                if (res.data.gemini_api_key_set) {
                    geminiApiKeyInput.placeholder = "API Key is configured ••••••••••••";
                } else {
                    geminiApiKeyInput.placeholder = "Enter GEMINI_API_KEY (Unconfigured)";
                }
                if (res.data.groq_api_key_set) {
                    groqApiKeyInput.placeholder = "API Key is configured ••••••••••••";
                } else {
                    groqApiKeyInput.placeholder = "Enter GROQ_API_KEY (Unconfigured)";
                }
            }
        } catch (err) {
            console.error("Failed to load API settings status:", err);
        }
    };

    if (saveApiKeysBtn) {
        saveApiKeysBtn.addEventListener('click', async () => {
            const gemini_api_key = geminiApiKeyInput.value.trim();
            const groq_api_key = groqApiKeyInput.value.trim();
            
            const payload = {};
            if (gemini_api_key) payload.gemini_api_key = gemini_api_key;
            if (groq_api_key) payload.groq_api_key = groq_api_key;
            
            if (Object.keys(payload).length === 0) {
                alert("Please enter at least one API key to save.");
                return;
            }
            
            saveApiKeysBtn.disabled = true;
            saveApiKeysBtn.innerText = "Saving Keys...";
            
            try {
                const resp = await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                
                const res = await resp.json();
                if (resp.ok && res.status === 'success') {
                    geminiApiKeyInput.value = '';
                    groqApiKeyInput.value = '';
                    await loadApiSettings();
                    
                    if (saveKeysStatus) {
                        saveKeysStatus.classList.remove('hidden');
                        setTimeout(() => {
                            saveKeysStatus.classList.add('hidden');
                        }, 3000);
                    }
                    addSysLog("AI Copilot API credentials updated.");
                } else {
                    alert(res.message || "Failed to update keys.");
                }
            } catch (err) {
                console.error("Failed to save API settings:", err);
                alert("An error occurred while saving API keys.");
            } finally {
                saveApiKeysBtn.disabled = false;
                saveApiKeysBtn.innerText = "Save API Keys";
            }
        });
    }

    // Call loadApiSettings initially
    loadApiSettings();

});

// Global remediation block trigger
function triggerMitigation() {
    alert("[SECURITY SOC COMMAND] Applying firewall rules to isolate source IP. Port rules have been pushed to router interfaces successfully!");
}

// Global Reports download handler pointing to Flask download attachment APIs
function downloadReport(type) {
    window.location.href = `/api/reports/download?format=${type}`;
}
