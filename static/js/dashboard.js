// dashboard.js - SOC Dashboard Charts, Mock Data, and Ingestion flow

document.addEventListener('DOMContentLoaded', () => {
    
    // ==========================================
    // 1. MOCK DATASETS & SETUP
    // ==========================================
    const mockDatasetRows = [
        { id: "FL-1082", src: "192.168.1.10", dst: "10.0.0.4", proto: "TCP (6)", port: 443, prediction: "Normal", confidence: 99.8, risk: "Low", type: "Secure HTTPS", time: "18:38:05", rate: 22.4, duration: 1.2, size: 840, flags: "ACK", desc: "Standard encrypted web browsing traffic via TLS handshake. Packet sizes and frequencies match baseline user profiles.", shap: [
            { name: "packet_rate", value: "22.4 p/s", impact: -0.18, type: "negative" },
            { name: "dst_port", value: "443", impact: -0.22, type: "negative" },
            { name: "flow_duration", value: "1.2s", impact: -0.12, type: "negative" },
            { name: "packet_size", value: "840B", impact: 0.05, type: "positive" },
            { name: "syn_flags", value: "0", impact: -0.15, type: "negative" }
        ]},
        { id: "FL-7294", src: "10.0.0.12", dst: "192.168.1.100", proto: "TCP (6)", port: 3306, prediction: "Attack", confidence: 98.7, risk: "Critical", type: "DDoS SQL Port Exploit", time: "18:38:02", rate: 2450.8, duration: 42.6, size: 3450, flags: "SYN", desc: "Massive volumetric scan targeting database interface. Features a high TCP SYN rate with short payloads, indicating port exhaustion tactics.", shap: [
            { name: "packet_rate", value: "2450.8 p/s", impact: 0.38, type: "positive" },
            { name: "dst_port", value: "3306", impact: 0.28, type: "positive" },
            { name: "flow_duration", value: "42.6s", impact: 0.15, type: "positive" },
            { name: "packet_size", value: "3450B", impact: -0.05, type: "negative" },
            { name: "syn_flags", value: "1", impact: 0.22, type: "positive" }
        ]},
        { id: "FL-3391", src: "172.16.0.45", dst: "192.168.1.5", proto: "UDP (17)", port: 53, prediction: "Suspicious", confidence: 72.4, risk: "Moderate", type: "DNS Tunneling Leak", time: "18:37:55", rate: 145.2, duration: 18.4, size: 1420, flags: "NONE", desc: "Large DNS requests repeating periodically. Suspicion of encrypted tunnel headers embedded within DNS queries for data exfiltration.", shap: [
            { name: "packet_rate", value: "145.2 p/s", impact: 0.12, type: "positive" },
            { name: "dst_port", value: "53", impact: -0.15, type: "negative" },
            { name: "flow_duration", value: "18.4s", impact: 0.08, type: "positive" },
            { name: "packet_size", value: "1420B", impact: 0.22, type: "positive" },
            { name: "syn_flags", value: "0", impact: -0.10, type: "negative" }
        ]},
        { id: "FL-8812", src: "192.168.1.25", dst: "192.168.1.1", proto: "ICMP (1)", port: 0, prediction: "Normal", confidence: 99.2, risk: "Low", type: "Ping Echo Request", time: "18:37:41", rate: 1.0, duration: 0.4, size: 64, flags: "NONE", desc: "Standard ICMP echo ping request mapping gateway connectivity. Completely aligned with safe node operations.", shap: [
            { name: "packet_rate", value: "1.0 p/s", impact: -0.25, type: "negative" },
            { name: "dst_port", value: "0", impact: -0.18, type: "negative" },
            { name: "flow_duration", value: "0.4s", impact: -0.22, type: "negative" },
            { name: "packet_size", value: "64B", impact: -0.14, type: "negative" },
            { name: "syn_flags", value: "0", impact: -0.10, type: "negative" }
        ]},
        { id: "FL-9904", src: "85.204.1.18", dst: "192.168.1.12", proto: "TCP (6)", port: 22, prediction: "Attack", confidence: 94.6, risk: "High", type: "SSH Brute-Force", time: "18:37:30", rate: 88.6, duration: 112.5, size: 2100, flags: "SYN-ACK", desc: "Rapid SSH connection retries from external WAN IP. Triggers multiple authentication failures, indicative of dictionary credential cracking.", shap: [
            { name: "packet_rate", value: "88.6 p/s", impact: 0.21, type: "positive" },
            { name: "dst_port", value: "22", impact: 0.32, type: "positive" },
            { name: "flow_duration", value: "112.5s", impact: 0.18, type: "positive" },
            { name: "packet_size", value: "2100B", impact: 0.04, type: "positive" },
            { name: "syn_flags", value: "1", impact: 0.08, type: "positive" }
        ]},
        { id: "FL-2281", src: "192.168.1.15", dst: "74.125.19.14", proto: "TCP (6)", port: 80, prediction: "Normal", confidence: 98.9, risk: "Low", type: "HTTP Insecure fetch", time: "18:37:12", rate: 8.5, duration: 2.1, size: 1040, flags: "ACK", desc: "Safe outbound TCP handshake fetch from external web assets. No suspicious payload configurations identified.", shap: [
            { name: "packet_rate", value: "8.5 p/s", impact: -0.20, type: "negative" },
            { name: "dst_port", value: "80", impact: -0.05, type: "negative" },
            { name: "flow_duration", value: "2.1s", impact: -0.10, type: "negative" },
            { name: "packet_size", value: "1040B", impact: -0.08, type: "negative" },
            { name: "syn_flags", value: "0", impact: -0.15, type: "negative" }
        ]},
        { id: "FL-4009", src: "192.168.1.30", dst: "192.168.1.120", proto: "TCP (6)", port: 445, prediction: "Suspicious", confidence: 64.8, risk: "Moderate", type: "SMB Share Query", time: "18:36:58", rate: 45.6, duration: 4.8, size: 2800, flags: "ACK", desc: "Outbound queries searching for network mapped folder assets via SMB protocol. Risk elevated due to access frequencies from guest segment.", shap: [
            { name: "packet_rate", value: "45.6 p/s", impact: 0.05, type: "positive" },
            { name: "dst_port", value: "445", impact: 0.15, type: "positive" },
            { name: "flow_duration", value: "4.8s", impact: -0.04, type: "negative" },
            { name: "packet_size", value: "2800B", impact: 0.18, type: "positive" },
            { name: "syn_flags", value: "0", impact: -0.10, type: "negative" }
        ]}
    ];

    let currentSelectedFlow = mockDatasetRows[1]; // Default selection for SHAP visual dashboard
    let activeDetectionsRan = false; // Controls whether table is fully populated or waiting

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
        // Deactivate all links & contents
        tabLinks.forEach(link => link.classList.remove('active', 'bg-white/5', 'text-white', 'border-white/5', 'shadow-neon-blue/5'));
        tabContents.forEach(content => content.classList.remove('active'));

        // Activate matching elements
        const activeLink = document.querySelector(`.tab-link[data-tab="${tabId}"]`);
        const activeContent = document.getElementById(`tab-${tabId}`);

        if (activeLink && activeContent) {
            activeLink.classList.add('active', 'bg-white/5', 'text-white', 'border-white/5', 'shadow-neon-blue/5');
            activeContent.classList.add('active');

            // Format layout title
            const tabNameMap = {
                overview: "Dashboard Overview",
                upload: "Upload Flow Dataset",
                monitoring: "Real-Time Detection Engine",
                shap: "SHAP Explainability Insights",
                reports: "Statistical Performance Reports",
                settings: "SOC Configurations & Rules"
            };
            headerTitle.innerText = tabNameMap[tabId] || "SOC Command Center";
        }
    };

    // Tab click handles
    tabLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetTab = link.getAttribute('data-tab');
            window.location.hash = targetTab;
            switchTab(targetTab);
        });
    });

    // Read initial hash URL route
    const handleHashRoute = () => {
        const hash = window.location.hash.substring(1);
        if (hash) {
            switchTab(hash);
        } else {
            switchTab('overview');
        }
    };
    window.addEventListener('hashchange', handleHashRoute);
    handleHashRoute(); // On page mount

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
        markers: { size: 0 },
        grid: {
            borderColor: 'rgba(255,255,255,0.05)',
            xaxis: { lines: { show: false } },
            yaxis: { lines: { show: true } }
        },
        xaxis: {
            categories: ['18:29', '18:30', '18:31', '18:32', '18:33', '18:34', '18:35', '18:36', '18:37', '18:38'],
            axisBorder: { show: false },
            axisTicks: { show: false }
        },
        yaxis: { title: { text: 'Flow rate (packets/sec)', style: { fontWeight: 500 } } },
        tooltip: { theme: 'dark', x: { show: true } },
        legend: { show: false }
    };
    const chartLiveTraffic = new ApexCharts(document.querySelector("#chartLiveTraffic"), liveTrafficOptions);
    chartLiveTraffic.render();

    // Chart 2: Threat Density Heatmap
    const generateHeatmapData = () => {
        const hours = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
        const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
        return days.map(day => ({
            name: day,
            data: hours.map(hour => ({
                x: hour,
                y: Math.floor(Math.random() * 85) // Random threat indexes
            }))
        }));
    };
    const heatmapOptions = {
        series: generateHeatmapData(),
        chart: {
            type: 'heatmap',
            height: 245,
            background: 'transparent',
            foreColor: '#9CA3AF',
            toolbar: { show: false }
        },
        dataLabels: { enabled: false },
        colors: ['#06B6D4'], // Base color theme
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
        xaxis: { axisBorder: { show: false }, axisTicks: { show: false } },
        tooltip: { theme: 'dark' }
    };
    const chartThreatHeatmap = new ApexCharts(document.querySelector("#chartThreatHeatmap"), heatmapOptions);
    chartThreatHeatmap.render();

    // Chart 3: Protocol distribution ratio
    const packetFlowOptions = {
        series: [68, 24, 8],
        chart: {
            type: 'donut',
            height: 235,
            background: 'transparent',
            foreColor: '#9CA3AF'
        },
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
                    background: 'transparent',
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
        series: [{
            name: 'Mean SHAP Value',
            data: [0.38, 0.32, 0.28, 0.22, 0.18, 0.14]
        }],
        chart: {
            type: 'bar',
            height: 230,
            background: 'transparent',
            foreColor: '#9CA3AF',
            toolbar: { show: false }
        },
        plotOptions: {
            bar: {
                horizontal: true,
                barHeight: '55%',
                borderRadius: 4,
                colors: {
                    ranges: [{ from: 0, to: 100, color: '#8B5CF6' }] // Accent Purple
                }
            }
        },
        dataLabels: { enabled: false },
        grid: { borderColor: 'rgba(255,255,255,0.05)', xaxis: { lines: { show: true } } },
        xaxis: {
            categories: ['dst_port', 'packet_rate', 'flow_duration', 'packet_size', 'payload_weight', 'syn_flags'],
            axisBorder: { show: false },
            axisTicks: { show: false }
        },
        yaxis: { labels: { style: { colors: '#9CA3AF' } } },
        tooltip: { theme: 'dark' }
    };
    const chartFeatureImportance = new ApexCharts(document.querySelector("#chartFeatureImportance"), featureImportanceOptions);
    chartFeatureImportance.render();

    // Chart 5: Reports Page distribution
    const reportsDistributionOptions = {
        series: [74, 18, 8],
        chart: {
            type: 'pie',
            height: 270,
            background: 'transparent',
            foreColor: '#9CA3AF'
        },
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
        chart: {
            type: 'area',
            height: 260,
            background: 'transparent',
            foreColor: '#9CA3AF',
            toolbar: { show: false }
        },
        colors: ['#10B981', '#EF4444'],
        dataLabels: { enabled: false },
        stroke: { curve: 'smooth', width: 2 },
        fill: {
            type: 'gradient',
            gradient: {
                shadeIntensity: 1,
                opacityFrom: 0.2,
                opacityTo: 0.02,
                stops: [0, 90, 100]
            }
        },
        grid: { borderColor: 'rgba(255,255,255,0.05)' },
        xaxis: {
            categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
            axisBorder: { show: false },
            axisTicks: { show: false }
        },
        tooltip: { theme: 'dark' }
    };
    const chartReportsTimeline = new ApexCharts(document.querySelector("#chartReportsTimeline"), reportsTimelineOptions);
    chartReportsTimeline.render();


    // ==========================================
    // 5. DATASET UPLOAD LOGIC
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

    let loadedFile = null;

    const setupFileDisplay = (name, size, cols, rows) => {
        loadedFile = { name, size, cols, rows };
        
        fileNameText.innerText = name;
        fileSizeText.innerText = size;
        fileColumnsText.innerText = cols;
        fileRowsText.innerText = rows.toLocaleString();

        dragDropArea.classList.add('hidden');
        fileStatsContainer.classList.remove('hidden');

        // Enable analyze button
        uploadAnalyzeBtn.disabled = false;
        uploadAnalyzeBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        uploadAnalyzeBtn.classList.add('hover:scale-[1.02]');
    };

    // Remove file handler
    removeFileBtn.addEventListener('click', () => {
        loadedFile = null;
        fileStatsContainer.classList.add('hidden');
        dragDropArea.classList.remove('hidden');
        datasetInput.value = '';
        uploadProgressBar.style.width = '0%';
        uploadPercent.innerText = '0%';

        // Disable analyze button
        uploadAnalyzeBtn.disabled = true;
        uploadAnalyzeBtn.classList.add('opacity-50', 'cursor-not-allowed');
        uploadAnalyzeBtn.classList.remove('hover:scale-[1.02]');
    });

    // File Browser Dialog
    dragDropArea.addEventListener('click', () => datasetInput.click());

    datasetInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            const kbSize = (file.size / 1024).toFixed(2) + " KB";
            setupFileDisplay(file.name, kbSize, 42, 12500);
        }
    });

    // Drag-over highlights
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
        if (file) {
            const kbSize = (file.size / 1024).toFixed(2) + " KB";
            setupFileDisplay(file.name, kbSize, 42, 12500);
        }
    });

    // Load sample dataset
    useSampleBtn.addEventListener('click', () => {
        setupFileDisplay("kdd_cup_intrusion_sample.csv", "412.8 KB", 41, 24600);
    });

    // Click Analyze Dataset
    uploadAnalyzeBtn.addEventListener('click', () => {
        if (!loadedFile) return;

        // Animate progression bar
        let progress = 0;
        uploadAnalyzeBtn.disabled = true;
        uploadAnalyzeBtn.innerText = "Analyzing Matrix...";
        
        const timer = setInterval(() => {
            progress += 10;
            uploadProgressBar.style.width = `${progress}%`;
            uploadPercent.innerText = `${progress}%`;

            if (progress >= 100) {
                clearInterval(timer);
                
                // Add sys log alert
                addSysLog(`INGEST: Integrated ${loadedFile.name} successfully. Launching Detection router.`);
                
                // Route automatically to Detection/Monitoring tab
                setTimeout(() => {
                    // Reset upload page state
                    uploadAnalyzeBtn.innerText = "Analyze Dataset";
                    uploadAnalyzeBtn.disabled = false;
                    window.location.hash = "monitoring";
                }, 500);
            }
        }, 120);
    });

    // ==========================================
    // 6. DETECTION RUNNER & TABLES POPULATION
    // ==========================================
    const runDetectionBtn = document.getElementById('runDetectionBtn');
    const detectionLoader = document.getElementById('detectionLoader');
    const detectionTableBody = document.getElementById('detectionTableBody');
    const tableSearch = document.getElementById('tableSearch');
    const tableFilter = document.getElementById('tableFilter');

    const renderTableRows = (data) => {
        detectionTableBody.innerHTML = '';
        
        if (data.length === 0) {
            detectionTableBody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center py-8 text-gray-500 font-light">No records found matching filters.</td>
                </tr>
            `;
            return;
        }

        data.forEach((row, idx) => {
            // Pred colors configuration
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
                <td class="px-6 py-4 font-mono font-bold text-gray-400">${row.id}</td>
                <td class="px-6 py-4 font-mono">${row.src}</td>
                <td class="px-6 py-4 font-mono">${row.dst}</td>
                <td class="px-6 py-4 font-mono text-gray-400">${row.proto} (port ${row.port})</td>
                <td class="px-6 py-4">
                    <span class="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold border ${predClass}">
                        <i data-lucide="${badgeIcon}" class="w-3.5 h-3.5"></i>
                        <span>${row.prediction.toUpperCase()}</span>
                    </span>
                </td>
                <td class="px-6 py-4 font-mono font-medium">${row.confidence}%</td>
                <td class="px-6 py-4">
                    <span class="${riskClass}">${row.risk}</span>
                </td>
                <td class="px-6 py-4 text-right">
                    <button class="px-3 py-1 rounded bg-[#0f192b] border border-white/5 hover:border-cyberSecondary text-cyberSecondary hover:text-white text-[10px] font-bold transition-all duration-200 view-details-btn" data-id="${row.id}">
                        Inspect SOC
                    </button>
                </td>
            `;

            // Click row triggers drawer
            tr.addEventListener('click', (e) => {
                // If user clicked the button itself, don't trigger twice
                if (e.target.closest('.view-details-btn')) return;
                openAttackDetails(row);
            });

            detectionTableBody.appendChild(tr);
        });

        // Initialize newly injected lucide icons
        lucide.createIcons();

        // Bind inspect buttons
        document.querySelectorAll('.view-details-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const id = btn.getAttribute('data-id');
                const row = mockDatasetRows.find(r => r.id === id);
                if (row) openAttackDetails(row);
            });
        });
    };

    // Pre-populate empty message
    const renderWaitingState = () => {
        detectionTableBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-16 text-gray-400 space-y-3">
                    <div class="p-3 rounded-full bg-[#111827] text-gray-500 w-fit mx-auto border border-white/5">
                        <i data-lucide="play-circle" class="w-8 h-8"></i>
                    </div>
                    <div>
                        <p class="text-sm font-semibold text-white">Detection Engine is Idle</p>
                        <p class="text-xs text-gray-500 font-light mt-1">Click the "Run Detection Engine" button above to ingest flow parameters and execute classification models.</p>
                    </div>
                </td>
            </tr>
        `;
        lucide.createIcons();
    };
    renderWaitingState();

    // Trigger run detection
    runDetectionBtn.addEventListener('click', () => {
        runDetectionBtn.disabled = true;
        detectionLoader.classList.remove('hidden');
        
        let progress = 0;
        const timer = setInterval(() => {
            progress += 20;
            if (progress >= 100) {
                clearInterval(timer);
                activeDetectionsRan = true;
                
                // Show output
                detectionLoader.classList.add('hidden');
                runDetectionBtn.disabled = false;
                
                applyFiltersAndRender();
                addSysLog("XGB_DECIDE: Analyzed active network matrix. Anomalies isolated.");
            }
        }, 180);
    });

    // Filter and search handlers
    const applyFiltersAndRender = () => {
        if (!activeDetectionsRan) return;

        const query = tableSearch.value.toLowerCase().trim();
        const typeFilter = tableFilter.value;

        const filtered = mockDatasetRows.filter(row => {
            const matchesSearch = row.id.toLowerCase().includes(query) || 
                                  row.src.includes(query) || 
                                  row.dst.includes(query) || 
                                  row.type.toLowerCase().includes(query);
            
            const matchesFilter = typeFilter === 'all' || 
                                  row.prediction.toLowerCase() === typeFilter;

            return matchesSearch && matchesFilter;
        });

        renderTableRows(filtered);
    };

    tableSearch.addEventListener('input', applyFiltersAndRender);
    tableFilter.addEventListener('change', applyFiltersAndRender);


    // ==========================================
    // 7. ATTACK DETAILS DRAWER CONTROLS
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
    const drawerRiskBox = document.getElementById('drawerRiskBox');
    const drawerHeaderIcon = document.getElementById('drawerHeaderIcon');

    const openAttackDetails = (row) => {
        // Populate values
        drawerTitle.innerText = row.prediction === 'Normal' ? "Flow Connection Details" : "Anomaly Alert Inspection";
        drawerFlowId.innerText = `Flow ID: ${row.id}`;
        drawerSrcIp.innerText = row.src;
        drawerDstIp.innerText = row.dst;
        drawerProtocol.innerText = row.proto + ` (port ${row.port})`;
        drawerAttackType.innerText = row.type;
        drawerTimestamp.innerText = row.time;
        
        // Pred specific styling
        if (row.prediction === 'Normal') {
            drawerRiskHeader.innerText = "SAFE SECURE FLOW";
            drawerConfidenceText.innerText = `${row.confidence}% Normal`;
            drawerRiskIndex.innerText = "LOW RISK (1/100)";
            drawerRiskBox.className = "p-4 rounded-xl bg-cyberSuccess/10 border border-cyberSuccess/20 flex flex-col items-center justify-center text-center space-y-1";
            drawerConfidenceText.className = "text-2xl font-space font-bold text-cyberSuccess text-glow-success";
            drawerRiskHeader.className = "text-[10px] font-semibold uppercase text-cyberSuccess tracking-widest font-mono";
            drawerHeaderIcon.className = "w-5 h-5 text-cyberSuccess";
            drawerHeaderIcon.setAttribute('data-lucide', 'shield-check');
            drawerRemediationText.innerText = "No remediation protocols required. Packet patterns fit standard traffic baseline criteria. Monitoring remains active.";
        } else if (row.prediction === 'Attack') {
            drawerRiskHeader.innerText = "CRITICAL SECURITY INCIDENT";
            drawerConfidenceText.innerText = `${row.confidence}% Attack`;
            drawerRiskIndex.innerText = `CRITICAL (${Math.floor(row.confidence)}/100)`;
            drawerRiskBox.className = "p-4 rounded-xl bg-cyberDanger/10 border border-cyberDanger/20 flex flex-col items-center justify-center text-center space-y-1";
            drawerConfidenceText.className = "text-2xl font-space font-bold text-cyberDanger text-glow-danger animate-pulse";
            drawerRiskHeader.className = "text-[10px] font-semibold uppercase text-cyberDanger tracking-widest font-mono";
            drawerHeaderIcon.className = "w-5 h-5 text-cyberDanger animate-pulse";
            drawerHeaderIcon.setAttribute('data-lucide', 'shield-alert');
            drawerRemediationText.innerText = `Deploy ingress block command immediately. Flag source IP ${row.src} at firewall and isolate endpoint port ${row.port} from corporate core switch.`;
        } else {
            drawerRiskHeader.innerText = "SUSPICIOUS LOG PROFILE";
            drawerConfidenceText.innerText = `${row.confidence}% Suspicious`;
            drawerRiskIndex.innerText = "MODERATE RISK (50/100)";
            drawerRiskBox.className = "p-4 rounded-xl bg-cyberWarning/10 border border-cyberWarning/20 flex flex-col items-center justify-center text-center space-y-1";
            drawerConfidenceText.className = "text-2xl font-space font-bold text-cyberWarning text-glow-cyan";
            drawerRiskHeader.className = "text-[10px] font-semibold uppercase text-cyberWarning tracking-widest font-mono";
            drawerHeaderIcon.className = "w-5 h-5 text-cyberWarning";
            drawerHeaderIcon.setAttribute('data-lucide', 'alert-triangle');
            drawerRemediationText.innerText = "Monitor connection log parameters continuously. Suggest running deep packet audits on protocol payloads to ensure no data is leaking.";
        }

        // Render mini SHAP list inside drawer
        drawerShapReasonsList.innerHTML = '';
        row.shap.forEach(item => {
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

        // Setup SHAP button linking
        drawerOpenShapBtn.onclick = () => {
            currentSelectedFlow = row;
            toggleDrawer(false);
            window.location.hash = "shap";
            renderShapDashboard();
        };

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
    // 8. SHAP DASHBOARD BUILDER (DYNAMIC FORCE PLOTS)
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

    const renderShapDashboard = () => {
        const row = currentSelectedFlow;
        shapFlowId.innerText = row.id;

        // Calculate force percentages
        let posSum = 0;
        let negSum = 0;
        row.shap.forEach(item => {
            if (item.type === 'positive') posSum += item.impact;
            else negSum += Math.abs(item.impact);
        });

        const totalForce = posSum + negSum;
        const normPercent = totalForce > 0 ? (negSum / totalForce) * 100 : 50;
        const attackPercent = 100 - normPercent;

        // Update force bars
        shapForceNormal.style.width = `${normPercent}%`;
        shapForceAttack.style.width = `${attackPercent}%`;
        shapForceSeparator.style.left = `${normPercent}%`;

        // Output probability config
        const probabilityVal = row.prediction === 'Normal' ? (100 - row.confidence) / 100 : row.confidence / 100;
        shapOutputVal.innerText = `Output Prob: ${probabilityVal.toFixed(3)} (${row.prediction.toUpperCase()})`;

        // Render explanation card
        if (row.prediction === 'Normal') {
            shapDecisionText.innerText = "NORMAL BUSINESS TRAFFIC";
            shapDecisionText.className = "text-cyberSuccess text-glow-success font-bold";
            shapExplanationText.innerText = `This connection matches standard header distributions. Key values preventing threat escalation include destination port ${row.port} (safe target) and normal packet size bounds of ${row.size}B.`;
        } else if (row.prediction === 'Attack') {
            shapDecisionText.innerText = `${row.type.toUpperCase()}`;
            shapDecisionText.className = "text-cyberDanger text-glow-danger font-bold animate-pulse";
            shapExplanationText.innerText = `Flagged as threat due to aggressive port access metrics. Highly abnormal packet rate (${row.rate} p/s) and destination port targeting (${row.port}) contributed significantly to classification heights.`;
        } else {
            shapDecisionText.innerText = "SUSPICIOUS ACTIVITY";
            shapDecisionText.className = "text-cyberWarning text-glow-cyan font-bold";
            shapExplanationText.innerText = `Classified as suspicious because of unusual packet size payloads (${row.size}B) targeting port ${row.port}. While not a direct exploit flood, patterns suggest probing configurations.`;
        }

        // Render Waterfall plot elements
        shapWaterfallContainer.innerHTML = '';
        let cumulativeValue = 0.34; // Base value
        
        // Injected base block
        const baseDiv = document.createElement('div');
        baseDiv.className = "flex justify-between items-center text-[10px] font-mono text-gray-500 bg-white/5 px-3 py-1.5 rounded";
        baseDiv.innerHTML = `<span>Model Base Ingestion Baseline</span><span class="font-bold">0.34</span>`;
        shapWaterfallContainer.appendChild(baseDiv);

        row.shap.forEach(item => {
            const isPos = item.type === 'positive';
            const sign = isPos ? '+' : '-';
            const colorClass = isPos ? 'text-cyberDanger font-bold' : 'text-cyberSuccess font-bold';
            
            cumulativeValue = isPos ? cumulativeValue + item.impact : cumulativeValue - item.impact;
            if (cumulativeValue < 0) cumulativeValue = 0.01;
            if (cumulativeValue > 1) cumulativeValue = 0.99;

            const div = document.createElement('div');
            div.className = "flex justify-between items-center text-xs font-mono border-b border-white/5 py-2";
            div.innerHTML = `
                <div class="flex flex-col">
                    <span class="text-white font-semibold">${item.name} = ${item.value}</span>
                    <span class="text-[9px] text-gray-400">Impact adjustment</span>
                </div>
                <div class="flex items-center space-x-6">
                    <span class="${colorClass}">${sign}${item.impact.toFixed(2)}</span>
                    <span class="text-gray-400 w-12 text-right font-bold">${cumulativeValue.toFixed(2)}</span>
                </div>
            `;
            shapWaterfallContainer.appendChild(div);
        });

        // Render features contribution details grid
        shapContributionList.innerHTML = '';
        row.shap.forEach(item => {
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
    };

    renderShapDashboard(); // Initial load default


    // ==========================================
    // 9. SETTINGS & THRESHOLDS
    // ==========================================
    const thresholdSlider = document.getElementById('thresholdSlider');
    const thresholdValue = document.getElementById('thresholdValue');

    if (thresholdSlider && thresholdValue) {
        thresholdSlider.addEventListener('input', (e) => {
            const val = parseFloat(e.target.value).toFixed(2);
            thresholdValue.innerText = val;
            
            // Adjust mock metrics card in dashboard
            const falsePosMetric = document.getElementById('m-false-positive');
            if (falsePosMetric) {
                // Lower threshold = higher false positives
                const fpr = (1 - val) * 0.22;
                falsePosMetric.innerText = `${fpr.toFixed(2)}%`;
            }
        });
    }


    // ==========================================
    // 10. SYSTEM STATUS LOGGER GENERATOR
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

        // Keep scroll bottom
        sysOpsLogs.scrollTop = sysOpsLogs.scrollHeight;
    };

    // Auto-generate minor background traffic logs to simulate network ingestion
    setInterval(() => {
        const randomIPs = ["192.168.1.15", "10.0.0.45", "192.168.1.12", "72.4.18.25", "10.0.0.18"];
        const randomPorts = [80, 443, 22, 53, 3306, 8080];
        const randomIP = randomIPs[Math.floor(Math.random() * randomIPs.length)];
        const randomPort = randomPorts[Math.floor(Math.random() * randomPorts.length)];

        addSysLog(`FLOW_DEAMON: Registered network flow packet from ${randomIP} on port ${randomPort}`);
        
        // Randomly update dashboard main metric packet totals slightly
        const packetsMetric = document.getElementById('m-total-packets');
        if (packetsMetric) {
            const curVal = parseFloat(packetsMetric.innerText);
            packetsMetric.innerText = (curVal + 0.3).toFixed(1) + "K";
        }
    }, 12000);


    // ==========================================
    // 11. RECENT ALERTS LIST POPULATOR (DASHBOARD RIGHT SIDE)
    // ==========================================
    const dashboardAlertsList = document.getElementById('dashboardAlertsList');
    
    const populateDashboardAlerts = () => {
        dashboardAlertsList.innerHTML = '';
        
        // Filter out attacks/suspicious rows
        const dangerRows = mockDatasetRows.filter(r => r.prediction !== 'Normal');
        
        dangerRows.forEach(row => {
            const isAttack = row.prediction === 'Attack';
            const dotClass = isAttack ? 'bg-cyberDanger shadow-neon-danger' : 'bg-cyberWarning';
            
            const div = document.createElement('div');
            div.className = "flex items-center space-x-3.5 p-3 rounded-xl border border-white/5 hover:border-cyberSecondary/30 hover:bg-white/5 cursor-pointer transition-all duration-150";
            div.innerHTML = `
                <span class="w-2.5 h-2.5 rounded-full ${dotClass} flex-shrink-0 animate-pulse"></span>
                <div class="flex-grow min-w-0">
                    <p class="text-xs font-semibold text-white truncate">${row.type}</p>
                    <p class="text-[10px] text-gray-400 font-mono mt-0.5 truncate">${row.src} ➔ Port ${row.port}</p>
                </div>
                <div class="text-right">
                    <p class="text-[10px] font-bold ${isAttack ? 'text-cyberDanger' : 'text-cyberWarning'}">${row.confidence}%</p>
                    <p class="text-[8px] text-gray-500 font-mono">${row.time}</p>
                </div>
            `;

            // Click alert opens drawer
            div.addEventListener('click', () => openAttackDetails(row));
            dashboardAlertsList.appendChild(div);
        });
    };
    populateDashboardAlerts();

});

// Global Trigger block action remediation
function triggerMitigation() {
    alert("[SECURITY SOC COMMAND] Applying firewall rules to isolate source IP. Port rules have been pushed to router interfaces successfully!");
}

// Global Trigger file download reports
function downloadReport(type) {
    alert(`[EXPORT INITIALIZED] Preparing certified security report file. Downloading your ${type.toUpperCase()} log summary report shortly...`);
}
