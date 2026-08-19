// app.js - Logic for the AI Kavach Dashboard

let dashboardData = null; // Store fetched data for export

document.addEventListener('DOMContentLoaded', () => {
    fetchData();
    setupSidebarListeners();
});

async function fetchData() {
    const refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) refreshBtn.innerText = 'Refreshing...';
    
    try {
        // We use the same 'test_run' endpoint for demonstration
        const response = await fetch('/api/runs/test_run/summary');
        if (!response.ok) {
            throw new Error('Run not found or API error');
        }
        
        dashboardData = await response.json();
        renderDashboard(dashboardData);
        showToast("Dashboard data refreshed successfully.", "success");
    } catch (error) {
        console.error("Error fetching data:", error);
        document.getElementById('run-id-display').innerText = "Connection Error";
        document.getElementById('vuln-table-body').innerHTML = `
            <tr><td colspan="5" style="text-align: center; color: var(--status-critical)">Failed to load data. API might be unreachable.</td></tr>
        `;
        showToast("Failed to fetch dashboard data.", "error");
    } finally {
        if (refreshBtn) refreshBtn.innerText = 'Refresh';
    }
}

function renderDashboard(data) {
    // Top Header
    document.getElementById('run-id-display').innerText = data.run_id || "Unknown Run";

    // Metrics
    animateValue('val-processed', 0, data.total_bugs_processed || 0, 1000);
    animateValue('val-resolved', 0, data.total_bugs_resolved || 0, 1000);
    
    const timeVal = data.average_time_per_verified_patch_s ? data.average_time_per_verified_patch_s.toFixed(1) + 's' : '-';
    document.getElementById('val-time').innerText = timeVal;
    
    document.getElementById('val-tokens').innerText = (data.total_tokens_used || 0).toLocaleString();

    // Vulnerabilities Table
    const tbody = document.getElementById('vuln-table-body');
    tbody.innerHTML = '';
    
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        data.vulnerabilities.forEach(vuln => {
            const tr = document.createElement('tr');
            
            // Severity Badge
            let sevClass = "badge-medium";
            const sev = (vuln.severity || "").toUpperCase();
            if (sev === "CRITICAL") sevClass = "badge-critical";
            if (sev === "HIGH") sevClass = "badge-high";
            
            // Status Class
            let statusClass = "text-muted";
            if (vuln.status === "Resolved") statusClass = "text-accent";
            else if (vuln.status.includes("Failed")) statusClass = "negative";

            tr.innerHTML = `
                <td style="font-family: var(--font-mono)">${vuln.id}</td>
                <td>${vuln.type}</td>
                <td style="font-family: var(--font-mono); color: var(--text-muted)">${vuln.location}</td>
                <td><span class="badge ${sevClass}">${vuln.severity}</span></td>
                <td class="${statusClass}">${vuln.status} <span style="font-size:0.75rem; color:var(--text-muted)">(${vuln.agent})</span></td>
            `;
            tbody.appendChild(tr);
        });
    } else {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted)">No vulnerabilities found in this run.</td></tr>`;
    }

    // Terminal Output
    const terminal = document.getElementById('terminal-output');
    terminal.innerHTML = '';
    
    if (data.agent_trace && data.agent_trace.length > 0) {
        let delay = 0;
        data.agent_trace.forEach((line) => {
            setTimeout(() => {
                const lineDiv = document.createElement('div');
                lineDiv.className = 'log-line';
                
                // Extremely simple parsing to colorize timestamp
                const match = line.match(/^(\[\d{2}:\d{2}:\d{2}\])\s*(.*)$/);
                if (match) {
                    let content = match[2];
                    // Highlight specific keywords
                    content = content.replace(/(VULN-\d+)/g, '<span class="log-highlight">$1</span>');
                    content = content.replace(/(failed|timeout)/gi, '<span style="color: var(--status-critical)">$1</span>');
                    content = content.replace(/(verified|resolved)/gi, '<span style="color: var(--status-low)">$1</span>');

                    lineDiv.innerHTML = `<span class="log-time">${match[1]}</span><span class="log-content">${content}</span>`;
                } else {
                    lineDiv.innerText = line;
                }
                
                terminal.appendChild(lineDiv);
                terminal.scrollTop = terminal.scrollHeight;
            }, delay);
            delay += 250; // Typewriter effect delay
        });
    } else {
        terminal.innerHTML = '<div class="log-line text-muted">No trace data available.</div>';
    }
}

// Helper for counting up numbers smoothly
function animateValue(id, start, end, duration) {
    if (start === end) return;
    let range = end - start;
    let current = start;
    let increment = end > start ? 1 : -1;
    // Calculate optimal step time
    let stepTime = Math.abs(Math.floor(duration / range));
    if (stepTime < 10) stepTime = 10;
    
    let obj = document.getElementById(id);
    let timer = setInterval(function() {
        current += increment;
        obj.innerHTML = current;
        if (current == end) {
            clearInterval(timer);
        }
    }, stepTime);
}

function toggleTheme() {
    const root = document.documentElement;
    const btn = document.getElementById('theme-toggle');
    if (root.getAttribute('data-theme') === 'light') {
        root.removeAttribute('data-theme');
        btn.innerText = '☀️ Light Mode';
    } else {
        root.setAttribute('data-theme', 'light');
        btn.innerText = '🌙 Dark Mode';
    }
}

function toggleDropdown() {
    document.getElementById("export-menu").classList.toggle("show");
}

// Close the dropdown if the user clicks outside of it
window.onclick = function(event) {
    if (!event.target.matches('.dropdown-toggle')) {
        var dropdowns = document.getElementsByClassName("dropdown-menu");
        for (var i = 0; i < dropdowns.length; i++) {
            var openDropdown = dropdowns[i];
            if (openDropdown.classList.contains('show')) {
                openDropdown.classList.remove('show');
            }
        }
    }
}

// Export the data as a downloadable file
function exportReport(format = 'json') {
    if (!dashboardData) {
        showToast("No data available to export.", "error");
        return;
    }
    
    if (format === 'json') {
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(dashboardData, null, 2));
        const dlAnchorElem = document.createElement('a');
        dlAnchorElem.setAttribute("href", dataStr);
        dlAnchorElem.setAttribute("download", `ai-kavach-report-${dashboardData.run_id || "unknown"}.json`);
        dlAnchorElem.click();
        showToast("JSON report exported successfully.", "success");
    } else if (format === 'csv') {
        let csvContent = "data:text/csv;charset=utf-8,ID,Type,Location,Severity,Status\n";
        if (dashboardData.vulnerabilities) {
            dashboardData.vulnerabilities.forEach(v => {
                csvContent += `${v.id},${v.type},${v.location},${v.severity},${v.status}\n`;
            });
        }
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", `ai-kavach-report-${dashboardData.run_id || "unknown"}.csv`);
        link.click();
        showToast("CSV report exported successfully.", "success");
    } else if (format === 'pdf') {
        showToast("PDF Export is coming soon!", "neutral");
    }
}

// SPA Navigation
function setupSidebarListeners() {
    const links = document.querySelectorAll('.nav-link');
    const views = document.querySelectorAll('.view-container');

    links.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            // Remove active class from all links
            links.forEach(l => l.classList.remove('active'));
            // Add to clicked link
            e.currentTarget.classList.add('active');
            
            // Hide all views
            views.forEach(v => v.classList.remove('active'));
            
            // Show target view
            const targetId = e.currentTarget.getAttribute('data-target');
            if (targetId) {
                document.getElementById(targetId).classList.add('active');
            }
        });
    });
}

// Simple Toast Notification System
function showToast(message, type = "neutral") {
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerText = message;
    
    container.appendChild(toast);
    
    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 10);
    
    // Remove after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
