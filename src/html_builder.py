"""
HTML Dashboard Generator
Builds a stunning, standalone, client-ready HTML report using TailwindCSS, Chart.js, and Vanilla JS for interactions.
"""

import json
from datetime import datetime
from typing import List
from models import Finding

def build_html_report(repo_url: str, findings: List[Finding]) -> str:
    """Generate a complete HTML string for the security dashboard."""
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Calculate KPIs
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")
    total_count = len(findings)
    
    # Serialize findings for JS
    findings_dicts = [f.model_dump() for f in findings]
    findings_json = json.dumps(findings_dicts)
    
    html = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {repo_url}</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
      tailwind.config = {{
        darkMode: 'class',
        theme: {{
          extend: {{
            colors: {{
              gray: {{
                850: '#1f2937',
                900: '#111827',
              }}
            }}
          }}
        }}
      }}
    </script>
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=Fira+Code&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Inter', sans-serif; }}
        .code-font {{ font-family: 'Fira Code', monospace; }}
        .scroll-hidden::-webkit-scrollbar {{ display: none; }}
        
        .kpi-card {{ transition: transform 0.2s, box-shadow 0.2s; cursor: pointer; }}
        .kpi-card:hover {{ transform: translateY(-4px); box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); }}
        .kpi-active {{ ring: 2px; }}
        
        .accordion-content {{ transition: max-height 0.3s ease-in-out; overflow: hidden; max-height: 0; }}
        .accordion-content.open {{ max-height: 5000px; }} /* Arbitrary large max-height for CSS transition */
        
        .chevron {{ transition: transform 0.3s ease; }}
        .chevron.open {{ transform: rotate(180deg); }}
    </style>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen p-8">

    <!-- Header -->
    <header class="mb-10 border-b border-gray-800 pb-6 flex justify-between items-end">
        <div>
            <h1 class="text-4xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-orange-500 mb-2">
                GitHub Leak Scanner
            </h1>
            <p class="text-gray-400 text-sm">Security Audit Report generated on <span class="text-gray-200">{scan_date}</span></p>
            <h2 class="text-xl font-semibold mt-4 text-gray-300">Target: <a href="{repo_url}" target="_blank" class="text-blue-400 hover:underline">{repo_url}</a></h2>
        </div>
        <div class="text-right">
            <div class="text-6xl font-black {"text-red-500" if high_count > 0 else "text-green-500"} cursor-pointer" onclick="setSeverityFilter('ALL')" id="totalKpi">
                {total_count}
            </div>
            <div class="text-gray-500 text-sm uppercase tracking-wide font-bold mt-1 cursor-pointer hover:text-gray-300" onclick="setSeverityFilter('ALL')">Total Leaks Detected (Reset Filter)</div>
        </div>
    </header>

    <!-- Main Grid: Visual Hierarchy Emphasized -->
    <div class="grid grid-cols-1 lg:grid-cols-4 gap-8 mb-12">
        
        <!-- KPIs (Dominant Cards) -->
        <div class="col-span-1 lg:col-span-3 grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="kpi-card bg-gray-800 rounded-xl p-8 border border-red-500/30 shadow-[0_0_20px_rgba(239,68,68,0.1)] flex flex-col justify-between" id="kpi-HIGH" onclick="setSeverityFilter('HIGH')">
                <div class="flex justify-between items-start mb-4">
                    <h3 class="text-red-400 font-bold uppercase tracking-widest text-sm">High Severity</h3>
                    <div class="p-3 bg-red-500/20 rounded-full">
                        <svg class="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                    </div>
                </div>
                <p class="text-6xl font-black text-white">{high_count}</p>
                <p class="text-red-400/80 text-sm mt-3">Critical credentials / API Keys</p>
            </div>
            
            <div class="kpi-card bg-gray-800 rounded-xl p-8 border border-yellow-500/30 flex flex-col justify-between" id="kpi-MEDIUM" onclick="setSeverityFilter('MEDIUM')">
                <div class="flex justify-between items-start mb-4">
                    <h3 class="text-yellow-400 font-bold uppercase tracking-widest text-sm">Medium Severity</h3>
                    <div class="p-3 bg-yellow-500/20 rounded-full">
                        <svg class="w-8 h-8 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    </div>
                </div>
                <p class="text-6xl font-black text-white">{medium_count}</p>
                <p class="text-yellow-400/80 text-sm mt-3">Generic tokens / High Entropy</p>
            </div>
            
            <div class="kpi-card bg-gray-800 rounded-xl p-8 border border-blue-400/30 flex flex-col justify-between" id="kpi-LOW" onclick="setSeverityFilter('LOW')">
                <div class="flex justify-between items-start mb-4">
                    <h3 class="text-blue-400 font-bold uppercase tracking-widest text-sm">Low Severity</h3>
                    <div class="p-3 bg-blue-400/20 rounded-full">
                        <svg class="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    </div>
                </div>
                <p class="text-6xl font-black text-white">{low_count}</p>
                <p class="text-blue-400/80 text-sm mt-3">Suspicious filenames / Configs</p>
            </div>
        </div>

        <!-- Chart (Responsive) -->
        <div class="col-span-1 bg-gray-800 rounded-xl p-6 border border-gray-700 shadow-lg flex flex-col justify-center items-center">
            <div class="w-full h-48 relative">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Findings Control Bar -->
    <div class="flex justify-between items-center mb-4">
        <h2 class="text-2xl font-bold flex items-center gap-3">
            <svg class="w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
            File Overview
        </h2>
        <div id="filterStatus" class="text-sm font-semibold px-4 py-2 bg-gray-800 rounded-lg border border-gray-700">Showing: ALL</div>
    </div>

    <!-- Grouped Table Container -->
    <div class="bg-gray-800 rounded-xl border border-gray-700 shadow-xl overflow-hidden mb-12" id="findingsContainer">
        <!-- Rendered by JS -->
    </div>

    <script>
        const rawFindings = {findings_json};
        let currentFilter = 'ALL';
        
        // Severity UI Mapping
        const sevMap = {{
            'HIGH': {{ class: 'text-red-400', bg: 'bg-red-400/10 border-red-400/20' }},
            'MEDIUM': {{ class: 'text-yellow-400', bg: 'bg-yellow-400/10 border-yellow-400/20' }},
            'LOW': {{ class: 'text-blue-400', bg: 'bg-blue-400/10 border-blue-400/20' }}
        }};

        function setSeverityFilter(sev) {{
            currentFilter = sev;
            document.getElementById('filterStatus').innerHTML = `Showing: <span class="${{sev !== 'ALL' ? sevMap[sev].class : 'text-gray-300'}}">${{sev}}</span>`;
            
            // Visual feedback on cards
            ['HIGH', 'MEDIUM', 'LOW'].forEach(s => {{
                const el = document.getElementById(`kpi-${{s}}`);
                if(el) {{
                    if(currentFilter === 'ALL' || currentFilter === s) {{
                        el.style.opacity = '1';
                        if(currentFilter === s) {{
                            el.classList.add('ring-2', 'ring-white');
                        }} else {{
                            el.classList.remove('ring-2', 'ring-white');
                        }}
                    }} else {{
                        el.style.opacity = '0.4';
                        el.classList.remove('ring-2', 'ring-white');
                    }}
                }}
            }});
            
            renderFindings();
        }}
        
        function toggleAccordion(fileId) {{
            const content = document.getElementById(`content-${{fileId}}`);
            const chevron = document.getElementById(`chevron-${{fileId}}`);
            if (content.classList.contains('open')) {{
                content.classList.remove('open');
                chevron.classList.remove('open');
            }} else {{
                content.classList.add('open');
                chevron.classList.add('open');
            }}
        }}

        function renderFindings() {{
            const container = document.getElementById('findingsContainer');
            container.innerHTML = '';
            
            // 1. Filter
            const filtered = currentFilter === 'ALL' ? rawFindings : rawFindings.filter(f => f.severity === currentFilter);
            
            if (filtered.length === 0) {{
                container.innerHTML = `<div class='p-12 text-center text-gray-500 text-lg'>No secrets match the current filter. 🎉</div>`;
                return;
            }}
            
            // 2. Group by file
            const groups = {{}};
            filtered.forEach(f => {{
                if (!groups[f.file]) groups[f.file] = {{ findings: [], high: 0, med: 0, low: 0 }};
                groups[f.file].findings.push(f);
                if (f.severity === 'HIGH') groups[f.file].high++;
                else if (f.severity === 'MEDIUM') groups[f.file].med++;
                else groups[f.file].low++;
            }});
            
            // 3. Sort groups (Files with High severity first, then count)
            const sortedFiles = Object.keys(groups).sort((a, b) => {{
                const gA = groups[a]; const gB = groups[b];
                if (gA.high !== gB.high) return gB.high - gA.high;
                if (gA.med !== gB.med) return gB.med - gA.med;
                return gB.findings.length - gA.findings.length;
            }});
            
            // 4. Render 
            sortedFiles.forEach((file, index) => {{
                const g = groups[file];
                const fileId = `file_${{index}}`;
                
                // Badges for group header
                let badgeHtml = '';
                if(g.high > 0) badgeHtml += `<span class="ml-2 px-2.5 py-0.5 rounded-full bg-red-500/20 text-red-400 text-xs font-bold">${{g.high}} HIGH</span>`;
                if(g.med > 0) badgeHtml += `<span class="ml-2 px-2.5 py-0.5 rounded-full bg-yellow-500/20 text-yellow-400 text-xs font-bold">${{g.med}} MED</span>`;
                if(g.low > 0) badgeHtml += `<span class="ml-2 px-2.5 py-0.5 rounded-full bg-blue-500/20 text-blue-400 text-xs font-bold">${{g.low}} LOW</span>`;
                
                // Group Header
                const header = document.createElement('div');
                header.className = "bg-gray-800 border-b border-gray-700/50 p-4 hover:bg-gray-750 transition-colors cursor-pointer flex justify-between items-center group sticky top-0 z-10";
                header.onclick = () => toggleAccordion(fileId);
                header.innerHTML = `
                    <div class="flex items-center gap-3 overflow-hidden">
                        <svg id="chevron-${{fileId}}" class="w-5 h-5 text-gray-500 chevron ${{'open'}}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                        </svg>
                        <span class="font-bold text-gray-200 code-font truncate" title="${{file}}">${{file}}</span>
                        <div class="hidden md:flex">${{badgeHtml}}</div>
                    </div>
                    <div class="text-sm font-semibold text-gray-400 bg-gray-900 px-3 py-1 rounded border border-gray-700 whitespace-nowrap">
                        ${{g.findings.length}} Finding(s)
                    </div>
                `;
                container.appendChild(header);
                
                // Group Content Details Table
                const content = document.createElement('div');
                content.id = `content-${{fileId}}`;
                content.className = "accordion-content bg-gray-900/40 " + "open";
                
                let rowsHtml = '';
                g.findings.forEach(f => {{
                    const sUi = sevMap[f.severity];
                    rowsHtml += `
                        <tr class="hover:bg-gray-750/50 transition-colors border-b border-gray-800 last:border-0">
                            <td class="px-6 py-4 whitespace-nowrap w-32">
                                <span class="px-2.5 py-1 rounded text-[10px] font-bold border ${{sUi.bg}} ${{sUi.class}} tracking-wider uppercase">
                                    ${{f.severity}}
                                </span>
                            </td>
                            <td class="px-6 py-4 text-sm font-semibold text-gray-300 w-1/4">${{f.pattern}}</td>
                            <td class="px-6 py-4 text-sm text-gray-500 code-font w-24 border-r border-gray-800 border-l">L: ${{f.line}}</td>
                            <td class="px-6 py-4 text-sm code-font text-red-300 break-all">
                                <span class="pr-2 opacity-50 select-none">$$</span>${{f.content.replace(/</g, "&lt;").replace(/>/g, "&gt;")}}
                            </td>
                        </tr>
                    `;
                }});
                
                content.innerHTML = `
                    <div class="overflow-x-auto">
                        <table class="w-full text-left border-collapse">
                            <tbody>${{rowsHtml}}</tbody>
                        </table>
                    </div>
                `;
                container.appendChild(content);
            }});
        }}

        // Render Initial Data
        renderFindings();

        // Render Chart
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{high_count}, {medium_count}, {low_count}],
                    backgroundColor: [
                        'rgba(239, 68, 68, 0.9)', // red-500
                        'rgba(234, 179, 8, 0.9)',  // yellow-500
                        'rgba(96, 165, 250, 0.9)'   // blue-400
                    ],
                    borderColor: [
                        'rgba(239, 68, 68, 1)',
                        'rgba(234, 179, 8, 1)',
                        'rgba(96, 165, 250, 1)'
                    ],
                    borderWidth: 0,
                    hoverOffset: 10
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                cutout: '75%',
                layout: {{ padding: 10 }},
                plugins: {{
                    legend: {{ position: 'bottom', labels: {{ color: '#9ca3af', padding: 15, font: {{ family: 'Inter', size: 10 }} }}, display: false }},
                    tooltip: {{ backgroundColor: 'rgba(17, 24, 39, 0.9)', titleFont: {{ family: 'Inter' }}, bodyFont: {{ family: 'Inter' }}, padding: 12 }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
    return html
