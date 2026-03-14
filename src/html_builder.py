"""
HTML Dashboard Generator
Builds a stunning, standalone, client-ready HTML report using TailwindCSS and Chart.js.
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
    </style>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen p-8">

    <!-- Header -->
    <header class="mb-12 border-b border-gray-800 pb-6 flex justify-between items-end">
        <div>
            <h1 class="text-4xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 mb-2">
                GitHub Leak Scanner
            </h1>
            <p class="text-gray-400 text-sm">Security Audit Report generated on <span class="text-gray-200">{scan_date}</span></p>
            <h2 class="text-xl font-semibold mt-4 text-gray-300">Target: <a href="{repo_url}" target="_blank" class="text-blue-400 hover:underline">{repo_url}</a></h2>
        </div>
        <div class="text-right">
            <div class="text-5xl font-black {"text-red-500" if high_count > 0 else "text-green-500"}">{total_count}</div>
            <div class="text-gray-500 text-sm uppercase tracking-wide font-bold mt-1">Total Leaks Detected</div>
        </div>
    </header>

    <!-- Main Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
        
        <!-- KPIs -->
        <div class="flex flex-col gap-4">
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700 shadow-lg flex items-center justify-between">
                <div>
                    <h3 class="text-gray-400 font-semibold mb-1 uppercase tracking-wider text-xs">High Severity</h3>
                    <p class="text-3xl font-bold text-red-500">{high_count}</p>
                </div>
                <div class="p-3 bg-red-500/10 rounded-full">
                    <svg class="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                </div>
            </div>
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700 shadow-lg flex items-center justify-between">
                <div>
                    <h3 class="text-gray-400 font-semibold mb-1 uppercase tracking-wider text-xs">Medium Severity</h3>
                    <p class="text-3xl font-bold text-yellow-500">{medium_count}</p>
                </div>
                <div class="p-3 bg-yellow-500/10 rounded-full">
                    <svg class="w-8 h-8 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                </div>
            </div>
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700 shadow-lg flex items-center justify-between">
                <div>
                    <h3 class="text-gray-400 font-semibold mb-1 uppercase tracking-wider text-xs">Low Severity</h3>
                    <p class="text-3xl font-bold text-blue-400">{low_count}</p>
                </div>
                <div class="p-3 bg-blue-400/10 rounded-full">
                    <svg class="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                </div>
            </div>
        </div>

        <!-- Chart -->
        <div class="col-span-1 lg:col-span-2 bg-gray-800 rounded-xl p-6 border border-gray-700 shadow-lg flex flex-col justify-center items-center">
            <div class="w-full max-w-md h-64">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Findings Table -->
    <div class="bg-gray-800 rounded-xl border border-gray-700 shadow-lg overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-700 flex justify-between items-center bg-gray-800/50">
            <h2 class="text-lg font-bold">Detected Secrets</h2>
            <div class="text-sm text-gray-400">Total: {total_count}</div>
        </div>
        <div class="overflow-x-auto scroll-hidden">
            <table class="w-full text-left border-collapse">
                <thead>
                    <tr class="bg-gray-900/50 text-gray-400 uppercase text-xs tracking-wider border-b border-gray-700">
                        <th class="px-6 py-4 font-semibold">Severity</th>
                        <th class="px-6 py-4 font-semibold">Pattern</th>
                        <th class="px-6 py-4 font-semibold">File : Line</th>
                        <th class="px-6 py-4 font-semibold">Exposed Content</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-700/50" id="findingsTable">
                    <!-- Javascript populates this -->
                </tbody>
            </table>
        </div>
        {"<div class='p-8 text-center text-gray-500'>No secrets found. Clean repository! 🎉</div>" if total_count == 0 else ""}
    </div>

    <script>
        const findings = {findings_json};
        
        // Populate Table
        const tbody = document.getElementById('findingsTable');
        findings.forEach(f => {{
            const tr = document.createElement('tr');
            tr.className = "hover:bg-gray-750 transition-colors group";
            
            // Severity Color Mapping
            let sevClass = "";
            let sevBg = "";
            if (f.severity === "HIGH") {{ sevClass = "text-red-400"; sevBg = "bg-red-400/10 border-red-400/20"; }}
            else if (f.severity === "MEDIUM") {{ sevClass = "text-yellow-400"; sevBg = "bg-yellow-400/10 border-yellow-400/20"; }}
            else {{ sevClass = "text-blue-400"; sevBg = "bg-blue-400/10 border-blue-400/20"; }}
            
            tr.innerHTML = `
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="px-2.5 py-1 rounded text-xs font-bold border ${{sevBg}} ${{sevClass}}">
                        ${{f.severity}}
                    </span>
                </td>
                <td class="px-6 py-4 text-sm font-medium text-gray-300 whitespace-nowrap">${{f.pattern}}</td>
                <td class="px-6 py-4 text-sm text-gray-400 code-font whitespace-nowrap">
                    <span class="text-blue-300">${{f.file}}</span> <span class="text-gray-500">:${{f.line}}</span>
                </td>
                <td class="px-6 py-4 text-sm code-font text-red-300 break-all max-w-xl">
                    <div class="px-3 py-1.5 bg-gray-900/50 rounded border border-gray-700 group-hover:border-gray-600 transition-colors">
                        ${{f.content}}
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        }});

        // Render Chart
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{high_count}, {medium_count}, {low_count}],
                    backgroundColor: [
                        'rgba(248, 113, 113, 0.8)', // red-400
                        'rgba(250, 204, 21, 0.8)',  // yellow-400
                        'rgba(96, 165, 250, 0.8)'   // blue-400
                    ],
                    borderColor: [
                        'rgba(248, 113, 113, 1)',
                        'rgba(250, 204, 21, 1)',
                        'rgba(96, 165, 250, 1)'
                    ],
                    borderWidth: 1,
                    hoverOffset: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {{
                    legend: {{ position: 'bottom', labels: {{ color: '#9ca3af', padding: 20, font: {{ family: 'Inter' }} }} }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
    return html
