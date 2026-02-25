package htmlreport

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nox Security Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f1117;color:#c9d1d9;line-height:1.6}
.container{max-width:1200px;margin:0 auto;padding:24px}
header{display:flex;justify-content:space-between;align-items:center;padding:16px 0;border-bottom:1px solid #30363d;margin-bottom:24px}
header h1{font-size:24px;font-weight:600;color:#f0f6fc}
header .meta{font-size:13px;color:#8b949e;text-align:right}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;margin-bottom:32px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;text-align:center}
.card .count{font-size:36px;font-weight:700;line-height:1}
.card .label{font-size:13px;color:#8b949e;margin-top:4px}
.card.critical .count{color:#f85149}
.card.high .count{color:#f0883e}
.card.medium .count{color:#d29922}
.card.low .count{color:#3fb950}
.card.info .count{color:#58a6ff}
.card.total .count{color:#f0f6fc}
.chart-section{display:flex;gap:32px;margin-bottom:32px;align-items:center;justify-content:center}
.bar-chart{display:flex;height:32px;border-radius:6px;overflow:hidden;flex:1;max-width:600px;background:#21262d}
.bar-chart .seg{height:100%;transition:width .3s}
.bar-chart .seg.critical{background:#f85149}
.bar-chart .seg.high{background:#f0883e}
.bar-chart .seg.medium{background:#d29922}
.bar-chart .seg.low{background:#3fb950}
.bar-chart .seg.info{background:#58a6ff}
.legend{display:flex;gap:16px;flex-wrap:wrap}
.legend-item{display:flex;align-items:center;gap:6px;font-size:13px;color:#8b949e}
.legend-dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.legend-dot.critical{background:#f85149}
.legend-dot.high{background:#f0883e}
.legend-dot.medium{background:#d29922}
.legend-dot.low{background:#3fb950}
.legend-dot.info{background:#58a6ff}
h2{font-size:18px;font-weight:600;color:#f0f6fc;margin-bottom:16px}
.controls{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.controls input,.controls select{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:8px 12px;color:#c9d1d9;font-size:14px}
.controls input{flex:1;min-width:200px}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}
th{background:#21262d;padding:10px 12px;text-align:left;font-size:13px;font-weight:600;color:#8b949e;cursor:pointer;user-select:none;border-bottom:1px solid #30363d}
th:hover{color:#f0f6fc}
td{padding:10px 12px;border-bottom:1px solid #21262d;font-size:14px}
tr:hover td{background:#1c2128}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:12px;font-weight:600;text-transform:uppercase}
.badge.critical{background:rgba(248,81,73,.15);color:#f85149}
.badge.high{background:rgba(240,136,62,.15);color:#f0883e}
.badge.medium{background:rgba(210,153,34,.15);color:#d29922}
.badge.low{background:rgba(63,185,80,.15);color:#3fb950}
.badge.info{background:rgba(88,166,255,.15);color:#58a6ff}
.file-path{color:#58a6ff;font-family:monospace;font-size:13px}
.msg{max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.no-findings{text-align:center;padding:48px;color:#8b949e;font-size:16px}
footer{text-align:center;padding:24px 0;color:#484f58;font-size:12px;border-top:1px solid #30363d;margin-top:32px}
</style>
</head>
<body>
<div class="container">
<header>
<h1>Nox Security Report</h1>
<div class="meta">
<div>nox {{.ToolVersion}}</div>
<div>{{.GeneratedAt}}</div>
</div>
</header>

<div class="summary">
<div class="card total"><div class="count">{{.Counts.Total}}</div><div class="label">Total</div></div>
<div class="card critical"><div class="count">{{.Counts.Critical}}</div><div class="label">Critical</div></div>
<div class="card high"><div class="count">{{.Counts.High}}</div><div class="label">High</div></div>
<div class="card medium"><div class="count">{{.Counts.Medium}}</div><div class="label">Medium</div></div>
<div class="card low"><div class="count">{{.Counts.Low}}</div><div class="label">Low</div></div>
<div class="card info"><div class="count">{{.Counts.Info}}</div><div class="label">Info</div></div>
</div>

{{if gt .Counts.Total 0}}
<div class="chart-section">
<div class="bar-chart">
{{if gt .Counts.Critical 0}}<div class="seg critical" style="width:{{pct .SevPercents.Critical}}%"></div>{{end}}
{{if gt .Counts.High 0}}<div class="seg high" style="width:{{pct .SevPercents.High}}%"></div>{{end}}
{{if gt .Counts.Medium 0}}<div class="seg medium" style="width:{{pct .SevPercents.Medium}}%"></div>{{end}}
{{if gt .Counts.Low 0}}<div class="seg low" style="width:{{pct .SevPercents.Low}}%"></div>{{end}}
{{if gt .Counts.Info 0}}<div class="seg info" style="width:{{pct .SevPercents.Info}}%"></div>{{end}}
</div>
<div class="legend">
<div class="legend-item"><span class="legend-dot critical"></span>Critical</div>
<div class="legend-item"><span class="legend-dot high"></span>High</div>
<div class="legend-item"><span class="legend-dot medium"></span>Medium</div>
<div class="legend-item"><span class="legend-dot low"></span>Low</div>
<div class="legend-item"><span class="legend-dot info"></span>Info</div>
</div>
</div>
{{end}}

<h2>Findings</h2>

{{if eq .Counts.Total 0}}
<div class="no-findings">No security findings detected.</div>
{{else}}
<div class="controls">
<input type="text" id="filter" placeholder="Filter by rule, file, or message..." oninput="filterTable()">
<select id="sevFilter" onchange="filterTable()">
<option value="">All Severities</option>
<option value="critical">Critical</option>
<option value="high">High</option>
<option value="medium">Medium</option>
<option value="low">Low</option>
<option value="info">Info</option>
</select>
</div>
<table id="findings">
<thead>
<tr>
<th onclick="sortTable(0)">Rule ID</th>
<th onclick="sortTable(1)">Severity</th>
<th onclick="sortTable(2)">File</th>
<th onclick="sortTable(3)">Line</th>
<th onclick="sortTable(4)">Message</th>
</tr>
</thead>
<tbody>
{{range .Findings}}
<tr data-sev="{{.SevClass}}">
<td><code>{{.RuleID}}</code></td>
<td><span class="badge {{.SevClass}}">{{.Severity}}</span></td>
<td class="file-path">{{.FilePath}}</td>
<td>{{.StartLine}}</td>
<td class="msg" title="{{.Message}}">{{.Message}}</td>
</tr>
{{end}}
</tbody>
</table>
{{end}}

<footer>Generated by nox {{.ToolVersion}} &mdash; language-agnostic security scanner</footer>
</div>

<script>
function filterTable(){
var q=(document.getElementById("filter").value||"").toLowerCase();
var s=document.getElementById("sevFilter").value;
var rows=document.querySelectorAll("#findings tbody tr");
rows.forEach(function(r){
var text=r.textContent.toLowerCase();
var sev=r.getAttribute("data-sev");
var matchText=!q||text.indexOf(q)>=0;
var matchSev=!s||sev===s;
r.style.display=(matchText&&matchSev)?"":"none";
});
}
var sortDir={};
function sortTable(col){
var table=document.getElementById("findings");
var tbody=table.querySelector("tbody");
var rows=Array.from(tbody.querySelectorAll("tr"));
sortDir[col]=!sortDir[col];
var dir=sortDir[col]?1:-1;
rows.sort(function(a,b){
var av=a.children[col].textContent.trim();
var bv=b.children[col].textContent.trim();
if(col===3){return dir*(parseInt(av,10)-parseInt(bv,10));}
if(col===1){return dir*(sevRank(av)-sevRank(bv));}
return dir*av.localeCompare(bv);
});
rows.forEach(function(r){tbody.appendChild(r);});
}
function sevRank(s){
var m={"critical":0,"high":1,"medium":2,"low":3,"info":4};
return m[s.toLowerCase()]||5;
}
</script>
</body>
</html>`
