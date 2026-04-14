"""Self-contained HTML report template for Quin Scanner.

The single placeholder ``{{REPORT_DATA_JSON}}`` is replaced at render time
with the JSON-serialised ``ScanReport.to_dict()`` output.
"""

HTML_TEMPLATE: str = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Quin Scanner Report</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --color-bg:#fafafa;
  --color-surface:#ffffff;
  --color-border:#e5e5e5;
  --color-text:#171717;
  --color-muted:#737373;
  --color-high:#ef4444;
  --color-medium:#f59e0b;
  --color-low:#22c55e;
  --color-accent:#6366f1;
  --font-sans:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  --font-mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,monospace;
  --radius-sm:4px;
  --radius-md:8px;
  --radius-lg:12px;
  --shadow-sm:0 1px 2px 0 rgba(0,0,0,.05);
  --shadow-md:0 4px 6px -1px rgba(0,0,0,.07),0 2px 4px -2px rgba(0,0,0,.05);
  --transition:150ms ease;
}
html{font-size:15px;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
body{font-family:var(--font-sans);background:var(--color-bg);color:var(--color-text);line-height:1.6}
.container{max-width:1120px;margin:0 auto;padding:0 24px}

/* ---------- Header ---------- */
.header{border-bottom:1px solid var(--color-border);background:var(--color-surface);padding:16px 0}
.header-inner{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.header h1{font-size:1.15rem;font-weight:700;letter-spacing:-.02em}
.header-meta{font-size:.8rem;color:var(--color-muted);text-align:right}

/* ---------- Hero Cards ---------- */
.hero{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:28px}
.hero-card{background:var(--color-surface);border:1px solid var(--color-border);border-radius:var(--radius-lg);padding:20px 24px;border-left:4px solid var(--color-border);transition:box-shadow var(--transition)}
.hero-card:hover{box-shadow:var(--shadow-md)}
.hero-card--green{border-left-color:var(--color-low)}
.hero-card--yellow{border-left-color:var(--color-medium)}
.hero-card--red{border-left-color:var(--color-high)}
.hero-card--accent{border-left-color:var(--color-accent)}
.hero-card__title{font-size:1.35rem;font-weight:700;letter-spacing:-.02em;margin-bottom:2px}
.hero-card__sub{font-size:.8rem;color:var(--color-muted);font-weight:500}

/* ---------- Capability Pills ---------- */
.pills{display:flex;flex-wrap:wrap;gap:6px;margin-top:20px}
.pill{display:inline-block;padding:3px 10px;border-radius:9999px;font-size:.75rem;font-weight:500;background:#f3f4f6;color:#374151;border:1px solid #e5e7eb;white-space:nowrap}
.pill--red{background:#fef2f2;color:#991b1b;border-color:#fecaca}
.pill--blue{background:#eff6ff;color:#1e40af;border-color:#bfdbfe}
.pill--indigo{background:#eef2ff;color:#3730a3;border-color:#c7d2fe}
.pill--emerald{background:#ecfdf5;color:#065f46;border-color:#a7f3d0}
.pill--amber{background:#fffbeb;color:#92400e;border-color:#fde68a}
.pill--orange{background:#fff7ed;color:#9a3412;border-color:#fed7aa}
.pill--gray{background:#f9fafb;color:#4b5563;border-color:#e5e7eb}
.risk-signal{display:block;padding:6px 10px;border-radius:var(--radius-sm);font-size:.78rem;font-weight:500;line-height:1.5;background:#fef2f2;color:#991b1b;border:1px solid #fecaca;word-wrap:break-word;overflow-wrap:break-word}

/* ---------- Summary ---------- */
.summary{margin-top:16px;padding:16px 20px;background:var(--color-surface);border:1px solid var(--color-border);border-radius:var(--radius-md);font-size:.9rem;line-height:1.7;color:#404040}
.summary--empty{color:var(--color-muted);font-style:italic}

/* ---------- Tab Bar ---------- */
.tab-bar{display:flex;gap:0;border-bottom:1px solid var(--color-border);margin-top:32px;overflow-x:auto;-webkit-overflow-scrolling:touch}
.tab-btn{padding:10px 18px;font-size:.82rem;font-weight:500;color:var(--color-muted);background:none;border:none;border-bottom:2px solid transparent;cursor:pointer;white-space:nowrap;transition:color var(--transition),border-color var(--transition)}
.tab-btn:hover{color:var(--color-text)}
.tab-btn--active{color:var(--color-accent);border-bottom-color:var(--color-accent);font-weight:600}

/* ---------- Tab Panels ---------- */
.panel{display:none;margin-top:20px;margin-bottom:48px}
.panel--active{display:block}

/* ---------- Tables ---------- */
.tbl-wrap{overflow-x:auto;border:1px solid var(--color-border);border-radius:var(--radius-md);background:var(--color-surface)}
table{width:100%;border-collapse:collapse;font-size:.82rem}
thead{background:#f9fafb}
th{padding:10px 14px;text-align:left;font-weight:600;color:var(--color-muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid var(--color-border);cursor:pointer;user-select:none;white-space:nowrap}
th:hover{color:var(--color-text)}
th .sort-arrow{margin-left:4px;font-size:.65rem;opacity:.5}
th .sort-arrow--active{opacity:1;color:var(--color-accent)}
td{padding:9px 14px;border-bottom:1px solid #f3f4f6;vertical-align:top;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:last-child td{border-bottom:none}
tr:hover td{background:#fafbfc}
.cell-mono{font-family:var(--font-mono);font-size:.78rem}
.confidence-pill{display:inline-block;padding:2px 8px;border-radius:9999px;font-size:.72rem;font-weight:600}
.confidence-pill--high{background:#dcfce7;color:#166534}
.confidence-pill--med{background:#fef9c3;color:#854d0e}
.confidence-pill--low{background:#fee2e2;color:#991b1b}

/* ---------- Pagination ---------- */
.pagination{display:flex;align-items:center;justify-content:space-between;padding:12px 14px;border-top:1px solid var(--color-border);font-size:.8rem;color:var(--color-muted)}
.pagination button{padding:5px 14px;font-size:.78rem;border:1px solid var(--color-border);border-radius:var(--radius-sm);background:var(--color-surface);color:var(--color-text);cursor:pointer;transition:all var(--transition)}
.pagination button:hover:not(:disabled){background:#f3f4f6;border-color:#d4d4d4}
.pagination button:disabled{opacity:.4;cursor:not-allowed}
.pagination-btns{display:flex;gap:6px}

/* ---------- Agent Cards ---------- */
.agent-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(480px,1fr));gap:16px}
.agent-card{background:var(--color-surface);border:1px solid var(--color-border);border-radius:var(--radius-md);padding:20px;transition:box-shadow var(--transition)}
.agent-card:hover{box-shadow:var(--shadow-md)}
.agent-card__header{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.agent-card__name{font-weight:700;font-size:1rem}
.agent-card__goal{font-size:.85rem;color:#525252;margin-bottom:12px;line-height:1.6}
.agent-card__section{margin-bottom:8px}
.agent-card__label{font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--color-muted);margin-bottom:4px}
.agent-card__footer{margin-top:12px;padding-top:10px;border-top:1px solid #f3f4f6;font-size:.75rem;color:var(--color-muted);font-family:var(--font-mono);word-break:break-all;overflow-wrap:break-word}

/* ---------- Section Headers ---------- */
.section-title{font-size:1rem;font-weight:700;margin-bottom:12px;letter-spacing:-.01em}
.section-gap{margin-top:28px}

/* ---------- Infra ---------- */
.infra-details{list-style:disc;padding-left:20px;font-size:.85rem;margin:8px 0;color:#404040}
.infra-details li{margin-bottom:4px}
.infra-files{font-size:.78rem;color:var(--color-muted);font-family:var(--font-mono);margin-top:8px}

/* ---------- Raw JSON ---------- */
.raw-block{background:#f8f9fa;border:1px solid var(--color-border);border-radius:var(--radius-md);padding:20px;overflow-x:auto;max-height:70vh;overflow-y:auto}
.raw-block code{font-family:var(--font-mono);font-size:.78rem;line-height:1.6;white-space:pre;color:#374151}

/* ---------- Empty State ---------- */
.empty{text-align:center;padding:48px 20px;color:var(--color-muted);font-size:.9rem;font-style:italic}

/* ---------- Footer ---------- */
.footer{border-top:1px solid var(--color-border);padding:20px 0;margin-top:48px;text-align:center;font-size:.78rem;color:var(--color-muted)}

/* ---------- Responsive ---------- */
@media(max-width:768px){
  .hero{grid-template-columns:1fr}
  .agent-grid{grid-template-columns:1fr}
  .header-inner{flex-direction:column;align-items:flex-start}
  .header-meta{text-align:left}
  .tab-btn{padding:10px 12px;font-size:.78rem}
  td,th{padding:7px 10px;font-size:.76rem}
}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="container header-inner">
    <h1>Quin Scanner Report</h1>
    <div class="header-meta" id="header-meta"></div>
  </div>
</div>

<div class="container">
  <!-- Hero Cards -->
  <div class="hero" id="hero"></div>

  <!-- Capability Pills -->
  <div class="pills" id="pills"></div>

  <!-- Summary -->
  <div id="summary"></div>

  <!-- Repo-level Risk Signals -->
  <div id="repo-risks"></div>

  <!-- Tab Bar -->
  <div class="tab-bar" id="tab-bar"></div>

  <!-- Tab Panels -->
  <div id="panels"></div>
</div>

<!-- Footer -->
<div class="footer">
  <div class="container" id="footer-text"></div>
</div>

<script>
window.__REPORT_DATA__ = {{REPORT_DATA_JSON}};
</script>
<script>
(function(){
  "use strict";

  var D = window.__REPORT_DATA__ || {};

  /* ---- Helpers ---- */
  function esc(s){
    if(s==null) return "";
    return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }
  function el(tag,attrs,html){
    var e=document.createElement(tag);
    if(attrs) Object.keys(attrs).forEach(function(k){e.setAttribute(k,attrs[k])});
    if(html!=null) e.innerHTML=html;
    return e;
  }
  function $(id){return document.getElementById(id)}
  function truncPath(p,n){
    if(!p) return "";
    var parts=p.replace(/\\\\/g,"/").split("/");
    if(parts.length<=n) return p;
    return "\\u2026/"+parts.slice(-n).join("/");
  }
  function confClass(c){
    if(c>=0.8) return "high";
    if(c>=0.5) return "med";
    return "low";
  }
  function confLabel(c){
    if(c>=0.8) return "High";
    if(c>=0.5) return "Medium";
    return "Low";
  }
  function titleCase(s){
    if(!s) return "";
    return s.replace(/[-_]/g," ").replace(/\\b\\w/g,function(c){return c.toUpperCase()});
  }

  /* ---- Risk helpers ---- */
  function riskSignalText(r){
    if(typeof r==="string") return r;
    if(r&&typeof r==="object") return r.signal||"";
    return "";
  }
  function riskControls(r){
    if(r&&typeof r==="object"&&Array.isArray(r.recommended_controls)) return r.recommended_controls;
    return [];
  }

  /* ---- Risk derivation ---- */
  function deriveRisk(){
    var agents=D.agents||[];
    var repoRisks=D.risk_signals||[];
    var uniqueRisks={};
    repoRisks.forEach(function(r){var t=riskSignalText(r);if(t)uniqueRisks[t]=true});
    agents.forEach(function(a){
      (a.risk_signals||[]).forEach(function(r){var t=riskSignalText(r);if(t)uniqueRisks[t]=true});
    });
    var count=Object.keys(uniqueRisks).length;
    var repoCount=repoRisks.filter(function(r){return riskSignalText(r)}).length;
    var agentCount=count-repoCount;
    if(agents.length>0||repoCount>0){
      if(count>=3) return {level:"High",color:"red",count:count,agents:agents.length,repoCount:repoCount,agentCount:agentCount};
      if(count>=1) return {level:"Medium",color:"yellow",count:count,agents:agents.length,repoCount:repoCount,agentCount:agentCount};
      return {level:"Low",color:"green",count:count,agents:agents.length,repoCount:repoCount,agentCount:agentCount};
    }
    var conf=D.confidence||0;
    if(conf>=0.8) return {level:"High",color:"red",count:0,agents:0,repoCount:0,agentCount:0};
    if(conf>=0.5) return {level:"Medium",color:"yellow",count:0,agents:0,repoCount:0,agentCount:0};
    return {level:"Low",color:"green",count:0,agents:0,repoCount:0,agentCount:0};
  }

  /* ---- Header ---- */
  (function renderHeader(){
    var repoName=(D.repo_path||"").replace(/\\\\/g,"/").split("/").pop()||D.repo_path||"Unknown";
    var ts=D.scan_timestamp||"";
    $("header-meta").innerHTML=esc(repoName)+(ts?" &middot; "+esc(ts):"");
  })();

  /* ---- Hero ---- */
  (function renderHero(){
    var conf=D.confidence||0;
    var isAI=D.is_ai_application;
    var verdictColor=isAI?(conf>=0.7?"green":"yellow"):"gray";
    var verdictBorder=verdictColor==="green"?"hero-card--green":verdictColor==="yellow"?"hero-card--yellow":"";
    var verdictText=isAI?"AI Application":"Not Detected";

    var fw=D.framework||"unknown";
    var fwDisplay=fw==="unknown"?"<span style='color:var(--color-muted)'>No Framework</span>":esc(titleCase(fw));

    var risk=deriveRisk();
    var riskBorder=risk.color==="red"?"hero-card--red":risk.color==="yellow"?"hero-card--yellow":"hero-card--green";
    var riskSub=risk.repoCount+" system-wide, "+risk.agentCount+" agent-specific";

    var html="";
    html+='<div class="hero-card '+verdictBorder+'">';
    html+='<div class="hero-card__title">'+esc(verdictText)+'</div>';
    html+='<div class="hero-card__sub">'+Math.round(conf*100)+'% confidence</div>';
    html+='</div>';

    html+='<div class="hero-card hero-card--accent">';
    html+='<div class="hero-card__title">'+fwDisplay+'</div>';
    html+='<div class="hero-card__sub">Framework</div>';
    html+='</div>';

    html+='<div class="hero-card '+riskBorder+'">';
    html+='<div class="hero-card__title">'+esc(risk.level)+'</div>';
    html+='<div class="hero-card__sub">'+esc(riskSub)+'</div>';
    html+='</div>';

    $("hero").innerHTML=html;
  })();

  /* ---- Pills ---- */
  (function renderPills(){
    var tags=D.capability_tags||[];
    if(!tags.length){$("pills").style.display="none";return}
    var html="";
    tags.forEach(function(t){html+='<span class="pill">'+esc(t)+'</span>'});
    $("pills").innerHTML=html;
  })();

  /* ---- Summary ---- */
  (function renderSummary(){
    var s=D.summary||"";
    if(!s){
      $("summary").innerHTML='<div class="summary summary--empty">No LLM analysis performed.</div>';
    }else{
      $("summary").innerHTML='<div class="summary">'+esc(s)+'</div>';
    }
  })();

  /* ---- Repo-level Risk Signals ---- */
  (function renderRepoRisks(){
    var signals=D.risk_signals||[];
    if(!signals.length){$("repo-risks").style.display="none";return}
    var html='<div style="margin:1.2rem 0"><div style="font-size:.85rem;font-weight:600;margin-bottom:.5rem">System-Wide Risk Signals</div>';
    html+=renderRiskSignals(signals);
    html+='</div>';
    $("repo-risks").innerHTML=html;
  })();

  /* ---- Tabs ---- */
  var TABS=[
    {id:"artifacts",label:"Artifacts"},
    {id:"agents",label:"Agents"},
    {id:"models",label:"Models"},
    {id:"tools",label:"Tools, Skills & MCP"},
    {id:"infra",label:"Infrastructure"},
    {id:"raw",label:"Raw Data"}
  ];
  var activeTab="artifacts";

  function renderTabBar(){
    var bar=$("tab-bar");
    bar.innerHTML="";
    TABS.forEach(function(t){
      var btn=el("button",{"class":"tab-btn"+(t.id===activeTab?" tab-btn--active":""),"data-tab":t.id},esc(t.label));
      btn.addEventListener("click",function(){switchTab(t.id)});
      bar.appendChild(btn);
    });
  }

  function switchTab(id){
    activeTab=id;
    renderTabBar();
    TABS.forEach(function(t){
      var p=$("panel-"+t.id);
      if(p){
        if(t.id===id){p.classList.add("panel--active")}
        else{p.classList.remove("panel--active")}
      }
    });
  }

  function createPanels(){
    var wrap=$("panels");
    wrap.innerHTML="";
    TABS.forEach(function(t){
      var d=el("div",{"class":"panel"+(t.id===activeTab?" panel--active":""),"id":"panel-"+t.id});
      wrap.appendChild(d);
    });
  }

  renderTabBar();
  createPanels();

  /* ==================================================================
     SORTABLE + PAGINATED TABLE ENGINE
     ================================================================== */
  function TableEngine(containerId,columns,rows,pageSize){
    this.container=$(containerId);
    this.columns=columns;       // [{key,label,render?,sortable?}]
    this.allRows=rows||[];
    this.pageSize=pageSize||50;
    this.page=0;
    this.sortCol=null;
    this.sortDir=1;             // 1 asc, -1 desc
    this.render();
  }
  TableEngine.prototype.totalPages=function(){return Math.max(1,Math.ceil(this.allRows.length/this.pageSize))};
  TableEngine.prototype.sortedRows=function(){
    var self=this;
    var rows=this.allRows.slice();
    if(this.sortCol!==null){
      var key=this.columns[this.sortCol].key;
      rows.sort(function(a,b){
        var va=a[key],vb=b[key];
        if(va==null) va="";
        if(vb==null) vb="";
        if(typeof va==="number"&&typeof vb==="number") return (va-vb)*self.sortDir;
        return String(va).localeCompare(String(vb))*self.sortDir;
      });
    }
    return rows;
  };
  TableEngine.prototype.render=function(){
    var self=this;
    if(!this.allRows.length){
      this.container.innerHTML='<div class="empty">No data to display.</div>';
      return;
    }
    var sorted=this.sortedRows();
    var start=this.page*this.pageSize;
    var pageRows=sorted.slice(start,start+this.pageSize);
    var html='<div class="tbl-wrap"><table><thead><tr>';
    this.columns.forEach(function(col,ci){
      var arrow="";
      if(col.sortable!==false){
        var isActive=self.sortCol===ci;
        var dir=isActive?(self.sortDir===1?"\\u25B2":"\\u25BC"):"\\u25B2";
        arrow=' <span class="sort-arrow'+(isActive?" sort-arrow--active":"")+'">'+dir+'</span>';
      }
      html+='<th data-ci="'+ci+'">'+esc(col.label)+arrow+'</th>';
    });
    html+='</tr></thead><tbody>';
    pageRows.forEach(function(row){
      html+='<tr>';
      self.columns.forEach(function(col){
        if(col.render){
          html+='<td>'+col.render(row)+'</td>';
        }else{
          html+='<td title="'+esc(row[col.key])+'">'+esc(row[col.key])+'</td>';
        }
      });
      html+='</tr>';
    });
    html+='</tbody></table>';
    // pagination
    var tp=this.totalPages();
    html+='<div class="pagination">';
    html+='<span>Page '+(this.page+1)+' of '+tp+'</span>';
    html+='<div class="pagination-btns">';
    html+='<button class="pg-prev"'+(this.page<=0?' disabled':'')+'>Prev</button>';
    html+='<button class="pg-next"'+(this.page>=tp-1?' disabled':'')+'>Next</button>';
    html+='</div></div></div>';
    this.container.innerHTML=html;

    // bind sort
    var ths=this.container.querySelectorAll("th[data-ci]");
    ths.forEach(function(th){
      th.addEventListener("click",function(){
        var ci=parseInt(th.getAttribute("data-ci"),10);
        if(self.columns[ci].sortable===false) return;
        if(self.sortCol===ci){self.sortDir*=-1}else{self.sortCol=ci;self.sortDir=1}
        self.page=0;
        self.render();
      });
    });
    // bind pagination
    var prevBtn=this.container.querySelector(".pg-prev");
    var nextBtn=this.container.querySelector(".pg-next");
    if(prevBtn) prevBtn.addEventListener("click",function(){if(self.page>0){self.page--;self.render()}});
    if(nextBtn) nextBtn.addEventListener("click",function(){if(self.page<self.totalPages()-1){self.page++;self.render()}});
  };

  /* ---- Findings Tab ---- */
  (function renderFindings(){
    var panel=$("panel-artifacts");
    var artifacts=D.artifacts||[];
    if(!artifacts.length){panel.innerHTML='<div class="empty">No artifacts detected.</div>';return}

    // Pre-sort by confidence desc
    artifacts=artifacts.slice().sort(function(a,b){return (b.confidence||0)-(a.confidence||0)});

    var columns=[
      {key:"scanner_name",label:"Scanner"},
      {key:"category",label:"Category"},
      {key:"file_path",label:"File",render:function(r){
        return '<span class="cell-mono" title="'+esc(r.file_path)+'">'+esc(truncPath(r.file_path,3))+'</span>';
      }},
      {key:"line_number",label:"Line",render:function(r){
        return r.line_number!=null?'<span class="cell-mono">'+r.line_number+'</span>':'<span style="color:var(--color-muted)">&mdash;</span>';
      }},
      {key:"match_text",label:"Match",render:function(r){
        return '<span class="cell-mono" title="'+esc(r.match_text)+'">'+esc(r.match_text)+'</span>';
      }},
      {key:"capability_tag",label:"Capability",render:function(r){
        return r.capability_tag?'<span class="pill">'+esc(r.capability_tag)+'</span>':'';
      }},
      {key:"confidence",label:"Confidence",render:function(r){
        var c=r.confidence||0;
        var cls=confClass(c);
        return '<span class="confidence-pill confidence-pill--'+cls+'">'+confLabel(c)+" "+Math.round(c*100)+"%</span>";
      }}
    ];
    new TableEngine("panel-artifacts",columns,artifacts,50);
  })();

  /* ---- Risk signal renderer (handles both string and dict formats) ---- */
  function renderRiskSignals(signals){
    if(!signals||!signals.length) return '';
    var html='<div style="margin-top:0">';
    signals.forEach(function(r){
      var text=riskSignalText(r);
      var ctrls=riskControls(r);
      if(!text) return;
      html+='<div style="margin-bottom:.5rem">';
      html+='<div class="risk-signal risk-toggle" style="cursor:'+(ctrls.length?'pointer':'default')+'">';
      html+=esc(text)+(ctrls.length?' <span style="float:right;margin-left:6px;font-size:.7rem;opacity:.6">&#9662;</span>':'');
      html+='</div>';
      if(ctrls.length){
        html+='<div class="risk-controls" style="display:none;margin:.35rem 0 .35rem 10px;font-size:.75rem;color:var(--color-muted)">';
        ctrls.forEach(function(c){html+='<div style="margin-bottom:.2rem">&#8594; '+esc(c)+'</div>'});
        html+='</div>';
      }
      html+='</div>';
    });
    html+='</div>';
    return html;
  }
  document.addEventListener("click",function(e){
    var t=e.target;
    if(t.classList&&t.classList.contains("risk-toggle")){
      var sib=t.nextElementSibling;
      if(sib&&sib.classList.contains("risk-controls")){
        sib.style.display=sib.style.display==="none"?"block":"none";
      }
    }
  });

  /* ---- Agents Tab ---- */
  (function renderAgents(){
    var panel=$("panel-agents");
    var agents=D.agents||[];
    if(!agents.length){panel.innerHTML='<div class="empty">No agents identified.</div>';return}

    var typeBadge=function(t){
      var cls="pill--gray";
      if(t==="supervisor") cls="pill--indigo";
      else if(t==="worker") cls="pill--blue";
      else if(t==="utility") cls="pill--gray";
      return '<span class="pill '+cls+'">'+esc(t||"unknown")+'</span>';
    };
    var pillList=function(arr,cls){
      if(!arr||!arr.length) return '<span style="color:var(--color-muted);font-size:.78rem">None</span>';
      return arr.map(function(s){return '<span class="pill '+(cls||"")+'">'+esc(s)+'</span>'}).join(" ");
    };

    var html='<div class="agent-grid">';
    agents.forEach(function(a){
      html+='<div class="agent-card">';
      html+='<div class="agent-card__header"><span class="agent-card__name">'+esc(a.name||"Unnamed Agent")+'</span>'+typeBadge(a.agent_type)+'</div>';
      if(a.goal) html+='<div class="agent-card__goal">'+esc(a.goal)+'</div>';

      if((a.capabilities||[]).length){
        html+='<div class="agent-card__section"><div class="agent-card__label">Capabilities</div><div class="pills" style="margin-top:0">'+pillList(a.capabilities)+'</div></div>';
      }
      if((a.skills||[]).length){
        html+='<div class="agent-card__section"><div class="agent-card__label">Skills</div><div class="pills" style="margin-top:0">'+pillList(a.skills)+'</div></div>';
      }
      if((a.tools||[]).length){
        html+='<div class="agent-card__section"><div class="agent-card__label">Tools</div><div class="pills" style="margin-top:0">'+pillList(a.tools)+'</div></div>';
      }
      if((a.risk_signals||[]).length){
        html+='<div class="agent-card__section"><div class="agent-card__label">Risk Signals</div>';
        html+=renderRiskSignals(a.risk_signals);
        html+='</div>';
      }
      if(a.source_file){
        html+='<div class="agent-card__footer" title="'+esc(a.source_file)+'">'+esc(truncPath(a.source_file,3))+'</div>';
      }
      html+='</div>';
    });
    html+='</div>';
    panel.innerHTML=html;
  })();

  /* ---- Models Tab ---- */
  (function renderModels(){
    var panel=$("panel-models");
    var models=D.model_usages||[];
    if(!models.length){panel.innerHTML='<div class="empty">No model usages detected.</div>';return}

    var providerCls=function(p){
      if(!p) return "pill--gray";
      var lp=p.toLowerCase();
      if(lp==="openai") return "pill--emerald";
      if(lp==="anthropic") return "pill--orange";
      if(lp==="google") return "pill--blue";
      return "pill--gray";
    };

    var columns=[
      {key:"provider",label:"Provider",render:function(r){
        return '<span class="pill '+providerCls(r.provider)+'">'+esc(r.provider)+'</span>';
      }},
      {key:"model_name",label:"Model",render:function(r){
        return '<span class="cell-mono">'+esc(r.model_name)+'</span>';
      }},
      {key:"role",label:"Role",render:function(r){
        return '<span class="pill">'+esc(r.role||"unknown")+'</span>';
      }},
      {key:"source",label:"Source"},
      {key:"file_path",label:"File",render:function(r){
        return '<span class="cell-mono" title="'+esc(r.file_path)+'">'+esc(truncPath(r.file_path,3))+'</span>';
      }},
      {key:"line_number",label:"Line",render:function(r){
        return r.line_number!=null?'<span class="cell-mono">'+r.line_number+'</span>':'<span style="color:var(--color-muted)">&mdash;</span>';
      }}
    ];
    new TableEngine("panel-models",columns,models,50);
  })();

  /* ---- Tools, Skills & MCP Tab ---- */
  (function renderToolsMcp(){
    var panel=$("panel-tools");
    var allUsages=D.tool_usages||[];
    var mcps=D.mcp_servers||[];

    /* Split tool_usages by type */
    var agentTools=allUsages.filter(function(t){var tt=t.tool_type||"tool_definition";return tt==="tool_definition"||tt==="external_service"});
    var skills=allUsages.filter(function(t){return t.tool_type==="skill"});
    var mcpTools=allUsages.filter(function(t){return t.tool_type==="mcp_tool"});

    var html="";

    /* Agent Tools */
    html+='<div class="section-title">Agent Tools</div>';
    html+='<div id="tools-table-wrap"></div>';

    /* Skills */
    html+='<div class="section-title section-gap">Skills</div>';
    html+='<div id="skills-table-wrap"></div>';

    /* MCP Servers */
    html+='<div class="section-title section-gap">MCP Servers</div>';
    html+='<div id="mcp-table-wrap"></div>';

    panel.innerHTML=html;

    /* Shared column renderers */
    var colToolName={key:"tool_name",label:"Name",render:function(r){return '<span class="cell-mono">'+esc(r.tool_name)+'</span>'}};
    var colFile={key:"source_file",label:"File",render:function(r){return '<span class="cell-mono" title="'+esc(r.source_file)+'">'+esc(truncPath(r.source_file,3))+'</span>'}};
    var colLine={key:"line_number",label:"Line",render:function(r){return r.line_number!=null?'<span class="cell-mono">'+r.line_number+'</span>':'<span style="color:var(--color-muted)">&mdash;</span>'}};

    /* Agent Tools table */
    if(!agentTools.length){
      $("tools-table-wrap").innerHTML='<div class="empty">No agent tools detected.</div>';
    }else{
      new TableEngine("tools-table-wrap",[
        colToolName,
        {key:"tool_type",label:"Type",render:function(r){var t=r.tool_type||"tool_definition";return t==="external_service"?'<span class="pill pill--blue">Service Integration</span>':'<span class="pill pill--indigo">Agent Tool</span>'}},
        {key:"service_category",label:"Category",render:function(r){if(!r.service_category)return'<span style="color:var(--color-muted)">&mdash;</span>';var s=r.service_category.replace(/_/g," ").replace(/\b\w/g,function(c){return c.toUpperCase()});return '<span class="pill pill--emerald">'+esc(s)+'</span>'}},
        colFile,colLine
      ],agentTools,50);
    }

    /* Skills table */
    if(!skills.length){
      $("skills-table-wrap").innerHTML='<div class="empty">No skills detected.</div>';
    }else{
      new TableEngine("skills-table-wrap",[
        colToolName,
        {key:"tool_type",label:"Type",render:function(){return '<span class="pill pill--emerald">Skill</span>'}},
        colFile,colLine
      ],skills,50);
    }

    /* MCP Servers table */
    if(!mcps.length&&!mcpTools.length){
      $("mcp-table-wrap").innerHTML='<div class="empty">No MCP servers detected.</div>';
    }else{
      var mcpRows=mcps.map(function(m){return{tool_name:m.name,tool_type:"mcp_server",source_file:m.source_file,transport:m.transport}});
      mcpTools.forEach(function(t){mcpRows.push({tool_name:t.tool_name,tool_type:"mcp_tool",source_file:t.source_file,transport:""})});
      new TableEngine("mcp-table-wrap",[
        {key:"tool_name",label:"Name",render:function(r){return '<span class="cell-mono">'+esc(r.tool_name)+'</span>'}},
        {key:"tool_type",label:"Type",render:function(r){return r.transport?'<span class="pill pill--amber">MCP Server</span>':'<span class="pill pill--amber">MCP Tool</span>'}},
        {key:"transport",label:"Transport",render:function(r){return r.transport?esc(r.transport):'<span style="color:var(--color-muted)">&mdash;</span>'}},
        {key:"source_file",label:"Source File",render:function(r){return '<span class="cell-mono" title="'+esc(r.source_file)+'">'+esc(truncPath(r.source_file,3))+'</span>'}}
      ],mcpRows,50);
    }
  })();

  /* ---- Infrastructure Tab ---- */
  (function renderInfra(){
    var panel=$("panel-infra");
    var infra=D.infra;
    if(!infra){panel.innerHTML='<div class="empty">No infrastructure configuration detected.</div>';return}

    var html='<div class="section-title">'+esc(titleCase(infra.platform||"Unknown"))+'</div>';
    if(infra.details&&infra.details.length){
      html+='<ul class="infra-details">';
      infra.details.forEach(function(d){html+='<li>'+esc(d)+'</li>'});
      html+='</ul>';
    }
    if(infra.source_files&&infra.source_files.length){
      html+='<div class="infra-files">Source files: '+infra.source_files.map(function(f){return esc(f)}).join(", ")+'</div>';
    }
    panel.innerHTML=html;
  })();

  /* ---- Raw Data Tab ---- */
  (function renderRaw(){
    var panel=$("panel-raw");
    var json;
    try{json=JSON.stringify(D,null,2)}catch(e){json="Error serializing data."}
    panel.innerHTML='<div class="raw-block"><code>'+esc(json)+'</code></div>';
  })();

  /* ---- Footer ---- */
  (function renderFooter(){
    var ts=D.scan_timestamp||"";
    $("footer-text").innerHTML="Generated by Quin Scanner"+(ts?" &middot; "+esc(ts):"");
  })();

})();
</script>
</body>
</html>
"""
