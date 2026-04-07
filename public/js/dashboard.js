/* ─────────────────────────────────────────────
   dashboard.js — pandaBase Security Dashboard
   All interactive features
   ───────────────────────────────────────────── */

// ═══════════════════════════════════════════
//  INIT DATA
// ═══════════════════════════════════════════
const ALL_EVENTS  = generateAuditLogs(350);
const ANOMALIES   = ALL_EVENTS.filter(e => e.isAnomaly);
const SESSIONS    = groupIntoSessions(ALL_EVENTS);
const RISK_SCORES = computeRiskScores(ALL_EVENTS);
const REPORT      = generateReport(ALL_EVENTS);

// ═══════════════════════════════════════════
//  NAV / VIEW SWITCHING
// ═══════════════════════════════════════════
const titles = {
  overview:'📊 Overview', anomalies:'🔍 Anomalies', chat:'🧠 Ask pandaBase',
  timeline:'🕵️ Timeline Playback', graph:'🌐 Graph View', risk:'🎯 Risk Scores',
  sessions:'🧩 Session Log', simulation:'🚨 Attack Simulation',
  realtime:'⚡ Real-time Feed', report:'🧪 Audit Report', definitions:'📖 Definitions',
};

document.querySelectorAll('#nav button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#nav button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const view = btn.dataset.view;
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById('view-' + view).classList.add('active');
    document.getElementById('page-title').textContent = titles[view] || view;
    if (view === 'graph') setTimeout(() => {
      populateGraphFilter();
      drawGraph();
    }, 50);
    if (view === 'realtime') startRealtime();
  });
});

// Clock
setInterval(() => {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}, 1000);

// ═══════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════
function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString('en-US', { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', second:'2-digit' });
}
function shortTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString('en-US', { hour:'2-digit', minute:'2-digit', second:'2-digit' });
}
function riskColor(r) {
  if (r >= 70) return 'var(--danger)';
  if (r >= 40) return 'var(--warn)';
  if (r >= 20) return 'var(--accent2)';
  return 'var(--accent)';
}
function riskClass(r) {
  if (r >= 70) return 'critical';
  if (r >= 40) return 'high';
  if (r >= 20) return 'medium';
  return 'low';
}
function actionColor(a){
  if(['DROP','TRUNCATE'].includes(a)) return 'var(--danger)';
  if(['GRANT','REVOKE'].includes(a)) return 'var(--warn)';
  if(a==='DELETE') return '#fb923c';
  return 'var(--text)';
}

// ═══════════════════════════════════════════
//  1. OVERVIEW
// ═══════════════════════════════════════════
(function renderOverview() {
  const cards = document.getElementById('stat-cards');
  const avgRisk = Math.round(ALL_EVENTS.reduce((s,e)=>s+e.riskScore,0)/ALL_EVENTS.length);
  const stats = [
    { label:'Total Events', value: ALL_EVENTS.length, cls:'blue' },
    { label:'Anomalies Detected', value: ANOMALIES.length, cls:'red' },
    { label:'Avg Risk Score', value: avgRisk, cls: avgRisk>30?'yellow':'green' },
    { label:'Active Users', value: [...new Set(ALL_EVENTS.map(e=>e.user))].length, cls:'green' },
  ];
  cards.innerHTML = stats.map(s => `
    <div class="card">
      <div class="card-title">${s.label}</div>
      <div class="card-value ${s.cls}">${s.value}</div>
    </div>`).join('');

  const tbody = document.querySelector('#overview-table tbody');
  const recent = [...ALL_EVENTS].reverse().slice(0, 60);
  tbody.innerHTML = recent.map(e => `<tr>
    <td>${fmtTime(e.timestamp)}</td>
    <td>${e.userName}</td>
    <td><span style="color:${actionColor(e.action)}">${e.action}</span></td>
    <td>${e.table} <span class="badge badge-${riskClass(
      e.sensitivity==='critical'?70:e.sensitivity==='high'?40:e.sensitivity==='medium'?20:0
    )}">${e.sensitivity}</span></td>
    <td><span class="risk-bar"><span class="risk-bar-fill" style="width:${e.riskScore}%;background:${riskColor(e.riskScore)}"></span></span>${e.riskScore}</td>
    <td>${e.isAnomaly ? '<span class="anomaly-flag" title="Anomaly detected">⚠</span>' : ''}</td>
  </tr>`).join('');
})();

// ═══════════════════════════════════════════
//  2. ANOMALIES (Explain the Weird Stuff)
// ═══════════════════════════════════════════

function getSuggestedFix(e) {
  if (e.action === 'DROP')
    return 'Revoke DROP privileges and restrict DDL operations to authorized DBAs only.';
  if (e.action === 'TRUNCATE' && e.table === 'audit_log')
    return 'Lock the audit_log table against TRUNCATE and enable immutable logging.';
  if (e.action === 'TRUNCATE')
    return 'Restrict TRUNCATE permissions and require approval for bulk data removal.';
  if (e.action === 'GRANT')
    return 'Review and revoke excessive privileges. Enable least-privilege access policies.';
  if (e.action === 'REVOKE')
    return 'Audit recent privilege changes and verify they align with change-management records.';
  if (e.userRole === 'External')
    return 'Block external IP access immediately and investigate the source.';
  if (e.userRole === 'Intern' && ['credentials', 'api_keys', 'salary_data'].includes(e.table))
    return 'Restrict intern access to sensitive tables. Apply role-based access controls.';
  if (e.action === 'DELETE' && e.riskScore >= 40)
    return 'Enable soft-delete policies and require multi-party approval for mass deletions.';
  if (e.anomalyReason?.includes('outside normal business hours'))
    return 'Enforce time-based access restrictions or require MFA for off-hours access.';
  if (e.anomalyReason?.includes('spike in query volume'))
    return 'Implement rate limiting and alert thresholds for abnormal query volumes.';
  if (e.anomalyReason?.includes('Bulk data export'))
    return 'Set row-count export limits and flag bulk download patterns in DLP policies.';
  if (e.anomalyReason?.includes('SQL injection'))
    return 'Enforce parameterized queries and deploy a Web Application Firewall (WAF).';
  if (e.anomalyReason?.includes('failed login'))
    return 'Enable account lockout after repeated failures and enforce MFA.';
  if (e.anomalyReason?.includes('new IP address'))
    return 'Whitelist known service-account IPs and alert on connections from new sources.';
  if (e.sensitivity === 'critical')
    return 'Tighten access controls on this critical table and enable detailed query logging.';
  return 'Investigate the activity and review user permissions for this resource.';
}

function renderAnomalies(filtered) {
  const list = (filtered || ANOMALIES).slice().sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));
  const tbody = document.querySelector('#anomaly-table tbody');
  tbody.innerHTML = list.map((e,i) => `<tr>
    <td>${fmtTime(e.timestamp)}</td>
    <td>${e.userName} <span style="color:var(--muted);font-size:11px">(${e.userRole})</span></td>
    <td><span style="color:${actionColor(e.action)}">${e.action}</span></td>
    <td>${e.table}</td>
    <td style="color:${riskColor(e.riskScore)};font-weight:600">${e.riskScore}</td>
    <td style="font-size:12px;color:var(--accent2);max-width:260px">${getSuggestedFix(e)}</td>
    <td><button class="why-btn" data-anomaly-id="${e.id}">Why is this weird?</button></td>
  </tr>`).join('');

  // Store current list for modal lookups
  window._currentAnomalyList = list;

  const status = document.getElementById('anomaly-filter-status');
  if (filtered) {
    status.textContent = `Showing ${list.length} of ${ANOMALIES.length} anomalies`;
  } else {
    status.textContent = '';
  }
}

(function initAnomalies() {
  renderAnomalies();

  // Set default date range from data
  const timestamps = ANOMALIES.map(e => new Date(e.timestamp));
  const minDate = new Date(Math.min(...timestamps));
  const maxDate = new Date(Math.max(...timestamps));
  document.getElementById('anomaly-date-from').value = minDate.toISOString().split('T')[0];
  document.getElementById('anomaly-date-to').value = maxDate.toISOString().split('T')[0];

  document.querySelector('#anomaly-table tbody').addEventListener('click', ev => {
    const btn = ev.target.closest('.why-btn');
    if (!btn) return;
    const id = +btn.dataset.anomalyId;
    const e = (window._currentAnomalyList || ANOMALIES).find(a => a.id === id);
    if (e) showAnomalyModal(e);
  });

  document.getElementById('anomaly-date-apply').addEventListener('click', applyAnomalyDateFilter);
  document.getElementById('anomaly-date-clear').addEventListener('click', () => {
    const timestamps = ANOMALIES.map(e => new Date(e.timestamp));
    document.getElementById('anomaly-date-from').value = new Date(Math.min(...timestamps)).toISOString().split('T')[0];
    document.getElementById('anomaly-date-to').value = new Date(Math.max(...timestamps)).toISOString().split('T')[0];
    renderAnomalies();
  });
})();

function applyAnomalyDateFilter() {
  const fromVal = document.getElementById('anomaly-date-from').value;
  const toVal   = document.getElementById('anomaly-date-to').value;
  if (!fromVal && !toVal) { renderAnomalies(); return; }

  const from = fromVal ? new Date(fromVal + 'T00:00:00') : new Date(0);
  const to   = toVal   ? new Date(toVal + 'T23:59:59')   : new Date(8640000000000000);

  const filtered = ANOMALIES.filter(e => {
    const t = new Date(e.timestamp);
    return t >= from && t <= to;
  });
  renderAnomalies(filtered);
}

function showAnomalyModal(e) {
  const body = document.getElementById('modal-body');
  body.innerHTML = `
    <p style="font-size:15px;color:var(--danger);font-weight:600;margin-bottom:12px">
      ${e.anomalyReason}
    </p>
    <div class="detail-row"><strong>User:</strong> ${e.userName} (${e.userRole}) — ${e.ip}</div>
    <div class="detail-row"><strong>Action:</strong> ${e.action} on <strong>${e.table}</strong> (${e.sensitivity} sensitivity)</div>
    <div class="detail-row"><strong>Time:</strong> ${fmtTime(e.timestamp)}</div>
    <div class="detail-row"><strong>Risk Score:</strong> <span style="color:${riskColor(e.riskScore)};font-weight:700">${e.riskScore}/100</span></div>
    <div class="detail-row" style="margin-top:10px"><strong>Query:</strong></div>
    <pre style="background:var(--bg);padding:10px;border-radius:6px;font-size:12px;overflow-x:auto;margin-top:4px;color:var(--accent)">${e.query}</pre>
    <p style="margin-top:14px;font-size:13px;line-height:1.6">
      <strong>What this means:</strong> This event deviates from normal database activity patterns.
      ${e.riskScore >= 70 ? 'Immediate investigation is recommended. This could indicate a security breach or policy violation.' :
        e.riskScore >= 40 ? 'This warrants attention. Review the user\'s recent activity for further suspicious behavior.' :
        'While not critical, this pattern is unusual and should be noted in the audit trail.'}
    </p>
    <div style="margin-top:14px;padding:12px 14px;background:rgba(56,189,248,.08);border:1px solid rgba(56,189,248,.2);border-radius:8px">
      <strong style="color:var(--accent2)">🛠 Suggested Fix:</strong>
      <p style="margin-top:6px;font-size:13px;line-height:1.6;color:var(--text)">${getSuggestedFix(e)}</p>
    </div>`;
  document.getElementById('anomaly-modal').classList.add('show');
}

document.getElementById('modal-close').addEventListener('click', () => {
  document.getElementById('anomaly-modal').classList.remove('show');
});
document.getElementById('anomaly-modal').addEventListener('click', ev => {
  if (ev.target === ev.currentTarget) ev.currentTarget.classList.remove('show');
});

// ═══════════════════════════════════════════
//  3. CHAT (Natural Language Querying)
// ═══════════════════════════════════════════
const chatMessages = document.getElementById('chat-messages');
const chatInput    = document.getElementById('chat-input');

function addChatMsg(text, sender) {
  const div = document.createElement('div');
  div.className = `chat-msg ${sender}`;
  div.innerHTML = `
    <div class="chat-avatar">${sender === 'bot' ? '🐼' : '👤'}</div>
    <div class="chat-bubble">${text}</div>`;
  chatMessages.appendChild(div);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Greeting
addChatMsg("Hey there! 🐼 I'm <strong>pandaBase AI</strong>, your friendly security auditor. Ask me anything about your database activity!<br><br>Try things like:<br>• <em>\"Who accessed customer data?\"</em><br>• <em>\"Show suspicious activity\"</em><br>• <em>\"What happened last night?\"</em><br>• <em>\"Most risky users\"</em>", 'bot');

function processChat(query) {
  const q = query.toLowerCase();
  let results = [];
  let response = '';

  if (q.match(/who.*access.*(customer|payment|salary|credential|api.key)/)) {
    const table = q.includes('customer') ? 'customers' : q.includes('payment') ? 'payments' : q.includes('salary') ? 'salary_data' : q.includes('credential') ? 'credentials' : 'api_keys';
    results = ALL_EVENTS.filter(e => e.table === table);
    const users = [...new Set(results.map(e => e.userName))];
    response = `I found <strong>${results.length}</strong> events on the <strong>${table}</strong> table.<br><br>Users who accessed it: <strong>${users.join(', ')}</strong>.<br><br>`;
    if (results.some(e => e.isAnomaly)) {
      const anoCount = results.filter(e => e.isAnomaly).length;
      response += `⚠️ <strong>${anoCount}</strong> of these were flagged as anomalous. You might want to check the Anomalies tab.`;
    } else {
      response += `✅ No anomalous access detected on this table.`;
    }
  }
  else if (q.match(/suspicious|anomal|weird|strange|unusual/)) {
    response = `I found <strong>${ANOMALIES.length}</strong> suspicious events in the audit log.<br><br>Top concerns:<br>`;
    ANOMALIES.sort((a,b)=>b.riskScore-a.riskScore).slice(0,5).forEach(e => {
      response += `• <strong>${e.userName}</strong> — ${e.action} on ${e.table} (risk: ${e.riskScore}) — <em>${e.anomalyReason}</em><br>`;
    });
    response += `<br>Check the <strong>Anomalies</strong> tab for full details.`;
  }
  else if (q.match(/risk|danger|threat|risky.*user/)) {
    response = `Here are the riskiest users:<br><br>`;
    RISK_SCORES.slice(0,5).forEach((u,i) => {
      response += `${i+1}. <strong>${u.name}</strong> (${u.role}) — Total risk: <strong>${u.total}</strong>, Anomalies: ${u.anomalies}<br>`;
    });
  }
  else if (q.match(/last.night|overnight|off.hours|after.hours|3.*am/)) {
    results = ALL_EVENTS.filter(e => { const h = new Date(e.timestamp).getHours(); return h < 6 || h > 22; });
    response = `I found <strong>${results.length}</strong> events during off-hours (10 PM – 6 AM).<br><br>`;
    const users = [...new Set(results.map(e => e.userName))];
    response += `Users active: <strong>${users.join(', ')}</strong><br><br>`;
    const risky = results.filter(e => e.riskScore >= 40);
    response += risky.length > 0
      ? `⚠️ <strong>${risky.length}</strong> of these had elevated risk scores.`
      : `✅ No high-risk events during off-hours.`;
  }
  else if (q.match(/delete|drop|truncate|destruct/)) {
    results = ALL_EVENTS.filter(e => ['DELETE','DROP','TRUNCATE'].includes(e.action));
    response = `Found <strong>${results.length}</strong> destructive operations (DELETE/DROP/TRUNCATE).<br><br>`;
    results.slice(0,5).forEach(e => {
      response += `• <strong>${e.userName}</strong> — ${e.action} on ${e.table} at ${fmtTime(e.timestamp)}<br>`;
    });
    if (results.length > 5) response += `<br>...and ${results.length - 5} more.`;
  }
  else if (q.match(/how many|count|total|summary|overview/)) {
    const avgRisk = Math.round(ALL_EVENTS.reduce((s,e)=>s+e.riskScore,0)/ALL_EVENTS.length);
    response = `📊 <strong>Quick Summary:</strong><br><br>`;
    response += `• Total events: <strong>${ALL_EVENTS.length}</strong><br>`;
    response += `• Anomalies: <strong>${ANOMALIES.length}</strong><br>`;
    response += `• Average risk: <strong>${avgRisk}</strong><br>`;
    response += `• Unique users: <strong>${[...new Set(ALL_EVENTS.map(e=>e.user))].length}</strong><br>`;
    response += `• Sessions: <strong>${SESSIONS.length}</strong><br>`;
    response += `• Audit grade: <strong>${REPORT.grade}</strong>`;
  }
  else if (q.match(/intern|joe/)) {
    results = ALL_EVENTS.filter(e => e.user === 'intern_joe');
    response = `Found <strong>${results.length}</strong> events from <strong>Joe Intern</strong>.<br><br>`;
    const tables = [...new Set(results.map(e => e.table))];
    response += `Tables accessed: <strong>${tables.join(', ')}</strong><br>`;
    const anoCount = results.filter(e => e.isAnomaly).length;
    response += anoCount > 0
      ? `⚠️ <strong>${anoCount}</strong> anomalous events detected. Interns shouldn't be poking around this much...`
      : `✅ Activity looks normal.`;
  }
  else if (q.match(/hello|hi|hey|help/)) {
    response = `Hey! 🐼 I'm here to help you audit your database. Try asking:<br>
    • "Who accessed customer data?"<br>
    • "Show suspicious activity"<br>
    • "What happened last night?"<br>
    • "Show me risky users"<br>
    • "Any destructive queries?"<br>
    • "Give me a summary"`;
  }
  else {
    response = `🤔 I'm not sure about that one. Try asking about:<br>
    • Specific tables (customers, payments, credentials...)<br>
    • Suspicious or anomalous activity<br>
    • Risky users<br>
    • Off-hours access<br>
    • Destructive operations<br>
    • A general summary`;
  }

  // fake typing delay
  setTimeout(() => addChatMsg(response, 'bot'), 400 + Math.random() * 600);
}

document.getElementById('chat-send').addEventListener('click', () => {
  const val = chatInput.value.trim();
  if (!val) return;
  addChatMsg(val, 'user');
  chatInput.value = '';
  processChat(val);
});
chatInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('chat-send').click();
});

// ═══════════════════════════════════════════
//  4. TIMELINE PLAYBACK
// ═══════════════════════════════════════════
let tlPlaying = false, tlIndex = 0, tlTimer = null, tlSpeed = 1;
const tlFeed   = document.getElementById('tl-feed');
const tlSlider = document.getElementById('tl-slider');
const tlTime   = document.getElementById('tl-time');

tlSlider.max = ALL_EVENTS.length - 1;

function renderTlEvent(e, isCurrent) {
  return `<div class="timeline-event ${e.isAnomaly?'highlight':''} ${isCurrent?'current':''}">
    <span class="te-time">${shortTime(e.timestamp)}</span>
    <span class="te-user">${e.userName}</span>
    <span class="te-action" style="color:${actionColor(e.action)}">${e.action}</span>
    <span style="min-width:90px">${e.table}</span>
    <span class="te-query">${e.query.substring(0,60)}…</span>
    <span class="te-risk" style="color:${riskColor(e.riskScore)}">${e.riskScore}</span>
  </div>`;
}

function tlRenderTo(idx) {
  const start = Math.max(0, idx - 40);
  let html = '';
  for (let i = start; i <= idx; i++) {
    html += renderTlEvent(ALL_EVENTS[i], i === idx);
  }
  tlFeed.innerHTML = html;
  tlFeed.scrollTop = tlFeed.scrollHeight;
  tlSlider.value = idx;
  tlTime.textContent = fmtTime(ALL_EVENTS[idx].timestamp);
}

function tlStep() {
  if (tlIndex >= ALL_EVENTS.length - 1) { tlPause(); return; }
  tlIndex++;
  tlRenderTo(tlIndex);
}

function tlPlay()  { tlPlaying = true; tlTimer = setInterval(tlStep, 300 / tlSpeed); document.getElementById('tl-play').classList.add('active-btn'); document.getElementById('tl-pause').classList.remove('active-btn'); }
function tlPause() { tlPlaying = false; clearInterval(tlTimer); document.getElementById('tl-pause').classList.add('active-btn'); document.getElementById('tl-play').classList.remove('active-btn'); }

document.getElementById('tl-play').addEventListener('click', () => { if (!tlPlaying) tlPlay(); });
document.getElementById('tl-pause').addEventListener('click', tlPause);
document.getElementById('tl-reset').addEventListener('click', () => { tlPause(); tlIndex = 0; tlRenderTo(0); });
tlSlider.addEventListener('input', () => { tlPause(); tlIndex = +tlSlider.value; tlRenderTo(tlIndex); });

const speedBtn = document.getElementById('tl-speed');
speedBtn.addEventListener('click', () => {
  const speeds = [1, 2, 4, 8];
  let i = speeds.indexOf(tlSpeed);
  tlSpeed = speeds[(i + 1) % speeds.length];
  speedBtn.textContent = tlSpeed + '×';
  if (tlPlaying) { clearInterval(tlTimer); tlTimer = setInterval(tlStep, 300 / tlSpeed); }
});

// init first frame
tlRenderTo(0);

// ═══════════════════════════════════════════
//  5. GRAPH VIEW (Canvas)
// ═══════════════════════════════════════════
function populateGraphFilter() {
  const select = document.getElementById('graph-user-filter');
  if (select.options.length > 1) return; // already populated
  const users = [...new Set(ALL_EVENTS.map(e => e.user))];
  const userNames = {};
  ALL_EVENTS.forEach(e => { userNames[e.user] = e.userName; });
  users.forEach(u => {
    const opt = document.createElement('option');
    opt.value = u;
    opt.textContent = `${userNames[u]} (${u})`;
    select.appendChild(opt);
  });
  select.addEventListener('change', () => drawGraph(select.value));
}

function drawGraph(filterUser) {
  if (filterUser === undefined) filterUser = document.getElementById('graph-user-filter')?.value || 'all';
  const events = filterUser === 'all' ? ALL_EVENTS : ALL_EVENTS.filter(e => e.user === filterUser);
  const canvas = document.getElementById('graph-canvas');
  const ctx = canvas.getContext('2d');
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width;
  canvas.height = 600;
  const W = canvas.width, H = canvas.height;

  ctx.fillStyle = '#111827';
  ctx.fillRect(0, 0, W, H);

  // Build nodes
  const users  = [...new Set(events.map(e => e.user))];
  const tables = [...new Set(events.map(e => e.table))];

  // Edges: count per user→table
  const edgeMap = {};
  events.forEach(e => {
    const key = e.user + '→' + e.table;
    if (!edgeMap[key]) edgeMap[key] = { from: e.user, to: e.table, count: 0, actions: new Set() };
    edgeMap[key].count++;
    edgeMap[key].actions.add(e.action);
  });
  const edges = Object.values(edgeMap);

  // Friendly display names
  const userNames = {};
  events.forEach(e => { userNames[e.user] = e.userName; });

  // Position — users on left column evenly spaced, tables on right column
  const nodes = {};
  const padY = 60;
  const leftX = 160, rightX = W - 180;
  const usableH = H - padY * 2;

  users.forEach((u, i) => {
    const y = padY + (usableH / (users.length - 1 || 1)) * i;
    nodes[u] = { x: leftX, y, label: userNames[u] || u, sublabel: u, type: 'user' };
  });
  tables.forEach((t, i) => {
    const y = padY + (usableH / (tables.length - 1 || 1)) * i;
    const sens = TABLES.find(tb => tb.name === t)?.sensitivity || 'low';
    nodes[t] = { x: rightX, y, label: t, sublabel: sens, type: 'table' };
  });

  // Draw edges (behind nodes)
  const maxCount = Math.max(...edges.map(e => e.count));
  edges.forEach(e => {
    const from = nodes[e.from], to = nodes[e.to];
    if (!from || !to) return;
    const thickness = 1.5 + (e.count / maxCount) * 7;
    const hasDanger = e.actions.has('DROP') || e.actions.has('DELETE') || e.actions.has('TRUNCATE');
    const hasGrant  = e.actions.has('GRANT') || e.actions.has('REVOKE');
    const alpha = 0.12 + (e.count / maxCount) * 0.3;

    ctx.beginPath();
    ctx.moveTo(from.x + 24, from.y);
    // Curved bezier for readability
    const cpx1 = from.x + (rightX - leftX) * 0.35;
    const cpx2 = from.x + (rightX - leftX) * 0.65;
    ctx.bezierCurveTo(cpx1, from.y, cpx2, to.y, to.x - 24, to.y);
    ctx.strokeStyle = hasDanger ? `rgba(244,63,94,${alpha + 0.1})` : hasGrant ? `rgba(245,158,11,${alpha})` : `rgba(79,201,120,${alpha})`;
    ctx.lineWidth = thickness;
    ctx.stroke();

    // Edge count label at midpoint for thick edges
    if (e.count / maxCount > 0.4) {
      const mx = (from.x + to.x) / 2;
      const my = (from.y + to.y) / 2;
      ctx.font = 'bold 10px Segoe UI';
      ctx.fillStyle = 'rgba(255,255,255,0.4)';
      ctx.textAlign = 'center';
      ctx.fillText(e.count + '×', mx, my - 4);
    }
  });

  // Column headers
  ctx.font = 'bold 13px Segoe UI';
  ctx.textAlign = 'center';
  ctx.fillStyle = '#4fc978';
  ctx.fillText('👤  USERS', leftX, 28);
  ctx.fillStyle = '#38bdf8';
  ctx.fillText('🗄️  TABLES', rightX, 28);

  // Draw nodes
  Object.values(nodes).forEach(n => {
    // Glow effect for user nodes
    if (n.type === 'user') {
      ctx.beginPath();
      ctx.arc(n.x, n.y, 28, 0, Math.PI * 2);
      const glow = ctx.createRadialGradient(n.x, n.y, 12, n.x, n.y, 28);
      glow.addColorStop(0, 'rgba(79,201,120,0.15)');
      glow.addColorStop(1, 'rgba(79,201,120,0)');
      ctx.fillStyle = glow;
      ctx.fill();
    }

    // Node circle
    ctx.beginPath();
    const r = n.type === 'user' ? 22 : 18;
    ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
    ctx.fillStyle = n.type === 'user' ? '#4fc978' : '#38bdf8';
    ctx.fill();
    ctx.strokeStyle = '#0a0e17';
    ctx.lineWidth = 3;
    ctx.stroke();

    // Icon inside node
    ctx.fillStyle = '#0a0e17';
    ctx.font = n.type === 'user' ? '14px Segoe UI' : '12px Segoe UI';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(n.type === 'user' ? '👤' : '🗄️', n.x, n.y);
    ctx.textBaseline = 'alphabetic';

    // Label
    ctx.fillStyle = '#e2e8f0';
    ctx.font = 'bold 13px Segoe UI';
    ctx.textAlign = n.type === 'user' ? 'right' : 'left';
    const lx = n.type === 'user' ? n.x - r - 10 : n.x + r + 10;
    ctx.fillText(n.label, lx, n.y + 1);

    // Sub-label (user id or sensitivity)
    ctx.fillStyle = '#64748b';
    ctx.font = '11px Segoe UI';
    ctx.fillText(n.sublabel, lx, n.y + 16);
  });
}

// ═══════════════════════════════════════════
//  6. RISK SCORES LEADERBOARD
// ═══════════════════════════════════════════
(function renderRisk() {
  const ul = document.getElementById('leaderboard');
  ul.innerHTML = RISK_SCORES.map((u, i) => {
    const rankCls = i === 0 ? 'gold' : i === 1 ? 'silver' : i === 2 ? 'bronze' : '';
    const medal = i === 0 ? '🥇' : i === 1 ? '🥈' : i === 2 ? '🥉' : `#${i+1}`;
    return `<li>
      <span class="lb-rank ${rankCls}">${medal}</span>
      <div class="lb-info">
        <div class="lb-name">${u.name}</div>
        <div class="lb-meta">${u.role} · ${u.events} events · ${u.anomalies} anomalies</div>
      </div>
      <div class="lb-score" style="color:${riskColor(u.total > 300 ? 80 : u.total > 150 ? 50 : 20)}">${u.total}</div>
    </li>`;
  }).join('');
})();

// ═══════════════════════════════════════════
//  7. SESSION RECONSTRUCTION
// ═══════════════════════════════════════════
(function renderSessions() {
  const container = document.getElementById('session-list');
  container.innerHTML = SESSIONS.slice(0, 25).map((s, si) => {
    const duration = ((new Date(s.end) - new Date(s.start)) / 60000).toFixed(0);
    return `<div class="session-card" data-session="${si}">
      <div class="session-header">
        <div>
          <span class="session-user">${s.userName}</span>
          <span style="color:var(--muted);font-size:12px">(${s.userRole})</span>
        </div>
        <div class="session-meta">
          ${fmtTime(s.start)} → ${shortTime(s.end)} · ${duration} min · ${s.events.length} queries · Max risk: <span style="color:${riskColor(s.maxRisk)};font-weight:600">${s.maxRisk}</span>
        </div>
      </div>
      <div class="session-steps" style="display:none">
        ${s.events.map((e, ei) => `
          <div class="session-step ${e.riskScore>=40?'risky':''}">
            <span class="step-num">${ei+1}</span>
            <div>
              <strong style="color:${actionColor(e.action)}">${e.action}</strong> on <strong>${e.table}</strong>
              <span style="color:var(--muted);font-size:12px;margin-left:8px">${shortTime(e.timestamp)}</span>
              ${e.isAnomaly ? '<span style="color:var(--danger);font-size:11px;margin-left:6px">⚠ anomaly</span>' : ''}
              <div style="font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:2px">${e.query}</div>
            </div>
          </div>`).join('')}
      </div>
    </div>`;
  }).join('');

  container.addEventListener('click', ev => {
    const card = ev.target.closest('.session-card');
    if (!card) return;
    const steps = card.querySelector('.session-steps');
    const isOpen = steps.style.display !== 'none';
    steps.style.display = isOpen ? 'none' : 'block';
    card.classList.toggle('expanded', !isOpen);
  });
})();

// ═══════════════════════════════════════════
//  8. ATTACK SIMULATION
// ═══════════════════════════════════════════
(function renderSimScenarios() {
  const container = document.getElementById('sim-scenarios');
  container.innerHTML = ATTACK_SCENARIOS.map((sc, i) => `
    <div class="sim-card" data-sim="${i}">
      <div class="sim-icon">${sc.icon}</div>
      <div class="sim-name">${sc.name}</div>
      <div class="sim-desc">${sc.description}</div>
    </div>`).join('');

  container.addEventListener('click', ev => {
    const card = ev.target.closest('.sim-card');
    if (!card) return;
    runSimulation(+card.dataset.sim);
  });
})();

function runSimulation(idx) {
  const sc = ATTACK_SCENARIOS[idx];
  const feed = document.getElementById('sim-feed');
  feed.style.display = 'block';
  feed.innerHTML = '';

  // Mark active
  document.querySelectorAll('.sim-card').forEach(c => c.classList.remove('active-sim'));
  document.querySelector(`.sim-card[data-sim="${idx}"]`).classList.add('active-sim');

  sc.steps.forEach((step, i) => {
    setTimeout(() => {
      const user = USERS.find(u => u.id === step.user);
      const div = document.createElement('div');
      div.className = 'sim-event';
      div.innerHTML = `
        <span class="se-icon">${i === sc.steps.length - 1 ? '🚨' : '🔵'}</span>
        <div class="se-detail">
          <strong>${user?.name || step.user}</strong> &mdash;
          <span style="color:${actionColor(step.action)}">${step.action}</span> on <strong>${step.table}</strong>
          <span style="color:var(--muted);font-size:12px;margin-left:8px">Risk: <span style="color:${riskColor(step.risk)};font-weight:600">${step.risk}</span></span>
          <div class="se-query">${step.query}</div>
          <div class="se-alert">🔍 pandaBase detected: ${step.anomaly}</div>
        </div>`;
      feed.appendChild(div);
      feed.scrollTop = feed.scrollHeight;
    }, step.delay);
  });
}

// ═══════════════════════════════════════════
//  9. REAL-TIME MODE (fake streaming)
// ═══════════════════════════════════════════
let rtRunning = false, rtTimer = null;
const rtFeed = document.getElementById('rt-feed');

function startRealtime() {
  if (rtRunning) return;
  rtRunning = true;
  document.getElementById('rt-toggle').textContent = '⏸ Pause Stream';
  document.getElementById('rt-toggle').classList.add('active-btn');

  rtTimer = setInterval(() => {
    const user  = pick(USERS);
    const table = pick(TABLES);
    const action = pick(ACTIONS);
    const risk  = riskForEvent(action, table.name, user, new Date().getHours());
    const isAnomaly = risk >= 75;
    const ts = new Date().toLocaleTimeString();

    const line = document.createElement('div');
    line.className = 'rt-line';
    line.innerHTML = `
      <span class="rt-ts">${ts}</span>
      <span class="rt-user">${user.id}</span>
      <span class="rt-action" style="color:${actionColor(action)}">${action}</span>
      <span class="rt-table">${table.name}</span>
      <span class="rt-risk" style="color:${riskColor(risk)}">${risk}</span>
      ${isAnomaly ? '<span class="rt-anomaly">⚠ ANOMALY</span>' : ''}`;
    rtFeed.appendChild(line);

    // Keep max 200 lines
    while (rtFeed.children.length > 200) rtFeed.removeChild(rtFeed.firstChild);
    rtFeed.scrollTop = rtFeed.scrollHeight;
  }, 400 + Math.random() * 400);
}

function stopRealtime() {
  rtRunning = false;
  clearInterval(rtTimer);
  document.getElementById('rt-toggle').textContent = '▶ Resume Stream';
  document.getElementById('rt-toggle').classList.remove('active-btn');
}

document.getElementById('rt-toggle').addEventListener('click', () => {
  rtRunning ? stopRealtime() : startRealtime();
});

// ═══════════════════════════════════════════
//  10. AUDIT REPORT
// ═══════════════════════════════════════════
(function renderReport() {
  const r = REPORT;
  const container = document.getElementById('report-content');

  const sensTableHtml = Object.entries(r.sensitiveTables)
    .sort((a,b) => b[1] - a[1])
    .map(([table, count]) => `<li><strong>${table}</strong> — ${count} access events</li>`)
    .join('');

  container.innerHTML = `
    <div class="report-header">
      <div style="font-size:13px;color:var(--muted);margin-bottom:8px">DATABASE SECURITY AUDIT REPORT</div>
      <div style="font-size:20px;font-weight:600;margin-bottom:20px">pandaBase Security Auditing</div>
      <div style="margin-bottom:6px;color:var(--muted);font-size:13px">Overall Security Grade</div>
      <div class="report-grade" style="color:${r.color}">${r.grade}</div>
      <div style="margin-top:8px;font-size:14px;color:var(--muted)">Average Risk Score: ${r.avgRisk}/100</div>
    </div>

    <div class="grid grid-3" style="margin-bottom:28px">
      <div class="card" style="text-align:center">
        <div class="card-title">Total Events</div>
        <div class="card-value blue">${r.total}</div>
      </div>
      <div class="card" style="text-align:center">
        <div class="card-title">Anomalies</div>
        <div class="card-value red">${r.anomalies}</div>
      </div>
      <div class="card" style="text-align:center">
        <div class="card-title">Critical Events</div>
        <div class="card-value yellow">${r.criticalEvents}</div>
      </div>
    </div>

    <div style="text-align:center;margin-bottom:28px">
      <button class="report-btn" onclick="exportReport()">📄 Export as Markdown</button>
      <button class="report-btn" style="margin-left:12px;background:var(--accent2)" onclick="exportReportExcel()">📊 Export to Excel</button>
    </div>

    <div class="report-section">
      <h3>🚨 High-Risk Users</h3>
      <ul class="report-list">
        ${r.riskUsers.map(u => `<li><strong>${u.name}</strong> (${u.role}) — Total risk: ${u.total}, Anomalies: ${u.anomalies}</li>`).join('')}
        ${r.riskUsers.length === 0 ? '<li>No high-risk users detected</li>' : ''}
      </ul>
    </div>

    <div class="report-section">
      <h3>📋 Sensitive Table Access</h3>
      <ul class="report-list">${sensTableHtml}</ul>
    </div>

    <div class="report-section">
      <h3>✅ Recommendations</h3>
      <ul class="report-list">
        ${r.recommendations.map(rec => `<li>${rec}</li>`).join('')}
      </ul>
    </div>

    </div>`;
})();

function exportReport() {
  const r = REPORT;
  let md = `# pandaBase Security Audit Report\n\n`;
  md += `**Date:** ${new Date().toLocaleDateString()}\n\n`;
  md += `## Overall Grade: ${r.grade}\n\n`;
  md += `- Average Risk Score: ${r.avgRisk}/100\n`;
  md += `- Total Events: ${r.total}\n`;
  md += `- Anomalies: ${r.anomalies}\n`;
  md += `- Critical Events: ${r.criticalEvents}\n`;
  md += `- Unique Users: ${r.uniqueUsers}\n\n`;
  md += `## High-Risk Users\n\n`;
  r.riskUsers.forEach(u => { md += `- **${u.name}** (${u.role}) — Risk: ${u.total}, Anomalies: ${u.anomalies}\n`; });
  md += `\n## Sensitive Table Access\n\n`;
  Object.entries(r.sensitiveTables).sort((a,b)=>b[1]-a[1]).forEach(([t,c]) => { md += `- **${t}** — ${c} events\n`; });
  md += `\n## Recommendations\n\n`;
  r.recommendations.forEach(rec => { md += `- ${rec}\n`; });
  md += `\n---\n*Generated by pandaBase Security Auditing*\n`;

  const blob = new Blob([md], { type: 'text/markdown' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'pandabase-audit-report.md';
  a.click();
}

// ═══════════════════════════════════════════
//  EXCEL EXPORT FUNCTIONS
// ═══════════════════════════════════════════
function eventsToRows(events) {
  return events.map(e => ({
    'Timestamp':     e.timestamp,
    'User ID':       e.user,
    'User Name':     e.userName,
    'Role':          e.userRole,
    'IP Address':    e.ip,
    'Action':        e.action,
    'Table':         e.table,
    'Sensitivity':   e.sensitivity,
    'Query':         e.query,
    'Risk Score':    e.riskScore,
    'Anomaly':       e.isAnomaly ? 'Yes' : 'No',
    'Anomaly Reason': e.anomalyReason || '',
  }));
}

function downloadExcel(rows, filename) {
  const ws = XLSX.utils.json_to_sheet(rows);
  // Auto-size columns
  const colWidths = Object.keys(rows[0] || {}).map(key => {
    const max = Math.max(key.length, ...rows.map(r => String(r[key] || '').length));
    return { wch: Math.min(max + 2, 50) };
  });
  ws['!cols'] = colWidths;

  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'Audit Logs');
  XLSX.writeFile(wb, filename);
}

function exportOverviewExcel() {
  const recent = [...ALL_EVENTS].reverse().slice(0, 60);
  downloadExcel(eventsToRows(recent), 'pandabase-recent-events.xlsx');
}

function exportAnomaliesExcel() {
  const sorted = ANOMALIES.sort((a, b) => b.riskScore - a.riskScore);
  downloadExcel(eventsToRows(sorted), 'pandabase-anomalies.xlsx');
}

function exportAllLogsExcel() {
  downloadExcel(eventsToRows(ALL_EVENTS), 'pandabase-all-logs.xlsx');
}

function exportReportExcel() {
  const r = REPORT;
  const wb = XLSX.utils.book_new();

  // Summary sheet
  const summaryRows = [
    { 'Metric': 'Security Grade', 'Value': r.grade },
    { 'Metric': 'Average Risk Score', 'Value': r.avgRisk + '/100' },
    { 'Metric': 'Total Events', 'Value': r.total },
    { 'Metric': 'Anomalies Detected', 'Value': r.anomalies },
    { 'Metric': 'Critical Events', 'Value': r.criticalEvents },
    { 'Metric': 'Unique Users', 'Value': r.uniqueUsers },
  ];
  const wsSummary = XLSX.utils.json_to_sheet(summaryRows);
  wsSummary['!cols'] = [{ wch: 22 }, { wch: 30 }];
  XLSX.utils.book_append_sheet(wb, wsSummary, 'Summary');

  // High-risk users sheet
  const riskRows = r.riskUsers.map(u => ({
    'User': u.name,
    'Role': u.role,
    'Total Risk': u.total,
    'Events': u.events,
    'Anomalies': u.anomalies,
  }));
  if (riskRows.length) {
    const wsRisk = XLSX.utils.json_to_sheet(riskRows);
    wsRisk['!cols'] = [{ wch: 20 }, { wch: 14 }, { wch: 12 }, { wch: 10 }, { wch: 12 }];
    XLSX.utils.book_append_sheet(wb, wsRisk, 'High-Risk Users');
  }

  // Sensitive tables sheet
  const tableRows = Object.entries(r.sensitiveTables).sort((a, b) => b[1] - a[1]).map(([t, c]) => ({
    'Table': t,
    'Access Events': c,
  }));
  if (tableRows.length) {
    const wsTables = XLSX.utils.json_to_sheet(tableRows);
    wsTables['!cols'] = [{ wch: 20 }, { wch: 16 }];
    XLSX.utils.book_append_sheet(wb, wsTables, 'Sensitive Tables');
  }

  // Recommendations sheet
  const recRows = r.recommendations.map((rec, i) => ({ '#': i + 1, 'Recommendation': rec }));
  const wsRec = XLSX.utils.json_to_sheet(recRows);
  wsRec['!cols'] = [{ wch: 4 }, { wch: 70 }];
  XLSX.utils.book_append_sheet(wb, wsRec, 'Recommendations');

  // All events sheet
  const wsEvents = XLSX.utils.json_to_sheet(eventsToRows(ALL_EVENTS));
  XLSX.utils.book_append_sheet(wb, wsEvents, 'All Events');

  XLSX.writeFile(wb, 'pandabase-audit-report.xlsx');
}
