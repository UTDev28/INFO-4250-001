/* ─────────────────────────────────────────────
   mockData.js — Fake audit-log data generator
   pandaBase Security Auditing
   ───────────────────────────────────────────── */

const USERS = [
  { id: 'admin',        name: 'Admin Root',       role: 'DBA',          ip: '10.0.0.1' },
  { id: 'jsmith',       name: 'John Smith',       role: 'Developer',    ip: '10.0.1.42' },
  { id: 'mwilliams',    name: 'Maria Williams',   role: 'Analyst',      ip: '10.0.2.17' },
  { id: 'analyst1',     name: 'Alex Chen',        role: 'Analyst',      ip: '10.0.2.33' },
  { id: 'dbadmin',      name: 'Dana Blake',       role: 'DBA',          ip: '10.0.0.5' },
  { id: 'intern_joe',   name: 'Joe Intern',       role: 'Intern',       ip: '192.168.1.88' },
  { id: 'svc_backup',   name: 'Backup Service',   role: 'Service',      ip: '10.0.0.200' },
  { id: 'hacker_x',     name: 'Unknown Actor',    role: 'External',     ip: '185.243.115.9' },
];

const TABLES = [
  { name: 'customers',      sensitivity: 'high' },
  { name: 'orders',          sensitivity: 'medium' },
  { name: 'payments',        sensitivity: 'critical' },
  { name: 'employees',       sensitivity: 'high' },
  { name: 'salary_data',     sensitivity: 'critical' },
  { name: 'audit_log',       sensitivity: 'medium' },
  { name: 'credentials',     sensitivity: 'critical' },
  { name: 'api_keys',        sensitivity: 'critical' },
  { name: 'products',        sensitivity: 'low' },
  { name: 'sessions',        sensitivity: 'medium' },
  { name: 'user_roles',      sensitivity: 'high' },
  { name: 'config',          sensitivity: 'medium' },
];

const ACTIONS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'GRANT', 'REVOKE', 'TRUNCATE'];

const ANOMALY_REASONS = [
  'Access occurred outside normal business hours (3:17 AM)',
  'User does not typically access this table',
  'Sudden spike in query volume (12× normal rate)',
  'Mass DELETE executed on a critical table',
  'Privilege escalation detected — GRANT ALL issued',
  'Sensitive table accessed from an external IP',
  'Bulk data export pattern detected (sequential SELECT with LIMIT offsets)',
  'DROP TABLE attempted on production table',
  'Service account accessed from a new IP address',
  'Multiple failed login attempts followed by success',
  'User accessed credentials table for the first time',
  'Query pattern resembles SQL injection attempt',
  'Unusually large result set returned (50K+ rows)',
  'TRUNCATE on audit_log — possible evidence tampering',
];

/* ── helpers ── */
function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

function generateQuery(action, table) {
  switch (action) {
    case 'SELECT':   return `SELECT * FROM ${table} WHERE id > ${rand(1,9999)} LIMIT ${rand(10,500)};`;
    case 'INSERT':   return `INSERT INTO ${table} (col1, col2) VALUES ('val${rand(1,99)}', ${rand(100,9999)});`;
    case 'UPDATE':   return `UPDATE ${table} SET status = 'modified' WHERE id = ${rand(1,5000)};`;
    case 'DELETE':   return `DELETE FROM ${table} WHERE created_at < '2025-${rand(1,12).toString().padStart(2,'0')}-01';`;
    case 'DROP':     return `DROP TABLE IF EXISTS ${table};`;
    case 'ALTER':    return `ALTER TABLE ${table} ADD COLUMN tmp_col VARCHAR(255);`;
    case 'GRANT':    return `GRANT ALL PRIVILEGES ON ${table} TO 'unknown_user'@'%';`;
    case 'REVOKE':   return `REVOKE SELECT ON ${table} FROM 'intern_joe'@'%';`;
    case 'TRUNCATE': return `TRUNCATE TABLE ${table};`;
    default:         return `SELECT 1;`;
  }
}

function riskForEvent(action, table, user, hour) {
  let score = 0;
  const sens = TABLES.find(t => t.name === table)?.sensitivity || 'low';
  if (sens === 'critical')  score += 25;
  else if (sens === 'high') score += 15;
  else if (sens === 'medium') score += 5;

  if (['DROP','TRUNCATE'].includes(action))  score += 50;
  if (['GRANT','REVOKE'].includes(action))   score += 30;
  if (action === 'DELETE')                   score += 20;
  if (action === 'UPDATE')                   score += 5;

  if (hour < 6 || hour > 22) score += 20;
  if (user.role === 'Intern')   score += 15;
  if (user.role === 'External') score += 40;

  return Math.min(score, 100);
}

/* ── main generator ── */
function generateAuditLogs(count = 300) {
  const events = [];
  const now = Date.now();
  const threeDays = 3 * 24 * 60 * 60 * 1000;

  for (let i = 0; i < count; i++) {
    const ts        = new Date(now - Math.random() * threeDays);
    const user      = pick(USERS);
    const tableObj  = pick(TABLES);
    const action    = pick(ACTIONS);
    const risk      = riskForEvent(action, tableObj.name, user, ts.getHours());
    const isAnomaly = risk >= 40 || Math.random() < 0.08;

    events.push({
      id:           i + 1,
      timestamp:    ts.toISOString(),
      ts:           ts.getTime(),
      user:         user.id,
      userName:     user.name,
      userRole:     user.role,
      ip:           user.ip,
      action:       action,
      table:        tableObj.name,
      sensitivity:  tableObj.sensitivity,
      query:        generateQuery(action, tableObj.name),
      riskScore:    risk,
      isAnomaly:    isAnomaly,
      anomalyReason: isAnomaly ? pick(ANOMALY_REASONS) : null,
    });
  }

  events.sort((a, b) => a.ts - b.ts);
  return events;
}

/* ── session grouping ── */
function groupIntoSessions(events) {
  const byUser = {};
  events.forEach(e => {
    if (!byUser[e.user]) byUser[e.user] = [];
    byUser[e.user].push(e);
  });

  const sessions = [];
  Object.keys(byUser).forEach(userId => {
    const userEvents = byUser[userId].sort((a, b) => a.ts - b.ts);
    let session = null;
    const GAP = 30 * 60 * 1000; // 30-min gap = new session

    userEvents.forEach(e => {
      if (!session || e.ts - session.events[session.events.length - 1].ts > GAP) {
        if (session) sessions.push(session);
        session = {
          id: sessions.length + 1,
          user: e.user,
          userName: e.userName,
          userRole: e.userRole,
          ip: e.ip,
          start: e.timestamp,
          end: e.timestamp,
          events: [],
          maxRisk: 0,
          tables: new Set(),
        };
      }
      session.events.push(e);
      session.end = e.timestamp;
      session.maxRisk = Math.max(session.maxRisk, e.riskScore);
      session.tables.add(e.table);
    });
    if (session) sessions.push(session);
  });

  sessions.forEach(s => { s.tables = [...s.tables]; });
  sessions.sort((a, b) => new Date(b.start) - new Date(a.start));
  return sessions;
}

/* ── risk leaderboard ── */
function computeRiskScores(events) {
  const scores = {};
  events.forEach(e => {
    if (!scores[e.user]) scores[e.user] = { user: e.user, name: e.userName, role: e.userRole, total: 0, events: 0, anomalies: 0 };
    scores[e.user].total += e.riskScore;
    scores[e.user].events++;
    if (e.isAnomaly) scores[e.user].anomalies++;
  });
  return Object.values(scores).sort((a, b) => b.total - a.total);
}

/* ── attack simulation scenarios ── */
const ATTACK_SCENARIOS = [
  {
    name: 'SQL Injection Attempt',
    icon: '💉',
    description: 'An external actor attempts SQL injection through the login form, escalating to data exfiltration.',
    steps: [
      { delay: 0,    user: 'hacker_x', action: 'SELECT', table: 'sessions',    query: "SELECT * FROM sessions WHERE user = '' OR '1'='1'; --", risk: 70, anomaly: 'Query pattern resembles SQL injection attempt' },
      { delay: 1500, user: 'hacker_x', action: 'SELECT', table: 'credentials', query: "SELECT username, password_hash FROM credentials WHERE '1'='1';", risk: 90, anomaly: 'Sensitive table accessed from an external IP' },
      { delay: 3000, user: 'hacker_x', action: 'SELECT', table: 'customers',   query: "SELECT * FROM customers LIMIT 50000 OFFSET 0;", risk: 85, anomaly: 'Bulk data export pattern detected (sequential SELECT with LIMIT offsets)' },
      { delay: 4500, user: 'hacker_x', action: 'SELECT', table: 'customers',   query: "SELECT * FROM customers LIMIT 50000 OFFSET 50000;", risk: 85, anomaly: 'Unusually large result set returned (50K+ rows)' },
      { delay: 6000, user: 'hacker_x', action: 'SELECT', table: 'payments',    query: "SELECT card_number, cvv, expiry FROM payments;", risk: 95, anomaly: 'Bulk data export pattern detected (sequential SELECT with LIMIT offsets)' },
    ],
  },
  {
    name: 'Data Exfiltration Spike',
    icon: '📤',
    description: 'A compromised developer account begins exporting massive amounts of sensitive data during off-hours.',
    steps: [
      { delay: 0,    user: 'jsmith',  action: 'SELECT', table: 'customers',   query: "SELECT * FROM customers;", risk: 60, anomaly: 'Access occurred outside normal business hours (3:17 AM)' },
      { delay: 1200, user: 'jsmith',  action: 'SELECT', table: 'payments',    query: "SELECT * FROM payments WHERE amount > 1000;", risk: 75, anomaly: 'User does not typically access this table' },
      { delay: 2400, user: 'jsmith',  action: 'SELECT', table: 'salary_data', query: "SELECT * FROM salary_data;", risk: 85, anomaly: 'Sudden spike in query volume (12× normal rate)' },
      { delay: 3600, user: 'jsmith',  action: 'SELECT', table: 'credentials', query: "SELECT * FROM credentials;", risk: 90, anomaly: 'User accessed credentials table for the first time' },
      { delay: 4800, user: 'jsmith',  action: 'SELECT', table: 'api_keys',    query: "SELECT key, secret FROM api_keys;", risk: 95, anomaly: 'Bulk data export pattern detected (sequential SELECT with LIMIT offsets)' },
    ],
  },
  {
    name: 'Privilege Escalation',
    icon: '👑',
    description: 'An intern account begins escalating privileges and attempting destructive operations.',
    steps: [
      { delay: 0,    user: 'intern_joe', action: 'SELECT', table: 'user_roles',  query: "SELECT * FROM user_roles;", risk: 50, anomaly: 'User does not typically access this table' },
      { delay: 1500, user: 'intern_joe', action: 'GRANT',  table: 'credentials', query: "GRANT ALL PRIVILEGES ON credentials TO 'intern_joe'@'%';", risk: 80, anomaly: 'Privilege escalation detected — GRANT ALL issued' },
      { delay: 3000, user: 'intern_joe', action: 'SELECT', table: 'credentials', query: "SELECT * FROM credentials WHERE role = 'admin';", risk: 85, anomaly: 'User accessed credentials table for the first time' },
      { delay: 4500, user: 'intern_joe', action: 'UPDATE', table: 'user_roles',  query: "UPDATE user_roles SET role = 'admin' WHERE user = 'intern_joe';", risk: 90, anomaly: 'Privilege escalation detected — GRANT ALL issued' },
      { delay: 6000, user: 'intern_joe', action: 'DELETE', table: 'audit_log',   query: "DELETE FROM audit_log WHERE user = 'intern_joe';", risk: 95, anomaly: 'TRUNCATE on audit_log — possible evidence tampering' },
    ],
  },
];

/* ── report generator ── */
function generateReport(events) {
  const total = events.length;
  const anomalies = events.filter(e => e.isAnomaly);
  const avgRisk = Math.round(events.reduce((s, e) => s + e.riskScore, 0) / total);
  const criticalEvents = events.filter(e => e.riskScore >= 70);
  const uniqueUsers = [...new Set(events.map(e => e.user))];
  const riskUsers = computeRiskScores(events).filter(u => u.total > 200);

  let grade, color;
  if (avgRisk < 15)      { grade = 'A — Secure';              color = '#4fc978'; }
  else if (avgRisk < 25) { grade = 'B — Mostly Secure';       color = '#7dd87d'; }
  else if (avgRisk < 40) { grade = 'C — Moderate Risk';       color = '#f0c040'; }
  else if (avgRisk < 60) { grade = 'D — High Risk';           color = '#f08030'; }
  else                   { grade = 'F — Critical';            color = '#ff4444'; }

  const sensitiveTables = {};
  events.filter(e => ['critical','high'].includes(e.sensitivity)).forEach(e => {
    sensitiveTables[e.table] = (sensitiveTables[e.table] || 0) + 1;
  });

  const recommendations = [];
  if (anomalies.length > 20) recommendations.push('Investigate the high volume of anomalous events immediately.');
  if (riskUsers.length > 0)  recommendations.push(`Review activity for high-risk users: ${riskUsers.map(u=>u.name).join(', ')}.`);
  if (events.some(e => e.action === 'DROP'))     recommendations.push('Restrict DROP TABLE permissions to DBA roles only.');
  if (events.some(e => e.action === 'GRANT'))    recommendations.push('Implement approval workflows for privilege changes.');
  if (events.some(e => e.table === 'audit_log' && e.action !== 'SELECT')) recommendations.push('Protect audit_log from modification — enable write-once logging.');
  if (events.some(e => e.userRole === 'External')) recommendations.push('Block or closely monitor all external IP access.');
  recommendations.push('Enable multi-factor authentication for all database accounts.');
  recommendations.push('Schedule regular security audits (quarterly recommended).');

  return { total, anomalies: anomalies.length, avgRisk, grade, color, criticalEvents: criticalEvents.length, uniqueUsers: uniqueUsers.length, riskUsers, sensitiveTables, recommendations };
}
