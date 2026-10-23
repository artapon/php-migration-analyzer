/* PHP Migration Analyzer – frontend (vanilla JS, hash router) */
'use strict';

// ---------------------------------------------------------------- utilities
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (n) => Number(n || 0).toLocaleString('en-US');
const SEV = ['blocker', 'critical', 'major', 'minor', 'info'];
const SEV_COLOR = { blocker: '#a4030f', critical: '#d02f3a', major: '#ed7d20', minor: '#3f8bd8', info: '#8a8f9c' };
// ---------------------------------------------------------------- i18n (EN / TH)
const LANG_KEY = 'pma-lang';
let LANG = (() => { try { return localStorage.getItem(LANG_KEY) || 'en'; } catch { return 'en'; } })();
const I18N_TH = {
  'Projects': 'โปรเจกต์', 'New scan': 'สแกนใหม่', 'Rules': 'กฎการตรวจ', 'Migration guide': 'คู่มือการย้ายเวอร์ชัน',
  'Compatibility': 'ความเข้ากันได้', 'Security': 'ความปลอดภัย', 'Best practice': 'แนวปฏิบัติที่ดี',
  'Removed': 'ถูกลบแล้ว', 'Behavior change': 'พฤติกรรมเปลี่ยน', 'Deprecated': 'เลิกใช้ (Deprecated)', 'Vulnerability': 'ช่องโหว่', 'Code smell': 'โค้ดควรปรับปรุง', 'Issue': 'ปัญหา',
  'Overview': 'ภาพรวม', 'Issues': 'ปัญหา', 'Code': 'โค้ด', 'Migration roadmap': 'แผนการย้ายเวอร์ชัน',
  'Print / PDF': 'พิมพ์ / PDF', 'Re-scan': 'สแกนอีกครั้ง', 'Passed': 'ผ่าน', 'Failed': 'ไม่ผ่าน',
  'Why is this an issue?': 'ทำไมจึงเป็นปัญหา?', 'How to fix it': 'วิธีแก้ไข',
  'Noncompliant (legacy)': 'ไม่ถูกต้อง (โค้ดเดิม)', 'Compliant (modern)': 'ถูกต้อง (โค้ดใหม่)',
  'Documentation ↗': 'เอกสารอ้างอิง ↗', 'Detection pattern': 'รูปแบบที่ใช้ตรวจจับ', 'Applies to': 'ใช้กับไฟล์',
  'min / issue': 'นาที / ปัญหา', 'Deprecated in': 'เลิกใช้ในเวอร์ชัน', 'Behavior changed in': 'พฤติกรรมเปลี่ยนในเวอร์ชัน', 'Removed in': 'ถูกลบในเวอร์ชัน', 'Applies when target ≥': 'ใช้เมื่อเวอร์ชันเป้าหมาย ≥',
  'Why? How to fix →': 'ทำไม? แก้อย่างไร →',
  'Quality gate': 'เกณฑ์คุณภาพ', 'readiness': 'ความพร้อม',
  'Compatibility issues': 'ปัญหาความเข้ากันได้', 'Security issues': 'ปัญหาความปลอดภัย', 'Estimated effort': 'เวลาแก้ไขโดยประมาณ',
  'Files ready for PHP': 'ไฟล์ที่พร้อมสำหรับ PHP', 'Written for PHP ≥': 'เขียนสำหรับ PHP ≥', 'breaks on PHP': 'ใช้ไม่ได้บน PHP',
  'Issues by severity': 'ปัญหาตามระดับความรุนแรง', 'issues': 'ปัญหา', 'Breaking points by PHP version': 'จุดที่ใช้ไม่ได้ตามเวอร์ชัน PHP',
  'removed': 'ถูกลบ', 'changed': 'เปลี่ยน', 'deprecated': 'เลิกใช้',
  'Top rules': 'กฎที่พบบ่อยที่สุด', 'All issues →': 'ปัญหาทั้งหมด →', 'Rule': 'กฎ', 'Severity': 'ความรุนแรง', 'Effort': 'เวลาแก้', 'Total': 'รวม',
  'Files with most issues': 'ไฟล์ที่มีปัญหามากที่สุด', 'Browse code →': 'ดูโค้ด →', 'File': 'ไฟล์', 'Blocker': 'Blocker', 'Critical': 'Critical',
  'Recommendations': 'คำแนะนำ', 'Project metrics': 'ข้อมูลโปรเจกต์', 'Modern syntax detected': 'ไวยากรณ์สมัยใหม่ที่พบ',
  'No version-specific issues 🎉': 'ไม่พบปัญหาที่ขึ้นกับเวอร์ชัน 🎉', 'No issues': 'ไม่มีปัญหา',
  'Type': 'ประเภท', 'PHP version': 'เวอร์ชัน PHP', 'Directory': 'โฟลเดอร์', 'Category': 'หมวดหมู่', 'clear': 'ล้าง',
  'Search message, file or code…': 'ค้นหาข้อความ ไฟล์ หรือโค้ด…', 'Reset filters': 'ล้างตัวกรอง', 'effort': 'เวลาแก้',
  'Show more': 'แสดงเพิ่ม', 'remaining': 'ที่เหลือ', 'not version-specific': 'ไม่ขึ้นกับเวอร์ชัน',
  'No issues 🎉': 'ไม่มีปัญหา 🎉', 'Nothing matches the current filters.': 'ไม่มีรายการที่ตรงกับตัวกรอง',
  'Filter files…': 'กรองไฟล์…', 'Select a file': 'เลือกไฟล์', 'lines': 'บรรทัด', 'issue(s)': 'ปัญหา',
  'Search rules… (e.g. mysql, each, nullable)': 'ค้นหากฎ… (เช่น mysql, each, nullable)', 'All categories': 'ทุกหมวดหมู่', 'All versions': 'ทุกเวอร์ชัน', 'shown': 'รายการ', 'rules': 'กฎ', 'No rules match': 'ไม่พบกฎที่ตรงกัน',
  'Project folder': 'โฟลเดอร์โปรเจกต์', 'Browse…': 'เลือก…', 'Local folder': 'โฟลเดอร์ในเครื่อง', 'Upload .zip': 'อัปโหลด .zip',
  'Project name (optional)': 'ชื่อโปรเจกต์ (ไม่บังคับ)', 'Target PHP version': 'เวอร์ชัน PHP เป้าหมาย', 'Rule categories': 'หมวดหมู่กฎ',
  'Advanced options': 'ตัวเลือกขั้นสูง', 'Excluded folders': 'โฟลเดอร์ที่ไม่ต้องสแกน', 'Max file size (KB)': 'ขนาดไฟล์สูงสุด (KB)',
  'Start analysis': 'เริ่มวิเคราะห์', 'Try the sample project': 'ลองสแกนโปรเจกต์ตัวอย่าง', 'What is analyzed?': 'ตรวจอะไรบ้าง?',
  'Analyzing project': 'กำลังวิเคราะห์โปรเจกต์', 'Choose project folder': 'เลือกโฟลเดอร์โปรเจกต์', 'Select': 'เลือก',
  'Scan your first PHP project': 'สแกนโปรเจกต์ PHP แรกของคุณ', 'scan(s)': 'การสแกน',
  'Compat.': 'เข้ากันได้', 'Maint.': 'ดูแลรักษา', 'Ready': 'พร้อม', 'Lines': 'บรรทัด',
  'Recommended tooling': 'เครื่องมือที่แนะนำ', 'nothing to fix': 'ไม่มีสิ่งที่ต้องแก้', 'issue(s) ': 'ปัญหา',
  'Scan a project': 'สแกนโปรเจกต์', 'Browse rules': 'ดูกฎทั้งหมด',
  'Files analyzed': 'จำนวนไฟล์ที่วิเคราะห์', 'Lines / lines of code': 'บรรทัดทั้งหมด / บรรทัดโค้ด', 'Classes / interfaces / traits': 'คลาส / interface / trait',
  'Files using namespaces': 'ไฟล์ที่ใช้ namespace', 'Files with strict_types': 'ไฟล์ที่ใช้ strict_types', 'include / require statements': 'คำสั่ง include / require',
};
const t = (s) => (LANG === 'th' && I18N_TH[s]) || s;
/** Rule text in the current language (title / description / fix). */
const rt = (r, field) => (LANG === 'th' && r && r.th && r.th[field]) || (r && r[field]) || '';
function setLang(l) {
  LANG = l;
  try { localStorage.setItem(LANG_KEY, l); } catch { /* ignore */ }
  applyStaticLang();
  render();
}
function applyStaticLang() {
  document.documentElement.lang = LANG;
  $$('.lang-switch button').forEach((b) => b.classList.toggle('active', b.dataset.lang === LANG));
  const navText = { home: 'Projects', new: 'New scan', rules: 'Rules', guide: 'Migration guide' };
  $$('.topnav a').forEach((a) => { a.textContent = t(navText[a.dataset.nav]); });
}
$$('.lang-switch button').forEach((b) => b.onclick = () => setLang(b.dataset.lang));

const CAT_EN = { compatibility: 'Compatibility', security: 'Security', 'best-practice': 'Best practice' };
const STATUS_EN = { removed: 'Removed', changed: 'Behavior change', deprecated: 'Deprecated', vulnerability: 'Vulnerability', 'code-smell': 'Code smell', issue: 'Issue' };
const CAT_LABEL = new Proxy(CAT_EN, { get: (o, k) => (k in o ? t(o[k]) : undefined) });
const STATUS_LABEL = new Proxy(STATUS_EN, { get: (o, k) => (k in o ? t(o[k]) : undefined) });
const vnum = (s) => { const [a, b = '0'] = String(s).split('.'); return +a * 100 + +b; };
const fmtDebt = (min) => { const d = Math.floor(min / 480), h = Math.floor((min % 480) / 60), m = min % 60; return d ? `${d}d ${h}h` : h ? `${h}h ${m}min` : `${m}min`; };
const timeAgo = (iso) => {
  const s = (Date.now() - new Date(iso)) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + ' min ago';
  if (s < 86400) return Math.floor(s / 3600) + ' h ago';
  return new Date(iso).toLocaleString();
};

async function api(url, opts) {
  const r = await fetch(url, opts);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

const state = { info: null, rules: null, ruleMap: {}, scans: {}, codeCache: {} };

async function getRules() {
  if (!state.rules) {
    state.rules = await api('/api/rules');
    state.ruleMap = Object.fromEntries(state.rules.map((r) => [r.id, r]));
  }
  return state.rules;
}
async function getScan(id) {
  if (!state.scans[id]) state.scans[id] = await api('/api/scans/' + encodeURIComponent(id));
  return state.scans[id];
}

// ---------------------------------------------------------------- modal
function openModal(title, html, onClose) {
  $('#modal-title').textContent = title;
  $('#modal-body').innerHTML = html;
  $('#modal').classList.remove('hidden');
  state.modalClose = onClose || null;
}
function closeModal() {
  $('#modal').classList.add('hidden');
  if (state.modalClose) state.modalClose();
  state.modalClose = null;
}
$('#modal-close').onclick = closeModal;
$('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('#modal').classList.contains('hidden')) closeModal(); });

// ---------------------------------------------------------------- router
function parseHash() {
  const h = location.hash.replace(/^#\/?/, '');
  const [p, q = ''] = h.split('?');
  return { parts: p.split('/').filter(Boolean).map(decodeURIComponent), query: Object.fromEntries(new URLSearchParams(q)) };
}
function go(path, query) {
  const qs = query ? new URLSearchParams(Object.entries(query).filter(([, v]) => v !== '' && v != null)).toString() : '';
  location.hash = '#/' + path + (qs ? '?' + qs : '');
}

async function render() {
  const { parts, query } = parseHash();
  const app = $('#app');
  const nav = parts[0] === 'scan' ? 'home' : parts[0] || 'home';
  $$('.topnav a').forEach((a) => a.classList.toggle('active', a.dataset.nav === nav));
  try {
    if (!state.info) state.info = await api('/api/info');
    if (!parts.length) return await pageHome(app);
    if (parts[0] === 'new') return pageNew(app);
    if (parts[0] === 'rules') return await pageRules(app, query);
    if (parts[0] === 'guide') return pageGuide(app);
    if (parts[0] === 'scan' && parts[1]) {
      const scan = await getScan(parts[1]);
      await getRules();
      const tab = parts[2] || 'overview';
      app.innerHTML = projectHeader(scan, tab) + '<div id="tab"></div>';
      const el = $('#tab');
      if (tab === 'overview') return pageOverview(el, scan);
      if (tab === 'issues') return pageIssues(el, scan, query);
      if (tab === 'code') return pageCode(el, scan, query);
      if (tab === 'roadmap') return pageRoadmap(el, scan);
    }
    app.innerHTML = '<div class="empty"><h2>Page not found</h2><a href="#/">Back to projects</a></div>';
  } catch (e) {
    app.innerHTML = `<div class="error-box">${esc(e.message)}</div><a href="#/">Back to projects</a>`;
  }
}
window.addEventListener('hashchange', () => { render(); });

// ---------------------------------------------------------------- shared bits
const ratingBadge = (r, lg) => `<span class="rating ${r}${lg ? ' lg' : ''}" title="Rating ${r}">${r}</span>`;
const sevBadge = (s) => `<span class="sev ${s}">${s}</span>`;
const issuesLink = (id, q, text) => `<a href="#/scan/${encodeURIComponent(id)}/issues?${new URLSearchParams(q)}">${text}</a>`;

function projectHeader(scan, tab) {
  const s = scan.summary, m = s.meta;
  const tab_ = (k, label) => `<a class="${tab === k ? 'active' : ''}" href="#/scan/${encodeURIComponent(m.id)}/${k}">${label}</a>`;
  return `
  <div class="proj-head">
    <div class="row wrap">
      <h1 style="margin:0">${esc(m.label || m.name)}</h1>
      <span class="gate ${s.qualityGate.status}">${s.qualityGate.status === 'PASSED' ? '✓ ' + t('Passed') : '✕ ' + t('Failed')}</span>
      <span class="tag ver">Target PHP ${esc(m.target)}</span>
      <span class="spacer"></span>
      <a class="btn sm" href="/api/scans/${encodeURIComponent(m.id)}/export.csv">⬇ CSV</a>
      <a class="btn sm" href="/api/scans/${encodeURIComponent(m.id)}/export.json">⬇ JSON</a>
      <button class="btn sm" onclick="window.print()">🖨 ${t('Print / PDF')}</button>
      <button class="btn sm" id="rescan">↻ ${t('Re-scan')}</button>
    </div>
    <div class="proj-meta" style="margin-top:6px">
      <span title="${esc(m.root)}">📁 ${esc(m.root)}</span>
      <span>🕒 ${esc(timeAgo(m.startedAt))}</span>
      <span>⏱ ${(m.durationMs / 1000).toFixed(1)} s</span>
      <span>${fmt(s.metrics.files)} files · ${fmt(s.metrics.ncloc)} lines of code</span>
      <span>${m.rulesCount} rules</span>
    </div>
    <div class="tabs">
      ${tab_('overview', t('Overview'))}${tab_('issues', `${t('Issues')} (${fmt(s.totals.issues)})`)}${tab_('code', t('Code'))}${tab_('roadmap', t('Migration roadmap'))}
    </div>
  </div>`;
}

document.addEventListener('click', async (e) => {
  if (e.target.id === 'rescan') {
    const { parts } = parseHash();
    const scan = state.scans[parts[1]];
    if (!scan) return;
    const m = scan.summary.meta;
    startScan({ path: m.root, target: m.target, exclude: m.excludes.join(','), categories: m.categories.join(','), label: m.label });
  }
  const ruleLink = e.target.closest('[data-rule]');
  if (ruleLink) { e.preventDefault(); showRule(ruleLink.dataset.rule); }
});

async function showRule(id) {
  await getRules();
  const r = state.ruleMap[id];
  if (!r) return;
  openModal(rt(r, 'title'), ruleDetailHtml(r));
}

function versionChain(r) {
  const parts = [];
  if (r.deprecated) parts.push(`<span class="tag deprecated">${t('Deprecated in')} ${r.deprecated}</span>`);
  if (r.changed) parts.push(`<span class="tag changed">${t('Behavior changed in')} ${r.changed}</span>`);
  if (r.removed) parts.push(`<span class="tag removed">${t('Removed in')} ${r.removed}</span>`);
  if (r.minTarget) parts.push(`<span class="tag">${t('Applies when target ≥')} ${r.minTarget}</span>`);
  return parts.join('');
}

function ruleDetailHtml(r) {
  return `
    <div class="row wrap" style="gap:8px">
      <span class="mono muted">${esc(r.id)}</span>
      <span class="tag ${r.category}">${CAT_LABEL[r.category]}</span>
      ${sevBadge(r.severity)}
      <span class="tag">⏱ ${r.effort} ${t('min / issue')}</span>
    </div>
    ${LANG === 'th' ? `<div class="th-line" style="margin-top:6px">${esc(r.title)}</div>` : ''}
    <div class="ver-chain">${versionChain(r)}</div>
    <h4>${t('Why is this an issue?')}</h4>
    <p>${esc(rt(r, 'description'))}</p>
    <h4>${t('How to fix it')}</h4>
    <p>${esc(rt(r, 'fix'))}</p>
    <div class="compare">
      <div class="bad"><h4>✕ ${t('Noncompliant (legacy)')}</h4><pre>${esc(r.before)}</pre></div>
      <div class="good"><h4>✓ ${t('Compliant (modern)')}</h4><pre>${esc(r.after)}</pre></div>
    </div>
    <p class="small muted" style="margin-top:14px">${t('Applies to')}: ${r.fileTypes.join(', ')} ·
      ${r.docs ? `<a href="${esc(r.docs)}" target="_blank" rel="noopener">${t('Documentation ↗')}</a>` : ''}</p>
    <details class="small"><summary class="muted">${t('Detection pattern')}</summary><pre>${esc(r.pattern)}</pre></details>`;
}

// ---------------------------------------------------------------- home
async function pageHome(app) {
  const list = await api('/api/scans');
  if (!list.length) {
    app.innerHTML = `
      <div class="panel empty">
        <div class="logo" style="width:80px;height:50px;font-size:24px;margin:0 auto 16px">php</div>
        <h2>${t('Scan your first PHP project')}</h2>
        <p>Find removed and deprecated features, behavior changes, security issues and best-practice<br>
          violations when upgrading a PHP 5.x application to PHP 7.x / 8.x.</p>
        <p><a class="btn primary" href="#/new">＋ ${t('New scan')}</a></p>
        <p class="small">${state.info.rules} rules · PHP 5.3 → 8.5</p>
      </div>`;
    return;
  }
  app.innerHTML = `
    <div class="hero"><h1>${t('Projects')}</h1><span class="muted">${list.length} ${t('scan(s)')}</span><span class="spacer"></span><a class="btn primary" href="#/new">＋ ${t('New scan')}</a></div>
    ${list.map((p) => `
      <div class="panel project-card">
        <div>
          <h3><a href="#/scan/${encodeURIComponent(p.id)}">${esc(p.label || p.root)}</a>
            <span class="gate ${p.gate}" style="margin-left:8px">${p.gate === 'PASSED' ? t('Passed') : t('Failed')}</span></h3>
          <div class="proj-meta"><span>📁 ${esc(p.root)}</span><span>Target PHP ${esc(p.target)}</span><span>${esc(timeAgo(p.startedAt))}</span></div>
          <div class="bar" style="margin-top:10px;max-width:420px">${SEV.map((s) => `<i style="width:${p.issues ? (p.bySeverity[s] / p.issues) * 100 : 0}%;background:${SEV_COLOR[s]}" title="${s}: ${p.bySeverity[s]}"></i>`).join('')}</div>
        </div>
        <div class="measures">
          <div class="measure"><div class="v">${ratingBadge(p.ratings.compatibility)}</div><div class="l">${t('Compat.')}</div></div>
          <div class="measure"><div class="v">${ratingBadge(p.ratings.security)}</div><div class="l">${t('Security')}</div></div>
          <div class="measure"><div class="v">${ratingBadge(p.ratings.maintainability)}</div><div class="l">${t('Maint.')}</div></div>
          <div class="measure"><div class="v">${fmt(p.issues)}</div><div class="l">${t('Issues')}</div></div>
          <div class="measure"><div class="v">${esc(p.debt)}</div><div class="l">${t('Effort')}</div></div>
          <div class="measure"><div class="v">${p.readiness}%</div><div class="l">${t('Ready')}</div></div>
          <div class="measure"><div class="v">${fmt(p.ncloc)}</div><div class="l">${t('Lines')}</div></div>
          <button class="icon-btn" title="Delete scan" data-del="${esc(p.id)}">🗑</button>
        </div>
      </div>`).join('')}`;
  $$('[data-del]', app).forEach((b) => b.onclick = async () => {
    b.disabled = true;
    await api('/api/scans/' + encodeURIComponent(b.dataset.del), { method: 'DELETE' });
    delete state.scans[b.dataset.del];
    render();
  });
}

// ---------------------------------------------------------------- new scan
function pageNew(app) {
  const targets = state.info.targets;
  const saved = (() => { try { return JSON.parse(localStorage.getItem('pma-new') || '{}'); } catch { return {}; } })();
  app.innerHTML = `
  <h1>${t('New scan')}</h1>
  <div class="new-layout">
    <div class="panel">
      <div class="tabs" id="src-tabs">
        <button data-src="folder" class="active">📁 ${t('Local folder')}</button>
        <button data-src="upload">⬆ ${t('Upload .zip')}</button>
      </div>
      <div data-pane="folder">
        <label class="field"><span>${t('Project folder')}</span>
          <div class="row"><input type="text" id="path" placeholder="${state.info.platform === 'win32' ? 'D:\\www\\my-legacy-app' : '/var/www/my-legacy-app'}" value="${esc(saved.path || '')}">
          <button class="btn" id="browse" type="button">${t('Browse…')}</button></div>
          <div class="hint">Absolute path of the PHP project on this machine (the server reads it directly — nothing is uploaded).</div>
        </label>
      </div>
      <div data-pane="upload" class="hidden">
        <div class="dropzone" id="drop">
          <div style="font-size:28px">⬆</div>
          <div><b>Drop a .zip of your project here</b> or click to choose</div>
          <div class="hint" id="zipname">Only .php/.inc/.phtml, composer.json, .htaccess and .ini files are extracted.</div>
          <input type="file" id="zip" accept=".zip" class="hidden">
        </div>
      </div>

      <label class="field" style="margin-top:16px"><span>${t('Project name (optional)')}</span>
        <input type="text" id="label" placeholder="e.g. Shop backend" value="${esc(saved.label || '')}"></label>

      <div class="field"><span style="font-weight:600;display:block;margin-bottom:6px">${t('Target PHP version')}</span>
        <div class="target-grid">${targets.map((t) => `<label><input type="radio" name="target" value="${t}" ${t === (saved.target || '8.4') ? 'checked' : ''}>PHP ${t}</label>`).join('')}</div>
        <div class="hint">Rules are evaluated against this version: features removed at or before it are blockers, deprecations become warnings.</div>
      </div>

      <div class="field"><span style="font-weight:600;display:block;margin-bottom:6px">${t('Rule categories')}</span>
        <div class="checks">
          ${['compatibility', 'security', 'best-practice'].map((c) => `<label><input type="checkbox" name="cat" value="${c}" ${!saved.categories || saved.categories.includes(c) ? 'checked' : ''}> ${CAT_LABEL[c]}</label>`).join('')}
        </div>
      </div>

      <details ${saved.exclude ? 'open' : ''}><summary style="cursor:pointer;font-weight:600">${t('Advanced options')}</summary>
        <label class="field" style="margin-top:10px"><span>${t('Excluded folders')}</span>
          <textarea id="exclude" rows="3">${esc(saved.exclude || state.info.defaultExcludes.join(', '))}</textarea>
          <div class="hint">Comma separated folder names or relative paths (e.g. vendor, cache, lib/legacy-pear). Third-party code in vendor/ is usually upgraded through Composer instead.</div>
        </label>
        <label class="field"><span>${t('Max file size (KB)')}</span><input type="text" id="maxkb" value="${esc(saved.maxkb || 1024)}" style="max-width:140px"></label>
      </details>

      <div id="new-err"></div>
      <div class="row" style="margin-top:12px"><button class="btn primary" id="start">▶ ${t('Start analysis')}</button>
        <button class="btn" id="sample" type="button" title="Scan the bundled sample legacy app">${t('Try the sample project')}</button></div>
    </div>

    <div class="panel">
      <h3>${t('What is analyzed?')}</h3>
      <ul style="padding-left:18px;margin:0">
        <li><b>Removed features</b> — mysql_*, ereg, mcrypt, each(), create_function(), PHP 4 constructors, magic quotes, register_globals…</li>
        <li><b>Behavior changes</b> — string/number comparison, concatenation precedence, uniform variable syntax, nested ternary…</li>
        <li><b>Deprecations</b> 7.x → 8.5 — dynamic properties, utf8_encode, \${} interpolation, implicit nullable types…</li>
        <li><b>Config</b> — php.ini / .htaccess directives, composer.json constraints & abandoned packages.</li>
        <li><b>Security</b> — SQL injection, XSS, file inclusion, command injection, weak hashing…</li>
        <li><b>Best practices</b> — PSR-12 visibility, short arrays, ??, str_contains, debug output…</li>
      </ul>
      <p class="small muted">Analysis is static (no code is executed). Comments and string contents are ignored where appropriate to avoid false positives.</p>
      <p><a href="#/rules">Browse all ${state.info.rules} rules →</a></p>
    </div>
  </div>`;

  let src = 'folder';
  let zipFile = null;
  $$('#src-tabs button').forEach((b) => b.onclick = () => {
    src = b.dataset.src;
    $$('#src-tabs button').forEach((x) => x.classList.toggle('active', x === b));
    $$('[data-pane]').forEach((p) => p.classList.toggle('hidden', p.dataset.pane !== src));
  });
  const drop = $('#drop');
  drop.onclick = () => $('#zip').click();
  $('#zip').onchange = (e) => { zipFile = e.target.files[0]; $('#zipname').textContent = zipFile ? `${zipFile.name} (${(zipFile.size / 1048576).toFixed(1)} MB)` : ''; };
  drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('drag'); };
  drop.ondragleave = () => drop.classList.remove('drag');
  drop.ondrop = (e) => {
    e.preventDefault(); drop.classList.remove('drag');
    zipFile = e.dataTransfer.files[0];
    $('#zipname').textContent = zipFile ? `${zipFile.name} (${(zipFile.size / 1048576).toFixed(1)} MB)` : '';
  };
  $('#browse').onclick = () => folderPicker($('#path').value, (p) => { $('#path').value = p; });

  const collect = () => ({
    target: ($('input[name=target]:checked') || {}).value || '8.4',
    categories: $$('input[name=cat]:checked').map((c) => c.value).join(','),
    exclude: $('#exclude').value,
    maxFileSizeKB: $('#maxkb').value,
    label: $('#label').value.trim(),
  });

  $('#start').onclick = () => {
    const o = collect();
    $('#new-err').innerHTML = '';
    if (!o.categories) return ($('#new-err').innerHTML = '<div class="error-box">Select at least one rule category.</div>');
    try { localStorage.setItem('pma-new', JSON.stringify({ path: $('#path').value, label: o.label, target: o.target, categories: o.categories.split(','), exclude: o.exclude, maxkb: o.maxFileSizeKB })); } catch { /* ignore */ }
    if (src === 'folder') {
      const p = $('#path').value.trim();
      if (!p) return ($('#new-err').innerHTML = '<div class="error-box">Enter the project folder.</div>');
      startScan({ ...o, path: p });
    } else {
      if (!zipFile) return ($('#new-err').innerHTML = '<div class="error-box">Choose a .zip file.</div>');
      startUpload(zipFile, o);
    }
  };
  $('#sample').onclick = async () => {
    const o = collect();
    startScan({ ...o, path: 'samples/legacy-shop', label: o.label || 'Sample: legacy-shop' });
  };
}

function folderPicker(start, onPick) {
  openModal(t('Choose project folder'), '<div id="fs"></div>');
  const load = async (dir) => {
    const box = $('#fs');
    if (!box) return;
    try {
      const r = await api('/api/fs?dir=' + encodeURIComponent(dir || ''));
      box.innerHTML = `
        <div class="row" style="margin-bottom:10px"><input type="text" id="fs-cur" value="${esc(r.dir)}" readonly>
          <button class="btn primary" id="fs-pick" ${r.dir ? '' : 'disabled'}>${t('Select')}</button></div>
        ${r.dir ? `<div class="hint" style="margin-bottom:8px">${r.phpCount || 0} PHP file(s) directly in this folder</div>` : ''}
        <div class="fs-list">
          ${r.parent !== null && r.parent !== undefined ? `<div class="fs-item" data-p="${esc(r.parent)}">⬆ ..</div>` : ''}
          ${r.dirs.map((d) => `<div class="fs-item" data-p="${esc(d.path)}">📁 ${esc(d.name)}</div>`).join('') || '<div class="fs-item muted">No sub-folders</div>'}
        </div>`;
      $$('.fs-item[data-p]', box).forEach((it) => it.onclick = () => load(it.dataset.p));
      $('#fs-pick', box).onclick = () => { onPick(r.dir); closeModal(); };
    } catch (e) {
      box.innerHTML = `<div class="error-box">${esc(e.message)}</div><button class="btn" id="fs-root">Go to top</button>`;
      $('#fs-root').onclick = () => load('');
    }
  };
  load(start);
}

async function startScan(body) {
  showProgress();
  try {
    const { jobId } = await api('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    pollJob(jobId);
  } catch (e) { progressError(e.message); }
}

function startUpload(file, o) {
  showProgress('Uploading archive…');
  const fd = new FormData();
  fd.append('archive', file);
  Object.entries(o).forEach(([k, v]) => fd.append(k, v));
  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/upload');
  xhr.upload.onprogress = (e) => {
    if (!e.lengthComputable) return;
    const pct = Math.round((e.loaded / e.total) * 100);
    const bar = $('#pbar');
    if (bar) { bar.classList.remove('indeterminate'); bar.firstElementChild.style.width = pct + '%'; }
    $('#ptext') && ($('#ptext').textContent = `Uploading… ${pct}%`);
    if (pct === 100) $('#ptext') && ($('#ptext').textContent = 'Extracting archive…');
  };
  xhr.onload = () => {
    let j = {};
    try { j = JSON.parse(xhr.responseText); } catch { /* ignore */ }
    if (xhr.status >= 400 || !j.jobId) return progressError(j.error || 'Upload failed');
    pollJob(j.jobId);
  };
  xhr.onerror = () => progressError('Upload failed');
  xhr.send(fd);
}

function showProgress(text) {
  openModal(t('Analyzing project'), `
    <div id="ptext">${esc(text || 'Collecting files…')}</div>
    <div class="pbar indeterminate" id="pbar"><i style="width:0"></i></div>
    <div class="small muted mono" id="pfile" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">&nbsp;</div>
    <div id="perr"></div>`, () => { state.polling = null; });
}
function progressError(msg) {
  const el = $('#perr');
  if (el) el.innerHTML = `<div class="error-box">${esc(msg)}</div>`;
  const bar = $('#pbar');
  if (bar) bar.classList.add('hidden');
}
function pollJob(jobId) {
  state.polling = jobId;
  const tick = async () => {
    if (state.polling !== jobId) return;
    try {
      const j = await api('/api/jobs/' + jobId);
      const p = j.progress || {};
      const bar = $('#pbar');
      if (p.phase === 'analyzing' && p.total) {
        bar.classList.remove('indeterminate');
        bar.firstElementChild.style.width = Math.round((p.done / p.total) * 100) + '%';
        $('#ptext').textContent = `Analyzing ${fmt(p.done)} / ${fmt(p.total)} files…`;
        $('#pfile').textContent = p.current || '';
      } else if (p.phase === 'reporting') {
        $('#ptext').textContent = 'Building report…';
        bar.firstElementChild.style.width = '100%';
      } else if (p.phase === 'collecting') {
        $('#ptext').textContent = 'Collecting files…';
      }
      if (j.status === 'done') {
        state.polling = null;
        closeModal();
        delete state.scans[j.scanId];
        go('scan/' + j.scanId);
        return;
      }
      if (j.status === 'error') return progressError(j.error);
      setTimeout(tick, 400);
    } catch (e) { progressError(e.message); }
  };
  tick();
}

// ---------------------------------------------------------------- overview
function pageOverview(el, scan) {
  const s = scan.summary, id = s.meta.id;
  const cat = (c) => s.byCategory[c] || { total: 0, blocker: 0, critical: 0, major: 0, minor: 0, info: 0, debt: 0 };
  const compat = cat('compatibility'), sec = cat('security'), bp = cat('best-practice');
  const total = s.totals.issues || 1;
  let acc = 0;
  const donut = SEV.map((sv) => { const a = acc; acc += (s.bySeverity[sv] / total) * 360; return `${SEV_COLOR[sv]} ${a}deg ${acc}deg`; }).join(',');
  const versions = s.byVersion;
  const maxV = Math.max(1, ...versions.map((v) => v.removed + v.changed + v.deprecated));
  const m = s.metrics;
  const pct = (a, b) => (b ? Math.round((a / b) * 100) : 0);

  const recs = [];
  if (compat.blocker + compat.critical) recs.push(`Fix <b>${fmt(compat.blocker + compat.critical)}</b> blocker/critical compatibility issues first — the application will not run on PHP ${esc(s.meta.target)} until they are resolved. See the ${`<a href="#/scan/${encodeURIComponent(id)}/roadmap">migration roadmap</a>`}.`);
  if (sec.blocker + sec.critical) recs.push(`<b>${fmt(sec.blocker + sec.critical)}</b> serious security issues found. Legacy code that relied on <code>magic_quotes_gpc</code> becomes injectable after migration — fix SQL injection with prepared statements.`);
  if (m.phpFiles && pct(m.namespacedFiles, m.phpFiles) < 50) recs.push(`Only ${pct(m.namespacedFiles, m.phpFiles)}% of files use namespaces. Introduce namespaces and <b>Composer PSR-4 autoloading</b> to replace ${fmt(m.includes)} manual include/require statements.`);
  if (!m.hasComposer) recs.push('No <code>composer.json</code> found. Use Composer to manage dependencies (PHPMailer, PDF libraries, …) instead of copying them into the project.');
  if (m.phpFiles && pct(m.strictTypesFiles, m.phpFiles) < 20) recs.push(`${pct(m.strictTypesFiles, m.phpFiles)}% of files declare <code>strict_types=1</code>. Add scalar/return types gradually and enable strict types in new code.`);
  recs.push('Automate mechanical fixes with <b>Rector</b> (<code>vendor/bin/rector process src --dry-run</code>) and verify with <b>PHPStan</b> and <code>php -l</code> on the target version.');

  el.innerHTML = `
  <div class="gate-banner ${s.qualityGate.status}">
    <div><div class="small" style="opacity:.85;text-transform:uppercase;letter-spacing:.05em">${t('Quality gate')} · PHP ${esc(s.meta.target)} ${t('readiness')}</div>
      <div class="big">${s.qualityGate.status === 'PASSED' ? 'PASSED' : 'FAILED'}</div></div>
    <ul>${s.qualityGate.conditions.map((c) => `<li class="${c.ok ? '' : 'bad'}">${esc(c.metric)}: <b>${esc(c.actual)}</b> (required ${c.op} ${esc(c.threshold)})</li>`).join('')}</ul>
  </div>

  <div class="grid g4" style="margin-top:16px">
    <div class="panel">
      <div class="kpi">${ratingBadge(s.ratings.compatibility, true)}<div><div class="val">${fmt(compat.total)}</div><div class="lbl">${t('Compatibility issues')}</div></div></div>
      <div class="kpi-sub">${['blocker', 'critical', 'major'].map((sv) => issuesLink(id, { category: 'compatibility', severity: sv }, `${sevBadge(sv)} ${fmt(compat[sv])}`)).join('')}</div>
    </div>
    <div class="panel">
      <div class="kpi">${ratingBadge(s.ratings.security, true)}<div><div class="val">${fmt(sec.total)}</div><div class="lbl">${t('Security issues')}</div></div></div>
      <div class="kpi-sub">${['blocker', 'critical', 'major'].map((sv) => issuesLink(id, { category: 'security', severity: sv }, `${sevBadge(sv)} ${fmt(sec[sv])}`)).join('')}</div>
    </div>
    <div class="panel">
      <div class="kpi">${ratingBadge(s.ratings.maintainability, true)}<div><div class="val">${esc(s.totals.debt)}</div><div class="lbl">${t('Estimated effort')}</div></div></div>
      <div class="kpi-sub small muted">Debt ratio ${s.totals.debtRatio}% · ${issuesLink(id, { category: 'best-practice' }, fmt(bp.total) + ' best-practice issues')}</div>
    </div>
    <div class="panel">
      <div class="kpi"><div class="progress-ring" style="color:${s.readiness >= 90 ? 'var(--ok)' : s.readiness >= 50 ? 'var(--rc)' : 'var(--fail)'}">${s.readiness}%</div>
        <div><div class="lbl" style="margin-top:0">${t('Files ready for PHP')} ${esc(s.meta.target)}</div></div></div>
      <div class="kpi-sub small muted">${t('Written for PHP ≥')} ${esc(s.detected.minVersion)}${s.detected.breaksAt ? ` · ${t('breaks on PHP')} ${esc(s.detected.breaksAt)}+` : ''}</div>
    </div>
  </div>

  <div class="grid g3" style="margin-top:16px">
    <div class="panel">
      <h3>${t('Issues by severity')}</h3>
      <div class="row" style="gap:22px;align-items:center">
        <div class="donut" style="background:conic-gradient(${s.totals.issues ? donut : '#eef0f4 0 360deg'})"><span>${fmt(s.totals.issues)}<small>${t('issues')}</small></span></div>
        <div class="legend" style="flex:1">${SEV.map((sv) => `<a href="#/scan/${encodeURIComponent(id)}/issues?severity=${sv}">${sevBadge(sv)}<span class="cnt">${fmt(s.bySeverity[sv])}</span></a>`).join('')}</div>
      </div>
    </div>
    <div class="panel" style="grid-column: span 2">
      <div class="panel-title"><h3>${t('Breaking points by PHP version')}</h3>
        <span class="small muted"><span class="sev blocker">${t('removed')}</span> &nbsp;<span class="sev major">${t('changed')}</span> &nbsp;<span class="sev" style="color:#e5b800">${t('deprecated')}</span></span></div>
      ${versions.length ? `<div class="timeline">${versions.map((v) => {
        const t = v.removed + v.changed + v.deprecated;
        const h = (n) => (n / maxV) * 120;
        return `<a class="col" href="#/scan/${encodeURIComponent(id)}/issues?version=${v.version}" title="PHP ${v.version}: ${v.removed} removed, ${v.changed} changed, ${v.deprecated} deprecated">
          <div class="n">${t}</div>
          <div class="stack"><i style="height:${h(v.removed)}px;background:var(--blocker)"></i><i style="height:${h(v.changed)}px;background:var(--major)"></i><i style="height:${h(v.deprecated)}px;background:#e5b800"></i></div>
          <div class="lbl">${v.version}</div></a>`;
      }).join('')}</div>` : `<div class="empty">${t('No version-specific issues 🎉')}</div>`}
    </div>
  </div>

  <div class="grid g2" style="margin-top:16px">
    <div class="panel">
      <div class="panel-title"><h3>${t('Top rules')}</h3>${issuesLink(id, {}, t('All issues →'))}</div>
      <table class="list"><thead><tr><th>${t('Rule')}</th><th>${t('Severity')}</th><th class="num">${t('Issues')}</th><th class="num">${t('Effort')}</th></tr></thead><tbody>
      ${s.byRule.slice(0, 15).map((r) => `<tr>
        <td><a href="#/scan/${encodeURIComponent(id)}/issues?rule=${r.rule}">${esc(rt(state.ruleMap[r.rule], 'title') || r.title)}</a><div class="small muted mono">${r.rule}</div></td>
        <td>${sevBadge(r.severity)}</td><td class="num">${fmt(r.count)}</td><td class="num nowrap">${fmtDebt(r.debt)}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">No issues</td></tr>'}
      </tbody></table>
    </div>
    <div class="panel">
      <div class="panel-title"><h3>${t('Files with most issues')}</h3><a href="#/scan/${encodeURIComponent(id)}/code">${t('Browse code →')}</a></div>
      <table class="list"><thead><tr><th>${t('File')}</th><th class="num">Blocker</th><th class="num">Critical</th><th class="num">${t('Total')}</th></tr></thead><tbody>
      ${s.topFiles.slice(0, 15).map((f) => `<tr>
        <td class="mono" style="word-break:break-all"><a href="#/scan/${encodeURIComponent(id)}/code?file=${encodeURIComponent(f.file)}">${esc(f.file)}</a></td>
        <td class="num" style="color:${f.blocker ? 'var(--blocker)' : ''}">${f.blocker}</td><td class="num" style="color:${f.critical ? 'var(--critical)' : ''}">${f.critical}</td><td class="num">${f.total}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">No issues</td></tr>'}
      </tbody></table>
    </div>
  </div>

  <div class="grid g2" style="margin-top:16px">
    <div class="panel">
      <h3>${t('Recommendations')}</h3>
      <ol style="padding-left:20px;margin:0">${recs.map((r) => `<li style="margin:6px 0">${r}</li>`).join('')}</ol>
    </div>
    <div class="panel">
      <h3>${t('Project metrics')}</h3>
      <table class="list"><tbody>
        <tr><td>${t('Files analyzed')}</td><td class="num">${fmt(m.files)} (${fmt(m.phpFiles)} PHP)</td></tr>
        <tr><td>${t('Lines / lines of code')}</td><td class="num">${fmt(m.lines)} / ${fmt(m.ncloc)}</td></tr>
        <tr><td>${t('Classes / interfaces / traits')}</td><td class="num">${fmt(m.classes)}</td></tr>
        <tr><td>${t('Files using namespaces')}</td><td class="num">${pct(m.namespacedFiles, m.phpFiles)}%</td></tr>
        <tr><td>${t('Files with strict_types')}</td><td class="num">${pct(m.strictTypesFiles, m.phpFiles)}%</td></tr>
        <tr><td>${t('include / require statements')}</td><td class="num">${fmt(m.includes)}</td></tr>
        <tr><td>Composer</td><td class="num">${m.hasComposer ? 'yes' : 'no'}</td></tr>
      </tbody></table>
      <h4 style="margin-top:14px">${t('Modern syntax detected')}</h4>
      <div class="feature-list">${s.detected.features.map((f) => `<span class="tag" title="${f.files} file(s)">${esc(f.name)} · ${f.version}</span>`).join('') || '<span class="muted small">None — code base looks like PHP ≤ 5.2 style.</span>'}</div>
      ${s.meta.skipped.length ? `<details style="margin-top:12px"><summary class="small muted">${s.meta.skipped.length} file(s) skipped</summary><ul class="small mono">${s.meta.skipped.slice(0, 100).map((x) => `<li>${esc(x.file)} — ${esc(x.reason)}</li>`).join('')}</ul></details>` : ''}
      ${s.meta.truncated ? '<div class="error-box small">Issue list truncated at 100,000 issues. Narrow the scan with excluded folders.</div>' : ''}
    </div>
  </div>`;
}

// ---------------------------------------------------------------- issues
const FACETS = [
  { key: 'severity', label: 'Severity', get: (i) => i.severity, order: SEV, render: (v) => sevBadge(v) },
  { key: 'category', label: 'Category', get: (i) => i.category, render: (v) => `<span class="tag ${v}">${CAT_LABEL[v] || v}</span>` },
  { key: 'status', label: 'Type', get: (i) => i.status, render: (v) => `<span class="tag ${v}">${STATUS_LABEL[v] || v}</span>` },
  { key: 'version', label: 'PHP version', get: (i) => i.version || '—', sort: (a, b) => (a === '—' ? 1 : b === '—' ? -1 : vnum(a) - vnum(b)), render: (v) => (v === '—' ? `<span class="muted">${t('not version-specific')}</span>` : `PHP ${v}`) },
  { key: 'rule', label: 'Rule', get: (i) => i.rule, render: (v) => `<span class="lab" title="${esc(v)}">${esc(rt(state.ruleMap[v], 'title') || v)}</span>`, limit: 12 },
  { key: 'dir', label: 'Directory', get: (i) => (i.file.includes('/') ? i.file.slice(0, i.file.lastIndexOf('/')) : '(root)'), render: (v) => `<span class="lab mono" title="${esc(v)}">${esc(v)}</span>`, limit: 10 },
];

function pageIssues(el, scan, query) {
  const id = scan.summary.meta.id;
  const filters = {};
  for (const f of FACETS) if (query[f.key]) filters[f.key] = new Set(query[f.key].split(','));
  const file = query.file || '';
  const q = (query.q || '').toLowerCase();
  const pass = (i, except) => {
    for (const f of FACETS) {
      if (f.key === except) continue;
      if (filters[f.key] && !filters[f.key].has(f.get(i))) return false;
    }
    if (file && i.file !== file) return false;
    if (q && !(i.message.toLowerCase().includes(q) || i.file.toLowerCase().includes(q) || i.code.toLowerCase().includes(q))) return false;
    return true;
  };
  const filtered = scan.issues.filter((i) => pass(i));
  const debt = filtered.reduce((a, i) => a + i.effort, 0);
  const setQuery = (patch) => go(`scan/${id}/issues`, { ...query, ...patch });

  const facetHtml = FACETS.map((f) => {
    const counts = {};
    for (const i of scan.issues) if (pass(i, f.key)) { const k = f.get(i); counts[k] = (counts[k] || 0) + 1; }
    if (filters[f.key]) for (const k of filters[f.key]) counts[k] = counts[k] || 0;
    let keys = Object.keys(counts);
    if (f.order) keys = f.order.filter((k) => k in counts);
    else if (f.sort) keys.sort(f.sort);
    else keys.sort((a, b) => counts[b] - counts[a]);
    const showAll = query['all_' + f.key];
    const lim = f.limit && !showAll ? f.limit : Infinity;
    return `<div class="facet"><h4>${t(f.label)}${filters[f.key] ? `<a href="#" data-clear="${f.key}" class="small">${t('clear')}</a>` : ''}</h4>
      ${keys.slice(0, lim).map((k) => `<div class="facet-item ${filters[f.key] && filters[f.key].has(k) ? 'on' : ''} ${counts[k] ? '' : 'zero'}" data-facet="${f.key}" data-val="${esc(k)}">${f.render(k)}<span class="c">${fmt(counts[k])}</span></div>`).join('') || '<div class="small muted">—</div>'}
      ${keys.length > lim ? `<a href="#" class="small" data-more="${f.key}">Show ${keys.length - lim} more</a>` : ''}
    </div>`;
  }).join('');

  const PAGE = 150;
  let shown = 0;
  el.innerHTML = `
  <div class="issues-layout">
    <div class="panel facets">${facetHtml}</div>
    <div>
      <div class="toolbar">
        <input type="text" id="q" placeholder="${t('Search message, file or code…')}" value="${esc(query.q || '')}">
        ${file ? `<span class="chip" id="clear-file" title="Clear file filter">${esc(file)}</span>` : ''}
        <span class="spacer"></span>
        <b>${fmt(filtered.length)}</b> ${t('issues')} · <span class="muted">${t('effort')} ${fmtDebt(debt)}</span>
        ${Object.keys(filters).length || file || q ? `<button class="btn sm" id="reset">${t('Reset filters')}</button>` : ''}
      </div>
      <div id="issue-list"></div>
      <div style="text-align:center;margin:12px"><button class="btn hidden" id="more">${t('Show more')}</button></div>
    </div>
  </div>`;

  const list = $('#issue-list');
  const renderMore = () => {
    const slice = filtered.slice(shown, shown + PAGE);
    shown += slice.length;
    let html = '';
    let lastFile = null; // each page starts a new file group
    for (const i of slice) {
      if (i.file !== lastFile) {
        if (lastFile !== null) html += '</div>';
        html += `<div class="issue-file"><div class="issue-file-head"><a href="#/scan/${encodeURIComponent(id)}/code?file=${encodeURIComponent(i.file)}">${esc(i.file)}</a></div>`;
        lastFile = i.file;
      }
      html += issueCard(i, id);
    }
    if (slice.length) html += '</div>';
    list.insertAdjacentHTML('beforeend', html);
    $('#more').classList.toggle('hidden', shown >= filtered.length);
    $('#more').textContent = `${t('Show more')} (${fmt(filtered.length - shown)} ${t('remaining')})`;
  };
  if (!filtered.length) list.innerHTML = `<div class="panel empty"><h2>${t('No issues 🎉')}</h2><p>${t('Nothing matches the current filters.')}</p></div>`;
  else renderMore();
  $('#more').onclick = renderMore;

  $$('.facet-item', el).forEach((it) => it.onclick = (e) => {
    const k = it.dataset.facet, v = it.dataset.val;
    const cur = new Set(filters[k] || []);
    if (e.ctrlKey || e.metaKey) { cur.has(v) ? cur.delete(v) : cur.add(v); }
    else if (cur.size === 1 && cur.has(v)) cur.clear();
    else { cur.clear(); cur.add(v); }
    setQuery({ [k]: [...cur].join(',') });
  });
  $$('[data-clear]', el).forEach((a) => a.onclick = (e) => { e.preventDefault(); setQuery({ [a.dataset.clear]: '' }); });
  $$('[data-more]', el).forEach((a) => a.onclick = (e) => { e.preventDefault(); setQuery({ ['all_' + a.dataset.more]: '1' }); });
  let timer;
  $('#q').oninput = (e) => { clearTimeout(timer); timer = setTimeout(() => setQuery({ q: e.target.value }), 350); };
  if (query.q) { const qi = $('#q'); qi.focus(); qi.setSelectionRange(qi.value.length, qi.value.length); }
  $('#reset') && ($('#reset').onclick = () => go(`scan/${id}/issues`));
  $('#clear-file') && ($('#clear-file').onclick = () => setQuery({ file: '' }));
}

/** In Thai mode: show the Thai rule title + short fix under the (English) issue message. */
function thRuleLine(ruleId) {
  if (LANG !== 'th') return '';
  const r = state.ruleMap[ruleId];
  if (!r || !r.th) return '';
  return `<div class="th-line">🇹🇭 <b>${esc(r.th.title)}</b> — ${esc(r.th.fix)}</div>`;
}

function issueCard(i, id) {
  return `<div class="issue">
    <div class="issue-msg" onclick="location.hash='#/scan/${encodeURIComponent(id)}/code?file=${encodeURIComponent(i.file)}&line=${i.line}'">${esc(i.message)}</div>
    ${thRuleLine(i.rule)}
    <div class="issue-meta">
      ${sevBadge(i.severity)}
      <span class="tag ${i.status}">${STATUS_LABEL[i.status] || i.status}</span>
      ${i.version ? `<span class="tag ver">PHP ${esc(i.version)}</span>` : ''}
      <span class="tag ${i.category}">${CAT_LABEL[i.category]}</span>
      <a href="#" data-rule="${esc(i.rule)}" class="mono">${esc(i.rule)}</a>
      <span>L${i.line}</span>
      <span>⏱ ${i.effort} min</span>
      ${i.removedIn ? `<span>removed in ${esc(i.removedIn)}</span>` : ''}
    </div>
    ${i.code.trim() ? `<div class="issue-code mono">${esc(i.code)}</div>` : ''}
  </div>`;
}

// ---------------------------------------------------------------- code viewer
async function pageCode(el, scan, query) {
  const id = scan.summary.meta.id;
  const counts = {};
  const worst = {};
  for (const i of scan.issues) {
    counts[i.file] = (counts[i.file] || 0) + 1;
    if (!worst[i.file] || SEV.indexOf(i.severity) < SEV.indexOf(worst[i.file])) worst[i.file] = i.severity;
  }
  const files = scan.files.slice().sort((a, b) => (counts[b.file] || 0) - (counts[a.file] || 0) || a.file.localeCompare(b.file));
  const sel = query.file || (files.find((f) => counts[f.file]) || files[0] || {}).file;

  el.innerHTML = `
  <div class="code-layout">
    <div>
      <input type="text" id="ffilter" placeholder="${t('Filter files…')}" style="margin-bottom:8px">
      <div class="panel file-list" id="flist">
        ${files.map((f) => `<div class="file-row ${f.file === sel ? 'on' : ''}" data-f="${esc(f.file)}" title="${esc(f.file)}">
          <span class="p">${esc(f.file)}</span>
          ${counts[f.file] ? `<span class="cnt" style="background:${SEV_COLOR[worst[f.file]]}">${counts[f.file]}</span>` : '<span class="small muted">✓</span>'}
        </div>`).join('')}
      </div>
    </div>
    <div class="panel source" id="source"><div class="loading">Select a file</div></div>
  </div>`;

  $('#ffilter').oninput = (e) => {
    const v = e.target.value.toLowerCase();
    $$('#flist .file-row').forEach((r) => r.classList.toggle('hidden', !r.dataset.f.toLowerCase().includes(v)));
  };
  $$('#flist .file-row').forEach((r) => r.onclick = () => go(`scan/${id}/code`, { file: r.dataset.f }));
  const on = $('#flist .file-row.on');
  if (on) on.scrollIntoView({ block: 'nearest' });
  if (sel) await showSource(id, sel, parseInt(query.line, 10) || 0);
}

async function showSource(id, file, line) {
  const box = $('#source');
  box.innerHTML = '<div class="loading">Loading…</div>';
  const key = id + '|' + file;
  let data = state.codeCache[key];
  try {
    if (!data) data = state.codeCache[key] = await api(`/api/scans/${encodeURIComponent(id)}/file?path=${encodeURIComponent(file)}`);
  } catch (e) {
    box.innerHTML = `<div class="error-box" style="margin:14px">${esc(e.message)}</div>`;
    return;
  }
  const lines = highlightPhp(data.content, /\.(php\d?|phtml|inc|module|ctp|install|theme)$/i.test(file));
  const byLine = {};
  for (const i of data.issues) (byLine[i.line] = byLine[i.line] || []).push(i);
  let rows = '';
  for (let n = 1; n <= lines.length; n++) {
    const iss = byLine[n];
    rows += `<tr id="L${n}" class="${iss ? 'has-issue' : ''} ${n === line ? 'target' : ''}"><td class="ln">${n}</td><td class="mk"></td><td class="c">${lines[n - 1] || ' '}</td></tr>`;
    if (iss) {
      rows += `<tr class="issue-row"><td class="ln"></td><td class="mk"></td><td>${iss.map((i) => `
        <div class="inline-issue" style="border-left-color:${SEV_COLOR[i.severity]}">
          ${sevBadge(i.severity)}
          <div><div>${esc(i.message)}</div>${thRuleLine(i.rule)}
            <div class="small muted" style="margin-top:3px"><span class="tag ${i.status}">${STATUS_LABEL[i.status]}</span> ${i.version ? `<span class="tag ver">PHP ${esc(i.version)}</span>` : ''} · ${i.effort} min</div></div>
          <a href="#" class="act small" data-rule="${esc(i.rule)}">${t('Why? How to fix →')}</a>
        </div>`).join('')}</td></tr>`;
    }
  }
  box.innerHTML = `
    <div class="source-head"><span style="word-break:break-all">${esc(file)}</span><span class="muted nowrap">${lines.length} ${t('lines')} · ${data.issues.length} ${t('issue(s)')}</span></div>
    <div class="source-body"><table class="src"><tbody>${rows}</tbody></table></div>`;
  if (line) {
    const tr = $('#L' + line);
    if (tr) tr.scrollIntoView({ block: 'center' });
  }
}

const PHP_KW = new Set('abstract and array as break callable case catch class clone const continue declare default do echo else elseif empty enddeclare endfor endforeach endif endswitch endwhile enum extends final finally fn for foreach function global goto if implements include include_once instanceof insteadof interface isset list match namespace new or print private protected public readonly require require_once return static switch throw trait try unset use var while xor yield null true false self parent die exit'.split(' '));

/** Tiny PHP syntax highlighter → array of HTML strings (one per line). */
function highlightPhp(src, isPhp) {
  const toks = [];
  const push = (cls, text) => { if (text) toks.push([cls, text]); };
  if (!isPhp) { push('', src); return toLines(toks); }
  let i = 0, mode = 'html';
  const re = /(\/\*[\s\S]*?(?:\*\/|$)|\/\/.*?(?=\?>|\n|$)|#(?!\[).*?(?=\?>|\n|$))|('(?:[^'\\]|\\[\s\S])*'?|"(?:[^"\\]|\\[\s\S])*"?|<<<\s*['"]?(\w+)['"]?[\s\S]*?\n\s*\3\b)|(\$[A-Za-z_]\w*)|(\b\d+(?:\.\d+)?\b)|(\?>)|([A-Za-z_]\w*)(?=\s*\()|([A-Za-z_]\w*)/y;
  while (i < src.length) {
    if (mode === 'html') {
      const j = src.indexOf('<?', i);
      if (j === -1) { push('', src.slice(i)); break; }
      push('', src.slice(i, j));
      const tag = /^<\?(php|=)?/i.exec(src.slice(j, j + 5))[0];
      push('tok-t', tag);
      i = j + tag.length;
      mode = 'php';
      continue;
    }
    re.lastIndex = i;
    const m = re.exec(src);
    if (!m) { push('', src[i]); i++; continue; }
    if (m[1]) push('tok-c', m[1]);
    else if (m[2]) push('tok-s', m[2]);
    else if (m[4]) push('tok-v', m[4]);
    else if (m[5]) push('tok-n', m[5]);
    else if (m[6]) { push('tok-t', m[6]); mode = 'html'; }
    else if (m[7]) push(PHP_KW.has(m[7].toLowerCase()) ? 'tok-k' : 'tok-f', m[7]);
    else if (m[8]) push(PHP_KW.has(m[8].toLowerCase()) ? 'tok-k' : '', m[8]);
    i = re.lastIndex;
  }
  return toLines(toks);
}
function toLines(toks) {
  const lines = [''];
  for (const [cls, text] of toks) {
    const parts = text.split('\n');
    parts.forEach((p, k) => {
      if (k > 0) lines.push('');
      const t = esc(p.replace(/\r$/, ''));
      if (t) lines[lines.length - 1] += cls ? `<span class="${cls}">${t}</span>` : t;
    });
  }
  return lines;
}

// ---------------------------------------------------------------- roadmap & guide
const GUIDE = [
  {
    key: 'prepare', title: 'Prepare the migration', versions: [],
    items: [
      'Put the code under version control (git) and create a dedicated migration branch.',
      'Run the target PHP version locally (e.g. Docker <code>php:8.4-apache</code>) and keep the old version available to compare behaviour.',
      'Write characterisation / smoke tests for critical flows (login, checkout, reports). Even simple HTTP tests catch most regressions.',
      'Enable full error reporting in development: <code>error_reporting=E_ALL</code>, <code>display_errors=On</code>, <code>log_errors=On</code>.',
      'Inventory dependencies: PHP extensions (<code>php -m</code>), Composer packages, libraries copied into the project (old PHPMailer, FPDF, Smarty, PEAR…).',
    ],
    cmds: ['docker run --rm -v "$PWD":/app -w /app php:8.4-cli sh -c \'find . -name "*.php" -not -path "./vendor/*" -print0 | xargs -0 -n1 php -l | grep -v "No syntax errors"\''],
  },
  {
    key: '56', title: 'PHP 5.x → 5.6 — remove PHP 4 / register_globals era code', versions: ['5.3', '5.4', '5.5', '5.6'],
    items: [
      'Replace <code>$HTTP_GET_VARS</code> & co. with superglobals; remove <code>session_register()</code>.',
      'Remove call-time pass-by-reference <code>foo(&amp;$x)</code>.',
      'Stop relying on <code>register_globals</code> / <code>magic_quotes_gpc</code>: read input explicitly and use prepared statements.',
      'Replace short open tags <code>&lt;?</code> with <code>&lt;?php</code>; remove removed ini directives from .htaccess / php.ini.',
    ],
  },
  {
    key: '70', title: 'PHP 5.6 → 7.0 — the big break', versions: ['7.0'],
    items: [
      'Replace <b>mysql_*</b> with PDO or mysqli — usually the largest task. Introduce a small DB wrapper first, then switch to prepared statements.',
      'Replace <code>ereg*</code> / <code>split()</code> with <code>preg_*</code>; replace <code>preg_replace /e</code> with <code>preg_replace_callback()</code>.',
      'Remove ASP tags, <code>=&amp; new</code>; rename PHP 4 constructors to <code>__construct()</code>.',
      'Check uniform variable syntax (<code>$$a[\'b\']</code>, <code>$obj-&gt;$p[\'x\']</code>).',
      'Engine errors are now <code>Error</code> exceptions — global handlers must accept <code>Throwable</code>.',
    ],
  },
  {
    key: '74', title: 'PHP 7.0 → 7.4 — clean up deprecations', versions: ['7.1', '7.2', '7.3', '7.4'],
    items: [
      'Replace <b>mcrypt</b> with OpenSSL / Sodium (7.2). Decrypt and re-encrypt stored data if needed.',
      'Replace <code>each()</code>, <code>create_function()</code>, <code>__autoload()</code> (deprecated 7.2, removed 8.0).',
      'Fix <code>count()</code> on non-countable values (warning in 7.2, TypeError in 8.0).',
      'Remove case-insensitive <code>define()</code>, curly-brace offsets <code>$s{0}</code>, unparenthesized nested ternaries.',
      'Start adopting typed properties, arrow functions and <code>??</code>.',
    ],
  },
  {
    key: '80', title: 'PHP 7.4 → 8.0 — stricter engine', versions: ['8.0'],
    items: [
      'Many warnings became <code>TypeError</code> / <code>ValueError</code> exceptions (e.g. <code>strlen(array)</code>, arithmetic on arrays, invalid argument types to internal functions).',
      'String-to-number comparison changed: <code>0 == "a"</code> is now <code>false</code>.',
      'PHP 4 style constructors are no longer called. <code>match</code> is a reserved keyword. <code>@</code> no longer silences fatal errors.',
      'Removed: <code>each</code>, <code>create_function</code>, <code>get_magic_quotes_gpc</code>, <code>money_format</code>, <code>(real)</code>, <code>(unset)</code>, <code>implode($arr, $glue)</code>…',
      'Optional parameters before required parameters are deprecated.',
    ],
  },
  {
    key: '8x', title: 'PHP 8.0 → 8.x — modern PHP', versions: ['8.1', '8.2', '8.3', '8.4', '8.5'],
    items: [
      'Passing <code>null</code> to non-nullable internal parameters is deprecated (8.1) — e.g. <code>strlen($maybeNull)</code>, <code>trim(null)</code>, <code>htmlspecialchars(null)</code>. Watch the deprecation log; this is not fully detectable statically.',
      'Add return types or <code>#[\\ReturnTypeWillChange]</code> to ArrayAccess / Iterator / Countable / JsonSerializable implementations (8.1).',
      'Declare all properties — dynamic properties are deprecated (8.2).',
      'Replace <code>utf8_encode/utf8_decode</code>, <code>"${var}"</code> interpolation, <code>strftime()</code>.',
      'Make implicit nullable types explicit: <code>?Type $x = null</code> (8.4). imap, pspell and oci8 moved to PECL (8.4).',
    ],
  },
  {
    key: 'verify', title: 'Verify & deploy', versions: [],
    items: [
      'Lint every file with the target version (<code>php -l</code>) and run static analysis (PHPStan / Psalm) at increasing levels.',
      'Run tests and manual smoke tests with <code>E_ALL</code>; monitor the error log for <code>E_DEPRECATED</code> and <code>TypeError</code>.',
      'Update php.ini for production: remove obsolete directives, <code>display_errors=Off</code>, <code>log_errors=On</code>, enable OPcache (and JIT if useful).',
      'Deploy to staging first, compare behaviour with the old version, then roll out to production.',
    ],
  },
];

const GUIDE_TH = {
  prepare: { title: 'เตรียมความพร้อมก่อนย้ายเวอร์ชัน', items: [
    'นำโค้ดเข้าระบบควบคุมเวอร์ชัน (git) และสร้าง branch สำหรับการย้ายเวอร์ชันโดยเฉพาะ',
    'ติดตั้ง PHP เวอร์ชันเป้าหมายในเครื่อง (เช่น Docker <code>php:8.4-apache</code>) และเก็บเวอร์ชันเดิมไว้เพื่อเปรียบเทียบการทำงาน',
    'เขียนชุดทดสอบ (smoke test) สำหรับขั้นตอนสำคัญ เช่น เข้าสู่ระบบ ชำระเงิน รายงาน แม้เป็นการทดสอบ HTTP ง่าย ๆ ก็ช่วยจับข้อผิดพลาดได้มาก',
    'เปิดการแสดงข้อผิดพลาดทั้งหมดในเครื่องพัฒนา: <code>error_reporting=E_ALL</code>, <code>display_errors=On</code>, <code>log_errors=On</code>',
    'สำรวจ dependency ทั้งหมด: ส่วนขยาย PHP (<code>php -m</code>), แพ็กเกจ Composer และไลบรารีที่คัดลอกมาไว้ในโปรเจกต์ (PHPMailer, FPDF, Smarty, PEAR รุ่นเก่า…)',
  ] },
  '56': { title: 'PHP 5.x → 5.6 — กำจัดโค้ดยุค PHP 4 / register_globals', items: [
    'เปลี่ยน <code>$HTTP_GET_VARS</code> และตัวแปรกลุ่มเดียวกันเป็น superglobal และเลิกใช้ <code>session_register()</code>',
    'ลบการส่งค่าแบบอ้างอิงตอนเรียกฟังก์ชัน <code>foo(&amp;$x)</code>',
    'เลิกพึ่ง <code>register_globals</code> / <code>magic_quotes_gpc</code>: อ่านข้อมูลขาเข้าอย่างชัดเจนและใช้ Prepared Statement',
    'เปลี่ยนแท็กเปิดแบบสั้น <code>&lt;?</code> เป็น <code>&lt;?php</code> และลบค่าตั้งที่ถูกลบแล้วออกจาก .htaccess / php.ini',
  ] },
  '70': { title: 'PHP 5.6 → 7.0 — การเปลี่ยนแปลงครั้งใหญ่', items: [
    'เปลี่ยน <b>mysql_*</b> เป็น PDO หรือ mysqli — มักเป็นงานที่ใหญ่ที่สุด แนะนำให้สร้าง DB wrapper ก่อน แล้วค่อยเปลี่ยนเป็น Prepared Statement',
    'เปลี่ยน <code>ereg*</code> / <code>split()</code> เป็น <code>preg_*</code> และเปลี่ยน <code>preg_replace /e</code> เป็น <code>preg_replace_callback()</code>',
    'ลบแท็กแบบ ASP และ <code>=&amp; new</code> เปลี่ยนชื่อ constructor แบบ PHP 4 เป็น <code>__construct()</code>',
    'ตรวจสอบ uniform variable syntax (<code>$$a[\'b\']</code>, <code>$obj-&gt;$p[\'x\']</code>)',
    'ข้อผิดพลาดของ engine กลายเป็น exception ชนิด <code>Error</code> — handler ส่วนกลางต้องรับ <code>Throwable</code>',
  ] },
  '74': { title: 'PHP 7.0 → 7.4 — เก็บกวาดสิ่งที่ถูกประกาศเลิกใช้', items: [
    'เปลี่ยน <b>mcrypt</b> เป็น OpenSSL / Sodium (7.2) และถอดรหัส/เข้ารหัสข้อมูลที่เก็บไว้ใหม่หากจำเป็น',
    'เปลี่ยน <code>each()</code>, <code>create_function()</code>, <code>__autoload()</code> (เลิกใช้ใน 7.2 และถูกลบใน 8.0)',
    'แก้การเรียก <code>count()</code> กับค่าที่นับไม่ได้ (warning ใน 7.2 และเป็น TypeError ใน 8.0)',
    'ลบ <code>define()</code> แบบไม่สนตัวพิมพ์, การเข้าถึง <code>$s{0}</code> ด้วยปีกกา และ ternary ซ้อนที่ไม่มีวงเล็บ',
    'เริ่มใช้ typed properties, arrow function และ <code>??</code>',
  ] },
  '80': { title: 'PHP 7.4 → 8.0 — engine เข้มงวดขึ้น', items: [
    'warning จำนวนมากกลายเป็น exception <code>TypeError</code> / <code>ValueError</code> (เช่น <code>strlen(array)</code>, การคำนวณกับอาร์เรย์, ส่งชนิดข้อมูลผิดให้ฟังก์ชันภายใน)',
    'การเปรียบเทียบสตริงกับตัวเลขเปลี่ยนไป: <code>0 == "a"</code> ได้ผลเป็น <code>false</code>',
    'constructor แบบ PHP 4 จะไม่ถูกเรียกอีก, <code>match</code> เป็นคำสงวน และ <code>@</code> ไม่ซ่อน fatal error อีกต่อไป',
    'ถูกลบ: <code>each</code>, <code>create_function</code>, <code>get_magic_quotes_gpc</code>, <code>money_format</code>, <code>(real)</code>, <code>(unset)</code>, <code>implode($arr, $glue)</code>…',
    'พารามิเตอร์ที่มีค่าเริ่มต้นอยู่หน้าพารามิเตอร์ที่จำเป็นถูกประกาศเลิกใช้',
  ] },
  '8x': { title: 'PHP 8.0 → 8.x — PHP สมัยใหม่', items: [
    'การส่ง <code>null</code> ให้พารามิเตอร์ของฟังก์ชันภายในที่ไม่รับ null ถูกประกาศเลิกใช้ (8.1) เช่น <code>strlen($maybeNull)</code>, <code>trim(null)</code>, <code>htmlspecialchars(null)</code> — ต้องดูจาก log เพราะตรวจแบบ static ได้ไม่ครบ',
    'เพิ่ม return type หรือ <code>#[\\ReturnTypeWillChange]</code> ให้คลาสที่ implement ArrayAccess / Iterator / Countable / JsonSerializable (8.1)',
    'ประกาศ property ทุกตัว — property แบบไดนามิกถูกประกาศเลิกใช้ (8.2)',
    'เปลี่ยน <code>utf8_encode/utf8_decode</code>, การแทรก <code>"${var}"</code> และ <code>strftime()</code>',
    'ระบุ nullable type ให้ชัดเจน: <code>?Type $x = null</code> (8.4) และ imap, pspell, oci8 ถูกย้ายไป PECL (8.4)',
  ] },
  verify: { title: 'ตรวจสอบและนำขึ้นใช้งานจริง', items: [
    'ตรวจ syntax ทุกไฟล์ด้วยเวอร์ชันเป้าหมาย (<code>php -l</code>) และรัน static analysis (PHPStan / Psalm) โดยเพิ่มระดับทีละขั้น',
    'รันชุดทดสอบและทดสอบด้วยมือโดยเปิด <code>E_ALL</code> และเฝ้าดู log สำหรับ <code>E_DEPRECATED</code> และ <code>TypeError</code>',
    'ปรับ php.ini สำหรับ production: ลบค่าตั้งที่เลิกใช้, <code>display_errors=Off</code>, <code>log_errors=On</code>, เปิด OPcache (และ JIT ถ้าเหมาะสม)',
    'นำขึ้น staging ก่อน เปรียบเทียบการทำงานกับเวอร์ชันเดิม แล้วจึงนำขึ้น production',
  ] },
};
/** Guide step in the current language. */
const gl = (g) => (LANG === 'th' && GUIDE_TH[g.key]) ? { ...g, ...GUIDE_TH[g.key] } : g;

const TOOLS = `
  <div class="grid g3">
    <div><h4>Rector — automated upgrades</h4>
      <div class="cmd">composer require --dev rector/rector
vendor/bin/rector init
# rector.php: ->withPhpSets(php84: true)
vendor/bin/rector process src --dry-run</div>
      <div class="small muted">Rewrites code automatically: constructors, each(), create_function, array syntax, null coalescing…</div></div>
    <div><h4>PHPCompatibility (PHP_CodeSniffer)</h4>
      <div class="cmd">composer require --dev phpcompatibility/php-compatibility:"^10"
vendor/bin/phpcs -p src --standard=PHPCompatibility \\
  --runtime-set testVersion 8.4</div>
      <div class="small muted">Cross-check with a second static ruleset.</div></div>
    <div><h4>PHPStan — type-level analysis</h4>
      <div class="cmd">composer require --dev phpstan/phpstan
vendor/bin/phpstan analyse src --level 3</div>
      <div class="small muted">Finds wrong argument types, undefined methods and null issues that regex-based tools cannot see.</div></div>
  </div>`;

function pageRoadmap(el, scan) {
  const s = scan.summary, id = s.meta.id, target = vnum(s.meta.target);
  const byV = Object.fromEntries(s.byVersion.map((v) => [v.version, v]));
  const steps = GUIDE.filter((g) => !g.versions.length || vnum(g.versions[0]) <= target);
  el.innerHTML = `
  <div class="panel" style="margin-bottom:16px">
    ${LANG === 'th' ? `
    <h2>แผนการย้ายไป PHP ${esc(s.meta.target)}</h2>
    <p class="muted" style="margin:0">อัปเกรดทีละขั้น และให้แอปพลิเคชันทำงานได้หลังทุกขั้นตอน ปัญหาที่พบจากการสแกนถูกจัดกลุ่มตามเวอร์ชัน PHP ที่ฟีเจอร์นั้นถูกลบ เปลี่ยนพฤติกรรม หรือประกาศเลิกใช้
    ส่วนปัญหาด้านความปลอดภัยและแนวปฏิบัติที่ดี (${fmt((s.byCategory.security || {}).total || 0)} + ${fmt((s.byCategory['best-practice'] || {}).total || 0)}) สามารถแก้ไขไปพร้อมกันได้</p>` : `
    <h2>Migration roadmap to PHP ${esc(s.meta.target)}</h2>
    <p class="muted" style="margin:0">Upgrade step by step and keep the application running after each step. Issues found by this scan are grouped by the PHP version in which the feature was removed, changed or deprecated.
    Security and best-practice issues (${fmt((s.byCategory.security || {}).total || 0)} + ${fmt((s.byCategory['best-practice'] || {}).total || 0)}) can be fixed in parallel.</p>`}
  </div>
  <div class="steps">
    ${steps.map(gl).map((g) => {
      const vs = g.versions.filter((v) => vnum(v) <= target);
      const stats = vs.map((v) => byV[v]).filter(Boolean);
      const count = stats.reduce((a, v) => a + v.removed + v.changed + v.deprecated, 0);
      const rulesCount = {};
      stats.forEach((v) => Object.entries(v.rules).forEach(([r, n]) => { rulesCount[r] = (rulesCount[r] || 0) + n; }));
      const done = g.versions.length && count === 0;
      return `<div class="step ${done ? 'done' : ''}"><div class="panel">
        <h3>${esc(g.title)} ${g.versions.length ? (count ? `<span class="tag removed">${fmt(count)} ${t('issue(s)')}</span>` : `<span class="tag best-practice">${t('nothing to fix')}</span>`) : ''}</h3>
        ${Object.keys(rulesCount).length ? `<table class="list" style="margin:8px 0 10px"><tbody>${Object.entries(rulesCount).sort((a, b) => b[1] - a[1]).map(([r, n]) => {
          const rule = state.ruleMap[r] || {};
          return `<tr><td><a href="#" data-rule="${esc(r)}">${esc(rt(rule, 'title') || r)}</a></td><td class="nowrap">${vs.filter((v) => byV[v] && byV[v].rules[r]).map((v) => `<span class="tag ver">${v}</span>`).join(' ')}</td>
            <td class="num">${issuesLink(id, { rule: r, version: vs.filter((v) => byV[v] && byV[v].rules[r]).join(',') }, fmt(n) + ' →')}</td></tr>`;
        }).join('')}</tbody></table>` : ''}
        <ul>${g.items.map((it) => `<li>${it}</li>`).join('')}</ul>
        ${(g.cmds || []).map((c) => `<div class="cmd">${esc(c)}</div>`).join('')}
      </div></div>`;
    }).join('')}
  </div>
  <div class="panel" style="margin-top:16px"><h3>${t('Recommended tooling')}</h3>${TOOLS}</div>`;
}

function pageGuide(app) {
  app.innerHTML = `
  <div class="panel" style="margin-bottom:16px">
    ${LANG === 'th' ? `
    <h1>คู่มือย้าย PHP 5.x → 8.x</h1>
    <p class="muted">ขั้นตอนการอัปเกรดแอปพลิเคชัน PHP รุ่นเก่าแบบทีละขั้น สแกนโปรเจกต์ของคุณเพื่อดูว่าขั้นตอนใดเกี่ยวข้องกับโค้ดของคุณบ้าง</p>` : `
    <h1>PHP 5.x → 8.x migration guide</h1>
    <p class="muted">A practical, step-by-step path for upgrading legacy PHP applications. Run a scan to see which steps affect your code.</p>`}
    <a class="btn primary" href="#/new">＋ ${t('Scan a project')}</a> <a class="btn" href="#/rules">${t('Browse rules')}</a>
  </div>
  <div class="steps">${GUIDE.map(gl).map((g) => `<div class="step"><div class="panel">
    <h3>${esc(g.title)}</h3>
    ${g.versions.length ? `<div class="ver-chain">${g.versions.map((v) => `<a class="tag ver" href="#/rules?version=${v}">PHP ${v}</a>`).join('')}</div>` : ''}
    <ul>${g.items.map((it) => `<li>${it}</li>`).join('')}</ul>
    ${(g.cmds || []).map((c) => `<div class="cmd">${esc(c)}</div>`).join('')}
  </div></div>`).join('')}</div>
  <div class="panel" style="margin-top:16px"><h3>${t('Recommended tooling')}</h3>${TOOLS}</div>`;
}

// ---------------------------------------------------------------- rules
async function pageRules(app, query) {
  const rules = await getRules();
  const q = (query.q || '').toLowerCase();
  const cat = query.category || '';
  const ver = query.version || '';
  const list = rules.filter((r) =>
    (!cat || r.category === cat) &&
    (!ver || [r.deprecated, r.removed, r.changed].includes(ver)) &&
    (!q || (r.title + ' ' + r.id + ' ' + r.description + ' ' + r.pattern + ' ' + (r.th ? r.th.title + ' ' + r.th.description : '')).toLowerCase().includes(q)));
  const sel = state.ruleMap[query.id] || list[0];
  const versions = [...new Set(rules.flatMap((r) => [r.deprecated, r.removed, r.changed]).filter(Boolean))].sort((a, b) => vnum(a) - vnum(b));
  app.innerHTML = `
  <div class="hero"><h1>${t('Rules')}</h1><span class="muted">${rules.length} ${t('rules')}</span></div>
  <div class="toolbar">
    <input type="text" id="rq" placeholder="${t('Search rules… (e.g. mysql, each, nullable)')}" value="${esc(query.q || '')}">
    <select id="rcat" style="max-width:200px"><option value="">${t('All categories')}</option>${Object.entries(CAT_LABEL).map(([k, v]) => `<option value="${k}" ${k === cat ? 'selected' : ''}>${v}</option>`).join('')}</select>
    <select id="rver" style="max-width:160px"><option value="">${t('All versions')}</option>${versions.map((v) => `<option ${v === ver ? 'selected' : ''}>${v}</option>`).join('')}</select>
    <span class="muted">${list.length} ${t('shown')}</span>
  </div>
  <div class="rules-layout">
    <div class="panel rule-list">${list.map((r) => `
      <div class="rule-item ${sel && r.id === sel.id ? 'on' : ''}" data-id="${r.id}">
        <div class="t">${esc(rt(r, 'title'))}</div>
        <div class="m">${sevBadge(r.severity)}<span class="tag ${r.category}">${CAT_LABEL[r.category]}</span>${r.removed ? `<span class="tag removed">${t('removed')} ${r.removed}</span>` : ''}${r.changed ? `<span class="tag changed">${t('changed')} ${r.changed}</span>` : ''}${r.deprecated ? `<span class="tag deprecated">${t('deprecated')} ${r.deprecated}</span>` : ''}</div>
      </div>`).join('') || `<div class="empty">${t('No rules match')}</div>`}</div>
    <div class="panel rule-detail">${sel ? `<h2>${esc(rt(sel, 'title'))}</h2>${ruleDetailHtml(sel)}` : ''}</div>
  </div>`;
  const upd = (patch) => go('rules', { ...query, ...patch });
  let timer;
  $('#rq').oninput = (e) => { clearTimeout(timer); timer = setTimeout(() => upd({ q: e.target.value, id: '' }), 300); };
  if (query.q) { const el = $('#rq'); el.focus(); el.setSelectionRange(el.value.length, el.value.length); }
  $('#rcat').onchange = (e) => upd({ category: e.target.value, id: '' });
  $('#rver').onchange = (e) => upd({ version: e.target.value, id: '' });
  $$('.rule-item').forEach((it) => it.onclick = () => upd({ id: it.dataset.id }));
}

applyStaticLang();
render();
