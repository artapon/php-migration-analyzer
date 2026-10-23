'use strict';

const express = require('express');
const multer = require('multer');
const AdmZip = require('adm-zip');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { scanProject, ruleCatalog, fileType, TARGETS, DEFAULT_EXCLUDES } = require('./src/scanner');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const SCANS_DIR = path.join(DATA_DIR, 'scans');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const MAX_ZIP_MB = parseInt(process.env.MAX_ZIP_MB || '500', 10);
const MAX_UNZIPPED_MB = parseInt(process.env.MAX_UNZIPPED_MB || '2000', 10);

for (const d of [SCANS_DIR, UPLOADS_DIR, path.join(DATA_DIR, 'tmp')]) fs.mkdirSync(d, { recursive: true });

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({ dest: path.join(DATA_DIR, 'tmp'), limits: { fileSize: MAX_ZIP_MB * 1024 * 1024 } });

/** In-memory job registry: jobId -> { status, progress, scanId, error } */
const jobs = new Map();
const newId = () => new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14) + '-' + crypto.randomBytes(3).toString('hex');
const validId = (id) => /^[\w-]{1,64}$/.test(id);

function parseOptions(body) {
  const exclude = typeof body.exclude === 'string'
    ? body.exclude.split(/[,\n]/).map(s => s.trim()).filter(Boolean)
    : Array.isArray(body.exclude) ? body.exclude : DEFAULT_EXCLUDES;
  let categories = body.categories;
  if (typeof categories === 'string') categories = categories.split(',').filter(Boolean);
  return {
    target: TARGETS.includes(body.target) ? body.target : '8.4',
    exclude,
    categories,
    maxFileSizeKB: Math.min(Math.max(parseInt(body.maxFileSizeKB, 10) || 1024, 16), 20480),
  };
}

function startJob(root, opts, extra = {}) {
  const jobId = newId();
  const job = { id: jobId, status: 'running', progress: { phase: 'queued', done: 0, total: 0 }, scanId: null, error: null };
  jobs.set(jobId, job);

  scanProject(root, opts, (p) => { job.progress = p; })
    .then(async (report) => {
      const scanId = jobId;
      report.summary.meta.id = scanId;
      report.summary.meta.source = extra.source || 'folder';
      report.summary.meta.label = extra.label || report.summary.meta.name;
      await fsp.writeFile(path.join(SCANS_DIR, scanId + '.json'), JSON.stringify(report));
      job.status = 'done';
      job.scanId = scanId;
    })
    .catch((e) => {
      job.status = 'error';
      job.error = e.message;
    })
    .finally(() => setTimeout(() => jobs.delete(jobId), 60 * 60 * 1000));
  return jobId;
}

async function loadScan(id) {
  if (!validId(id)) return null;
  try {
    return JSON.parse(await fsp.readFile(path.join(SCANS_DIR, id + '.json'), 'utf8'));
  } catch {
    return null;
  }
}

// ----------------------------------------------------------------------------- API

app.get('/api/info', (req, res) => {
  res.json({ targets: TARGETS, defaultExcludes: DEFAULT_EXCLUDES, rules: ruleCatalog().length, platform: process.platform, home: os.homedir() });
});

app.get('/api/rules', (req, res) => res.json(ruleCatalog()));

/** Scan a folder on this machine. */
app.post('/api/scan', async (req, res) => {
  const dir = (req.body.path || '').trim();
  if (!dir) return res.status(400).json({ error: 'path is required' });
  const root = path.resolve(dir);
  const st = await fsp.stat(root).catch(() => null);
  if (!st || !st.isDirectory()) return res.status(400).json({ error: `Folder not found: ${root}` });
  const jobId = startJob(root, parseOptions(req.body), { source: 'folder', label: req.body.label });
  res.json({ jobId });
});

/** Upload a .zip of the project and scan it. */
app.post('/api/upload', upload.single('archive'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'archive (.zip) is required' });
  const id = newId();
  const dest = path.join(UPLOADS_DIR, id);
  try {
    await extractZip(req.file.path, dest);
  } catch (e) {
    await fsp.rm(dest, { recursive: true, force: true });
    return res.status(400).json({ error: 'Could not extract archive: ' + e.message });
  } finally {
    fsp.rm(req.file.path, { force: true }).catch(() => {});
  }
  // If the zip contains a single top folder, scan inside it.
  let root = dest;
  const entries = await fsp.readdir(dest, { withFileTypes: true });
  if (entries.length === 1 && entries[0].isDirectory()) root = path.join(dest, entries[0].name);
  const label = req.body.label || req.file.originalname.replace(/\.zip$/i, '');
  const jobId = startJob(root, parseOptions(req.body), { source: 'upload', label });
  res.json({ jobId });
});

async function extractZip(zipPath, dest) {
  const zip = new AdmZip(zipPath);
  const entries = zip.getEntries();
  const limit = MAX_UNZIPPED_MB * 1024 * 1024;
  let total = 0;
  await fsp.mkdir(dest, { recursive: true });
  const base = path.resolve(dest) + path.sep;
  for (const e of entries) {
    if (e.isDirectory) continue;
    const name = e.entryName.replace(/\\/g, '/');
    // only keep files the scanner can use – keeps uploads small and safe
    if (!fileType(path.posix.basename(name))) continue;
    const target = path.resolve(dest, name);
    if (!target.startsWith(base)) throw new Error('unsafe path in archive: ' + name);
    const data = e.getData();
    total += data.length;
    if (total > limit) throw new Error(`archive expands to more than ${MAX_UNZIPPED_MB} MB`);
    await fsp.mkdir(path.dirname(target), { recursive: true });
    await fsp.writeFile(target, data, { mode: 0o644 });
  }
}

app.get('/api/jobs/:id', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'job not found' });
  res.json(job);
});

app.get('/api/scans', async (req, res) => {
  const files = (await fsp.readdir(SCANS_DIR)).filter(f => f.endsWith('.json'));
  const list = [];
  for (const f of files) {
    try {
      const r = JSON.parse(await fsp.readFile(path.join(SCANS_DIR, f), 'utf8'));
      const s = r.summary;
      list.push({
        id: s.meta.id, label: s.meta.label, root: s.meta.root, source: s.meta.source, target: s.meta.target,
        startedAt: s.meta.startedAt, gate: s.qualityGate.status, ratings: s.ratings, issues: s.totals.issues,
        debt: s.totals.debt, files: s.metrics.files, ncloc: s.metrics.ncloc, bySeverity: s.bySeverity, readiness: s.readiness,
      });
    } catch { /* ignore broken file */ }
  }
  list.sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  res.json(list);
});

app.get('/api/scans/:id', async (req, res) => {
  const r = await loadScan(req.params.id);
  if (!r) return res.status(404).json({ error: 'scan not found' });
  res.json(r);
});

app.delete('/api/scans/:id', async (req, res) => {
  const r = await loadScan(req.params.id);
  if (!r) return res.status(404).json({ error: 'scan not found' });
  await fsp.rm(path.join(SCANS_DIR, req.params.id + '.json'), { force: true });
  // remove extracted upload if it belongs to this scan only
  const root = path.resolve(r.summary.meta.root);
  if (root.startsWith(path.resolve(UPLOADS_DIR) + path.sep)) {
    const top = path.join(UPLOADS_DIR, path.relative(UPLOADS_DIR, root).split(path.sep)[0]);
    await fsp.rm(top, { recursive: true, force: true });
  }
  res.json({ ok: true });
});

/** Source of a scanned file (only files that are part of the scan). */
app.get('/api/scans/:id/file', async (req, res) => {
  const r = await loadScan(req.params.id);
  if (!r) return res.status(404).json({ error: 'scan not found' });
  const rel = String(req.query.path || '');
  const entry = r.files.find(f => f.file === rel);
  if (!entry) return res.status(404).json({ error: 'file is not part of this scan' });
  const root = path.resolve(r.summary.meta.root);
  const full = path.resolve(root, rel);
  if (!full.startsWith(root + path.sep)) return res.status(400).json({ error: 'invalid path' });
  try {
    const buf = await fsp.readFile(full);
    let content;
    try { content = new TextDecoder('utf-8', { fatal: true }).decode(buf).replace(/^﻿/, ''); } catch { content = buf.toString('latin1'); }
    res.json({ path: rel, content, issues: r.issues.filter(i => i.file === rel) });
  } catch (e) {
    res.status(410).json({ error: 'file no longer available on disk: ' + e.message });
  }
});

app.get('/api/scans/:id/export.csv', async (req, res) => {
  const r = await loadScan(req.params.id);
  if (!r) return res.status(404).send('scan not found');
  const esc = (s) => {
    let v = String(s == null ? '' : s);
    if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; // avoid CSV formula injection in Excel
    return '"' + v.replace(/"/g, '""') + '"';
  };
  const head = ['id', 'severity', 'category', 'status', 'php_version', 'rule', 'file', 'line', 'message', 'effort_min', 'code'];
  const rows = r.issues.map(i => [i.id, i.severity, i.category, i.status, i.version, i.rule, i.file, i.line, i.message, i.effort, i.code.trim()].map(esc).join(','));
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="php-migration-${req.params.id}.csv"`);
  res.send('﻿' + head.join(',') + '\n' + rows.join('\n'));
});

app.get('/api/scans/:id/export.json', async (req, res) => {
  const r = await loadScan(req.params.id);
  if (!r) return res.status(404).send('scan not found');
  res.setHeader('Content-Disposition', `attachment; filename="php-migration-${req.params.id}.json"`);
  res.json(r);
});

/** Folder browser for the "scan local folder" picker. */
app.get('/api/fs', async (req, res) => {
  let dir = String(req.query.dir || '');
  if (!dir) {
    if (process.platform === 'win32') {
      const drives = [];
      for (const l of 'CDEFGHIJKLMNOPQRSTUVWXYZ') {
        if (fs.existsSync(l + ':\\')) drives.push({ name: l + ':\\', path: l + ':\\' });
      }
      return res.json({ dir: '', parent: null, dirs: drives });
    }
    dir = '/';
  }
  const abs = path.resolve(dir);
  try {
    const entries = await fsp.readdir(abs, { withFileTypes: true });
    const dirs = entries.filter(e => e.isDirectory() && !e.name.startsWith('$')).map(e => ({ name: e.name, path: path.join(abs, e.name) }))
      .sort((a, b) => a.name.localeCompare(b.name));
    const phpCount = entries.filter(e => e.isFile() && fileType(e.name) === 'php').length;
    const parent = path.dirname(abs) === abs ? (process.platform === 'win32' ? '' : null) : path.dirname(abs);
    res.json({ dir: abs, parent, dirs, phpCount });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: err.message || 'internal error' });
});

app.listen(PORT, HOST, () => {
  console.log(`PHP Migration Analyzer running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`${ruleCatalog().length} rules loaded · reports stored in ${SCANS_DIR}`);
});
