'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { lex, lineIndex } = require('./lexer');
const { rules, FEATURES } = require('./rules');

const PHP_EXT = new Set(['.php', '.php3', '.php4', '.php5', '.php7', '.phtml', '.inc', '.module', '.ctp', '.phps', '.install', '.theme']);
const DEFAULT_EXCLUDES = ['vendor', 'node_modules', '.git', '.svn', '.hg', '.idea', '.vscode'];
const SEVERITIES = ['blocker', 'critical', 'major', 'minor', 'info'];
const TARGETS = ['7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1', '8.2', '8.3', '8.4', '8.5'];

const v = (s) => {
  const [a, b = '0'] = String(s).split('.');
  return parseInt(a, 10) * 100 + parseInt(b, 10);
};

function fileType(name) {
  const lower = name.toLowerCase();
  if (lower === 'composer.json') return 'composer';
  if (lower === '.htaccess' || lower === '.user.ini' || lower === 'php.ini' || /^php.*\.ini$/.test(lower) || lower.endsWith('.ini')) return 'ini';
  if (PHP_EXT.has(path.extname(lower))) return 'php';
  return null;
}

function decode(buf) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buf).replace(/^﻿/, '');
  } catch {
    // Legacy projects often use TIS-620 / Windows-874 / Latin-1. latin1 keeps 1 byte = 1 char.
    return buf.toString('latin1');
  }
}

/** Decide whether (and how) a rule hit applies for the chosen target version. */
function evaluate(rule, ov, target) {
  const pick = (k) => (ov && Object.prototype.hasOwnProperty.call(ov, k) ? ov[k] : rule[k]);
  const d = pick('deprecated'), r = pick('removed'), c = pick('changed');
  if (r && v(r) <= target) return { status: 'removed', version: r, severity: rule.severity };
  if (c && v(c) <= target) return { status: 'changed', version: c, severity: rule.severity };
  if (d && v(d) <= target) {
    const sev = rule.severity === 'blocker' || rule.severity === 'critical' ? 'major' : rule.severity;
    return { status: 'deprecated', version: d, severity: sev, removedIn: r || null };
  }
  if (!d && !r && !c) {
    if (rule.minTarget && v(rule.minTarget) > target) return null;
    return { status: rule.category === 'security' ? 'vulnerability' : rule.category === 'best-practice' ? 'code-smell' : 'issue', version: null, severity: rule.severity };
  }
  return null; // not relevant for this target yet
}

function analyzeFile(text, relPath, type, target, ruleset, limits = {}) {
  const maxPerRule = limits.maxPerRule || 300;
  const views = type === 'php'
    ? lex(text)
    : { raw: text, code: text, src: text, str: text, dq: text, hasHtml: false };
  const locate = lineIndex(text);
  const lines = text.split('\n');
  const ctx = {
    views, hasHtml: views.hasHtml, target, targetStr: limits.targetStr, v, relPath,
    isAbove: (ver) => target >= v(ver),
  };

  const issues = [];
  const seen = new Set();

  for (const rule of ruleset) {
    const types = rule.fileTypes || ['php'];
    if (!types.includes(type)) continue;
    // quick skip: rule cannot apply at all for this target
    if (!rule.check && !evaluate(rule, null, target)) continue;

    let hits = [];
    try {
      if (rule.check) {
        hits = rule.check(ctx) || [];
      } else {
        const view = views[rule.view || 'code'];
        const re = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g');
        let m;
        while ((m = re.exec(view))) {
          if (m[0] === '') { re.lastIndex++; continue; }
          if (rule.filter && !rule.filter(m, ctx, m.index)) continue;
          hits.push({ index: m.index, message: rule.message ? rule.message(m, ctx) : rule.title });
          if (hits.length >= maxPerRule) break;
        }
      }
    } catch (e) {
      hits = [];
    }

    for (const h of hits.slice(0, maxPerRule)) {
      const ev = evaluate(rule, h, target);
      if (!ev) continue;
      // skip leading whitespace so the column points at the code
      let idx = h.index;
      while (idx < text.length && (text[idx] === ' ' || text[idx] === '\t' || text[idx] === '\n' || text[idx] === '\r')) idx++;
      const { line, col } = locate(idx);
      const key = rule.id + ':' + line + ':' + (h.message || '');
      if (seen.has(key)) continue;
      seen.add(key);
      issues.push({
        rule: rule.id,
        file: relPath,
        line, col,
        severity: ev.severity,
        category: rule.category,
        status: ev.status,
        version: ev.version,
        removedIn: ev.removedIn || null,
        message: h.message || rule.title,
        effort: rule.effort || 5,
        code: (lines[line - 1] || '').replace(/\r$/, '').slice(0, 300),
      });
    }
  }

  // metrics
  let ncloc = 0;
  if (type === 'php') {
    for (const l of views.code.split('\n')) if (/\S/.test(l)) ncloc++;
  }
  const features = [];
  if (type === 'php') for (const f of FEATURES) if (f.re.test(views.code)) features.push(f.name);

  return {
    issues,
    metrics: {
      lines: lines.length,
      ncloc,
      strictTypes: type === 'php' && /declare\s*\(\s*strict_types\s*=\s*1/.test(views.code),
      namespaced: type === 'php' && /^\s*namespace\s+[A-Za-z_\\]/m.test(views.code),
      includes: type === 'php' ? (views.code.match(/\b(?:include|include_once|require|require_once)\b/gi) || []).length : 0,
      classes: type === 'php' ? (views.code.match(/(?<![\w$:>])(?:class|trait|interface)\s+[A-Za-z_]/gi) || []).length : 0,
    },
    features,
  };
}

async function collectFiles(root, excludes, maxFileSize) {
  const out = [];
  const skipped = [];
  const ex = new Set(excludes.map(e => e.toLowerCase()));
  async function walk(dir) {
    let entries;
    try { entries = await fsp.readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (ex.has(e.name.toLowerCase())) continue;
        const rel = path.relative(root, full).replace(/\\/g, '/');
        if (ex.has(rel.toLowerCase())) continue;
        await walk(full);
      } else if (e.isFile()) {
        const type = fileType(e.name);
        if (!type) continue;
        let size = 0;
        try { size = (await fsp.stat(full)).size; } catch { continue; }
        const rel = path.relative(root, full).replace(/\\/g, '/');
        if (size > maxFileSize) { skipped.push({ file: rel, reason: `larger than ${Math.round(maxFileSize / 1024)} KB` }); continue; }
        out.push({ full, rel, type, size });
      }
    }
  }
  await walk(root);
  out.sort((a, b) => a.rel.localeCompare(b.rel));
  return { files: out, skipped };
}

function rating(issues) {
  const worst = new Set(issues.map(i => i.severity));
  if (worst.has('blocker')) return 'E';
  if (worst.has('critical')) return 'D';
  if (worst.has('major')) return 'C';
  if (worst.has('minor')) return 'B';
  return 'A';
}

function debtRating(ratio) {
  if (ratio <= 0.05) return 'A';
  if (ratio <= 0.1) return 'B';
  if (ratio <= 0.2) return 'C';
  if (ratio <= 0.5) return 'D';
  return 'E';
}

function formatDebt(min) {
  const d = Math.floor(min / 480);
  const h = Math.floor((min % 480) / 60);
  const m = min % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}min`;
  return `${m}min`;
}

function buildSummary(issues, fileResults, meta) {
  const bySeverity = Object.fromEntries(SEVERITIES.map(s => [s, 0]));
  const byCategory = {};
  const byStatus = {};
  const byRule = {};
  const byVersion = {};
  const byFile = {};
  let debt = 0;

  const ruleMap = Object.fromEntries(rules.map(r => [r.id, r]));
  for (const i of issues) {
    bySeverity[i.severity]++;
    byCategory[i.category] = byCategory[i.category] || { total: 0, blocker: 0, critical: 0, major: 0, minor: 0, info: 0, debt: 0 };
    byCategory[i.category].total++;
    byCategory[i.category][i.severity]++;
    byCategory[i.category].debt += i.effort;
    byStatus[i.status] = (byStatus[i.status] || 0) + 1;
    const r = ruleMap[i.rule];
    byRule[i.rule] = byRule[i.rule] || { rule: i.rule, title: r.title, category: r.category, severity: i.severity, count: 0, debt: 0 };
    byRule[i.rule].count++;
    byRule[i.rule].debt += i.effort;
    if (i.version) {
      byVersion[i.version] = byVersion[i.version] || { version: i.version, removed: 0, changed: 0, deprecated: 0, rules: {} };
      byVersion[i.version][i.status]++;
      byVersion[i.version].rules[i.rule] = (byVersion[i.version].rules[i.rule] || 0) + 1;
    }
    const f = byFile[i.file] = byFile[i.file] || { file: i.file, total: 0, blocker: 0, critical: 0, major: 0, minor: 0, info: 0, debt: 0 };
    f.total++; f[i.severity]++; f.debt += i.effort;
    debt += i.effort;
  }

  const phpFiles = fileResults.filter(f => f.type === 'php');
  const ncloc = phpFiles.reduce((a, f) => a + f.metrics.ncloc, 0);
  const lines = fileResults.reduce((a, f) => a + f.metrics.lines, 0);

  const compat = issues.filter(i => i.category === 'compatibility');
  const sec = issues.filter(i => i.category === 'security');
  const debtRatio = ncloc ? debt / (ncloc * 30) : 0;

  // files that will not run on the target (blocker/critical compatibility issues)
  const brokenFiles = new Set(compat.filter(i => i.severity === 'blocker' || i.severity === 'critical').map(i => i.file));
  const readiness = phpFiles.length ? Math.round(((phpFiles.length - phpFiles.filter(f => brokenFiles.has(f.rel)).length) / phpFiles.length) * 1000) / 10 : 100;

  // features -> detected minimal version, removed issues -> max working version
  const featureCount = {};
  for (const f of phpFiles) for (const n of f.features) featureCount[n] = (featureCount[n] || 0) + 1;
  const features = FEATURES.filter(f => featureCount[f.name]).map(f => ({ name: f.name, version: f.version, files: featureCount[f.name] }));
  const minVersion = features.reduce((a, f) => (v(f.version) > v(a) ? f.version : a), '5.2');
  const removedVersions = issues.filter(i => i.status === 'removed' && i.category === 'compatibility').map(i => i.version);
  const breaksAt = removedVersions.length ? removedVersions.reduce((a, b) => (v(b) < v(a) ? b : a)) : null;

  const counts = (arr, s) => arr.filter(i => i.severity === s).length;
  const ratings = {
    compatibility: rating(compat),
    security: rating(sec),
    maintainability: debtRating(debtRatio),
  };
  const conditions = [
    { metric: 'Compatibility blocker issues', op: '=', threshold: 0, actual: counts(compat, 'blocker') },
    { metric: 'Compatibility critical issues', op: '=', threshold: 0, actual: counts(compat, 'critical') },
    { metric: 'Security vulnerabilities (blocker + critical)', op: '=', threshold: 0, actual: counts(sec, 'blocker') + counts(sec, 'critical') },
    { metric: 'Maintainability rating', op: '<=', threshold: 'C', actual: ratings.maintainability },
  ].map(c => ({ ...c, ok: c.op === '=' ? c.actual === c.threshold : c.actual <= c.threshold }));

  const versions = Object.values(byVersion).sort((a, b) => v(a.version) - v(b.version));

  return {
    totals: { issues: issues.length, debtMinutes: debt, debt: formatDebt(debt), debtRatio: Math.round(debtRatio * 1000) / 10 },
    bySeverity, byCategory, byStatus,
    byRule: Object.values(byRule).sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || b.count - a.count),
    byVersion: versions,
    topFiles: Object.values(byFile).sort((a, b) => b.blocker - a.blocker || b.critical - a.critical || b.total - a.total).slice(0, 25),
    ratings,
    qualityGate: { status: conditions.every(c => c.ok) ? 'PASSED' : 'FAILED', conditions },
    readiness,
    metrics: {
      files: fileResults.length,
      phpFiles: phpFiles.length,
      lines, ncloc,
      classes: phpFiles.reduce((a, f) => a + f.metrics.classes, 0),
      strictTypesFiles: phpFiles.filter(f => f.metrics.strictTypes).length,
      namespacedFiles: phpFiles.filter(f => f.metrics.namespaced).length,
      includes: phpFiles.reduce((a, f) => a + f.metrics.includes, 0),
      hasComposer: fileResults.some(f => f.type === 'composer'),
      filesWithIssues: Object.keys(byFile).length,
    },
    detected: { features, minVersion, breaksAt },
    meta,
  };
}

/**
 * Scan a directory.
 * @param {string} root
 * @param {{target?:string, exclude?:string[], maxFileSizeKB?:number, categories?:string[]}} opts
 * @param {(p:{phase:string, done:number, total:number, current?:string})=>void} onProgress
 */
async function scanProject(root, opts = {}, onProgress = () => {}) {
  const started = Date.now();
  const targetStr = TARGETS.includes(opts.target) ? opts.target : '8.4';
  const target = v(targetStr);
  const excludes = (opts.exclude && opts.exclude.length ? opts.exclude : DEFAULT_EXCLUDES).map(s => s.trim()).filter(Boolean);
  const maxFileSize = (opts.maxFileSizeKB || 1024) * 1024;
  const categories = opts.categories && opts.categories.length ? opts.categories : ['compatibility', 'security', 'best-practice'];
  const ruleset = rules.filter(r => categories.includes(r.category));

  const st = await fsp.stat(root).catch(() => null);
  if (!st || !st.isDirectory()) throw new Error(`Folder not found: ${root}`);

  onProgress({ phase: 'collecting', done: 0, total: 0 });
  const { files, skipped } = await collectFiles(root, excludes, maxFileSize);

  const issues = [];
  const fileResults = [];
  const MAX_ISSUES = 100000;
  let truncated = false;

  for (let n = 0; n < files.length; n++) {
    const f = files[n];
    if (n % 5 === 0) {
      onProgress({ phase: 'analyzing', done: n, total: files.length, current: f.rel });
      await new Promise(r => setImmediate(r));
    }
    let text;
    try { text = decode(await fsp.readFile(f.full)); } catch (e) { skipped.push({ file: f.rel, reason: e.message }); continue; }
    const res = analyzeFile(text, f.rel, f.type, target, ruleset, { targetStr });
    fileResults.push({ rel: f.rel, type: f.type, size: f.size, metrics: res.metrics, features: res.features, issues: res.issues.length });
    for (const i of res.issues) {
      if (issues.length >= MAX_ISSUES) { truncated = true; break; }
      issues.push(i);
    }
  }
  onProgress({ phase: 'reporting', done: files.length, total: files.length });

  issues.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line);
  issues.forEach((i, idx) => { i.id = idx + 1; });

  const meta = {
    root,
    name: path.basename(root),
    target: targetStr,
    excludes,
    categories,
    startedAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    skipped,
    truncated,
    rulesCount: ruleset.length,
  };
  const summary = buildSummary(issues, fileResults, meta);
  return {
    summary,
    files: fileResults.map(f => ({ file: f.rel, type: f.type, size: f.size, lines: f.metrics.lines, ncloc: f.metrics.ncloc, issues: f.issues })),
    issues,
  };
}

/** Public rule metadata (no functions / regex objects). */
const TH = require('./rules-th');
function ruleCatalog() {
  return rules.map(r => ({
    th: TH[r.id] ? { title: TH[r.id][0], description: TH[r.id][1], fix: TH[r.id][2] } : null,
    id: r.id, title: r.title, category: r.category, severity: r.severity,
    deprecated: r.deprecated || null, removed: r.removed || null, changed: r.changed || null, minTarget: r.minTarget || null,
    effort: r.effort, description: r.description, fix: r.fix, before: r.before, after: r.after, docs: r.docs,
    fileTypes: r.fileTypes || ['php'],
    pattern: r.pattern ? r.pattern.source : '(structural check)',
  }));
}

module.exports = { scanProject, analyzeFile, ruleCatalog, fileType, TARGETS, DEFAULT_EXCLUDES, SEVERITIES, v };
