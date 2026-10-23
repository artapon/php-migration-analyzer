#!/usr/bin/env node
'use strict';

/**
 * Command-line scanner (for CI pipelines).
 *
 *   node cli.js <folder> [--target 8.4] [--format text|json|csv] [--out report.json]
 *                        [--exclude vendor,cache] [--fail-on blocker|critical|major|minor|gate|none]
 */
const fs = require('fs');
const path = require('path');
const { scanProject, TARGETS, SEVERITIES } = require('./src/scanner');

const args = process.argv.slice(2);
const opt = (name, def) => {
  const i = args.indexOf('--' + name);
  return i >= 0 && args[i + 1] ? args[i + 1] : def;
};
const root = args.find((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--')));

if (!root || args.includes('--help') || args.includes('-h')) {
  console.log(`Usage: node cli.js <folder> [options]

Options:
  --target <ver>     Target PHP version (${TARGETS.join(', ')})          [default: 8.4]
  --format <fmt>     text | json | csv                                     [default: text]
  --out <file>       Write the report to a file instead of stdout
  --exclude <list>   Comma separated folders to skip                       [default: vendor,node_modules,.git,...]
  --categories <l>   compatibility,security,best-practice                  [default: all]
  --fail-on <level>  Exit with code 1 when issues of this severity (or worse) exist,
                     "gate" = quality gate failed, "none" = always exit 0  [default: gate]`);
  process.exit(root ? 0 : 2);
}

const target = opt('target', '8.4');
const format = opt('format', 'text');
const failOn = opt('fail-on', 'gate');
const exclude = opt('exclude', '') ? opt('exclude').split(',') : undefined;
const categories = opt('categories', '') ? opt('categories').split(',') : undefined;

const C = process.stdout.isTTY && !opt('out') ? {
  red: (s) => `\x1b[31m${s}\x1b[0m`, green: (s) => `\x1b[32m${s}\x1b[0m`, yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`, bold: (s) => `\x1b[1m${s}\x1b[0m`, cyan: (s) => `\x1b[36m${s}\x1b[0m`,
} : new Proxy({}, { get: () => (s) => s });
const sevColor = { blocker: C.red, critical: C.red, major: C.yellow, minor: C.cyan, info: C.dim };

(async () => {
  let lastPct = -1;
  const report = await scanProject(path.resolve(root), { target, exclude, categories }, (p) => {
    if (process.stderr.isTTY && p.total) {
      const pct = Math.floor((p.done / p.total) * 100);
      if (pct !== lastPct) { process.stderr.write(`\rAnalyzing ${p.done}/${p.total} files (${pct}%)   `); lastPct = pct; }
    }
  });
  if (process.stderr.isTTY) process.stderr.write('\r' + ' '.repeat(60) + '\r');

  const s = report.summary;
  let out;
  if (format === 'json') out = JSON.stringify(report, null, 2);
  else if (format === 'csv') {
    const esc = (v) => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
    out = 'severity,category,status,php_version,rule,file,line,message\n' +
      report.issues.map((i) => [i.severity, i.category, i.status, i.version, i.rule, i.file, i.line, i.message].map(esc).join(',')).join('\n');
  } else {
    const lines = [];
    let file = null;
    for (const i of report.issues) {
      if (i.file !== file) { file = i.file; lines.push('', C.bold(file)); }
      lines.push(`  ${String(i.line).padStart(5)}  ${sevColor[i.severity](i.severity.padEnd(8))} ${i.message} ${C.dim('[' + i.rule + ']')}`);
    }
    lines.push('', C.bold(`PHP ${s.meta.target} migration report – ${s.meta.root}`));
    lines.push(`  Files: ${s.metrics.files}  Lines of code: ${s.metrics.ncloc}  Issues: ${s.totals.issues}  Effort: ${s.totals.debt}`);
    lines.push('  ' + SEVERITIES.map((x) => `${sevColor[x](x)}: ${s.bySeverity[x]}`).join('  '));
    lines.push(`  Ratings – compatibility ${s.ratings.compatibility}, security ${s.ratings.security}, maintainability ${s.ratings.maintainability}   Ready files: ${s.readiness}%`);
    for (const c of s.qualityGate.conditions) lines.push(`  ${c.ok ? C.green('✓') : C.red('✕')} ${c.metric}: ${c.actual} (${c.op} ${c.threshold})`);
    lines.push('  Quality gate: ' + (s.qualityGate.status === 'PASSED' ? C.green('PASSED') : C.red('FAILED')));
    out = lines.join('\n');
  }

  const outFile = opt('out');
  if (outFile) { fs.writeFileSync(outFile, out); console.error(`Report written to ${outFile}`); }
  else console.log(out);

  let fail = false;
  if (failOn === 'gate') fail = s.qualityGate.status !== 'PASSED';
  else if (SEVERITIES.includes(failOn)) fail = SEVERITIES.slice(0, SEVERITIES.indexOf(failOn) + 1).some((x) => s.bySeverity[x] > 0);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e.message); process.exit(2); });
