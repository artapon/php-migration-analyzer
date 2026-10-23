'use strict';

/**
 * Lightweight PHP lexer.
 *
 * Splits a PHP source file into regions (inline HTML, code, comments, strings,
 * heredoc/nowdoc) and produces several "views" of the same file. Every view has
 * exactly the same length and line layout as the original, so a match index in
 * any view maps straight back to a line/column in the real file.
 *
 *   raw   - original source
 *   code  - PHP code only (comments, string contents and inline HTML blanked)
 *   src   - PHP code + string contents (comments and inline HTML blanked)
 *   str   - string contents only
 *   dq    - interpolated string contents only ("...", heredoc, `...`)
 */

const KEEP = {
  html:    { raw: 1 },
  code:    { raw: 1, code: 1, src: 1 },
  comment: { raw: 1 },
  sq:      { raw: 1, src: 1, str: 1 },
  dq:      { raw: 1, src: 1, str: 1, dq: 1 },
  nowdoc:  { raw: 1, src: 1, str: 1 },
};

function blank(s) {
  return s.replace(/[^\r\n]/g, ' ');
}

function tokenizeRegions(src) {
  const regions = [];
  const n = src.length;
  let i = 0;
  let start = 0;
  let mode = 'html';

  const push = (end, type) => {
    if (end > start) regions.push([start, end, type]);
    start = end;
  };

  while (i < n) {
    if (mode === 'html') {
      const j = src.indexOf('<?', i);
      if (j === -1) { i = n; break; }
      // <?xml ... is not PHP
      if (/^<\?xml/i.test(src.substr(j, 5))) { i = j + 2; continue; }
      push(j, 'html');
      let tagLen = 2;
      if (/^<\?php/i.test(src.substr(j, 5))) tagLen = 5;
      else if (src[j + 2] === '=') tagLen = 3;
      i = j + tagLen;
      push(i, 'code');
      mode = 'php';
      continue;
    }

    // ---- PHP mode ----
    const c = src[i];
    const c2 = src[i + 1];

    if (c === '?' && c2 === '>') {
      push(i, 'code');
      i += 2;
      push(i, 'code');
      mode = 'html';
      continue;
    }

    // PHP 8 attribute #[Name(...)] – otherwise "#[" is just a comment (PHP 5/7)
    const isAttr = c === '#' && c2 === '[' &&
      /^#\[\s*\\?[A-Za-z_][\w\\]*\s*(\(.*\))?\s*(,\s*\\?[A-Za-z_][\w\\]*\s*(\(.*\))?\s*)*\]\s*$/.test(src.slice(i, (src.indexOf('\n', i) + 1 || n + 1) - 1).trimEnd());
    if (isAttr) { i += 2; continue; }

    // single line comment: // or #   (ends at newline or ?>)
    if ((c === '/' && c2 === '/') || c === '#') {
      push(i, 'code');
      while (i < n && src[i] !== '\n' && !(src[i] === '?' && src[i + 1] === '>')) i++;
      push(i, 'comment');
      continue;
    }
    if (c === '/' && c2 === '*') {
      push(i, 'code');
      const j = src.indexOf('*/', i + 2);
      i = j === -1 ? n : j + 2;
      push(i, 'comment');
      continue;
    }

    if (c === "'" || c === '"' || c === '`') {
      const q = c;
      i++;
      push(i, 'code'); // opening quote stays as code
      while (i < n && src[i] !== q) {
        if (src[i] === '\\') i++;
        i++;
      }
      if (i > n) i = n;
      push(i, q === "'" ? 'sq' : 'dq');
      if (i < n) { i++; push(i, 'code'); } // closing quote
      continue;
    }

    if (c === '<' && c2 === '<' && src[i + 2] === '<') {
      const m = /^<<<[ \t]*(["']?)([A-Za-z_][A-Za-z0-9_]*)\1\r?\n/.exec(src.substr(i, 300));
      if (m) {
        const isNow = m[1] === "'";
        const id = m[2];
        i += m[0].length;
        push(i, 'code');
        const re = new RegExp('(^|\\n)[ \\t]*' + id + '(?![A-Za-z0-9_])', 'g');
        re.lastIndex = i;
        // the closing id may be on the very first body line (empty heredoc)
        let endBody = -1;
        let endId = -1;
        const first = new RegExp('^[ \\t]*' + id + '(?![A-Za-z0-9_])').exec(src.substr(i, id.length + 100));
        if (first) { endBody = i; endId = i + first[0].length; }
        else {
          const mm = re.exec(src);
          if (mm) { endBody = mm.index + mm[1].length; endId = mm.index + mm[0].length; }
        }
        if (endBody === -1) { i = n; push(n, isNow ? 'nowdoc' : 'dq'); continue; }
        i = endBody;
        push(i, isNow ? 'nowdoc' : 'dq');
        i = endId;
        push(i, 'code');
        continue;
      }
    }

    i++;
  }
  if (start < n) push(n, mode === 'html' ? 'html' : 'code');
  return regions;
}

function lex(src) {
  const regions = tokenizeRegions(src);
  const parts = { code: [], src: [], str: [], dq: [] };
  for (const [s, e, type] of regions) {
    const text = src.slice(s, e);
    const keep = KEEP[type];
    const b = blank(text);
    parts.code.push(keep.code ? text : b);
    parts.src.push(keep.src ? text : b);
    parts.str.push(keep.str ? text : b);
    parts.dq.push(keep.dq ? text : b);
  }
  return {
    raw: src,
    code: parts.code.join(''),
    src: parts.src.join(''),
    str: parts.str.join(''),
    dq: parts.dq.join(''),
    hasHtml: regions.some(r => r[2] === 'html' && /\S/.test(src.slice(r[0], r[1]))),
  };
}

/** Returns a function mapping a char index -> {line, col} (1-based). */
function lineIndex(src) {
  const starts = [0];
  for (let i = 0; i < src.length; i++) if (src.charCodeAt(i) === 10) starts.push(i + 1);
  return function locate(idx) {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= idx) lo = mid; else hi = mid - 1;
    }
    return { line: lo + 1, col: idx - starts[lo] + 1 };
  };
}

module.exports = { lex, lineIndex };
