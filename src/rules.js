'use strict';

/**
 * Rule catalog for PHP 5.x -> 8.x migration analysis.
 *
 * Rule fields
 *   id, title, category: 'compatibility' | 'security' | 'best-practice'
 *   severity: blocker | critical | major | minor | info   (severity once removed/changed)
 *   deprecated / removed / changed : PHP version strings ('7.0')
 *   minTarget : rule only applies when target >= this (modern-syntax suggestions)
 *   effort    : estimated minutes to fix one occurrence (technical debt)
 *   view      : which lexer view the pattern runs on (code | src | str | dq | raw)
 *   pattern   : global RegExp     |  check(ctx) -> [{ index, message?, deprecated?, removed?, changed? }]
 *   filter(m, ctx) -> false to drop a match
 *   message(m, ctx) -> string
 *   fileTypes : ['php'] (default) | ['ini'] | ['composer']
 *   description, fix, before, after, docs
 */

const DOC = {
  m54: 'https://www.php.net/manual/en/migration54.incompatible.php',
  m55: 'https://www.php.net/manual/en/migration55.deprecated.php',
  m56: 'https://www.php.net/manual/en/migration56.deprecated.php',
  m70: 'https://www.php.net/manual/en/migration70.incompatible.php',
  m70r: 'https://www.php.net/manual/en/migration70.removed-exts-sapis.php',
  m71: 'https://www.php.net/manual/en/migration71.incompatible.php',
  m72: 'https://www.php.net/manual/en/migration72.deprecated.php',
  m73: 'https://www.php.net/manual/en/migration73.deprecated.php',
  m74: 'https://www.php.net/manual/en/migration74.deprecated.php',
  m74i: 'https://www.php.net/manual/en/migration74.incompatible.php',
  m80: 'https://www.php.net/manual/en/migration80.incompatible.php',
  m80d: 'https://www.php.net/manual/en/migration80.deprecated.php',
  m81: 'https://www.php.net/manual/en/migration81.deprecated.php',
  m81i: 'https://www.php.net/manual/en/migration81.incompatible.php',
  m82: 'https://www.php.net/manual/en/migration82.deprecated.php',
  m83: 'https://www.php.net/manual/en/migration83.deprecated.php',
  m84: 'https://www.php.net/manual/en/migration84.deprecated.php',
  m84r: 'https://www.php.net/manual/en/migration84.removed-extensions.php',
  m85: 'https://www.php.net/manual/en/migration85.deprecated.php',
  owasp: 'https://owasp.org/www-project-top-ten/',
  psr12: 'https://www.php-fig.org/psr/psr-12/',
};

/** Regex for a call to one of the given global functions (not methods, not declarations). */
function fnCall(names) {
  return new RegExp(
    '(?<![\\w$>:\\\\])(?<!function\\s+&?\\s*)\\\\?\\b(' + names.join('|') + ')\\s*\\(',
    'gi'
  );
}

/** Message builder for function-replacement maps. */
function replMsg(map, verb, fallback) {
  return (m) => {
    const name = m[1];
    const r = map[name.toLowerCase()];
    return `${name}() ${verb}. ${r ? 'Use ' + r + ' instead.' : fallback}`;
  };
}

const MYSQL_MAP = {
  mysql_connect: 'mysqli_connect() or new PDO()',
  mysql_pconnect: "mysqli_connect('p:host') or PDO with ATTR_PERSISTENT",
  mysql_query: 'mysqli_query($link, $sql) / PDO::prepare() + execute()',
  mysql_unbuffered_query: 'mysqli_query($link, $sql, MYSQLI_USE_RESULT)',
  mysql_db_query: 'mysqli_select_db() + mysqli_query()',
  mysql_select_db: 'mysqli_select_db($link, $db)',
  mysql_fetch_array: 'mysqli_fetch_array($result)',
  mysql_fetch_assoc: 'mysqli_fetch_assoc($result) / PDOStatement::fetch(PDO::FETCH_ASSOC)',
  mysql_fetch_row: 'mysqli_fetch_row($result)',
  mysql_fetch_object: 'mysqli_fetch_object($result)',
  mysql_num_rows: 'mysqli_num_rows($result) / PDOStatement::rowCount()',
  mysql_affected_rows: 'mysqli_affected_rows($link)',
  mysql_insert_id: 'mysqli_insert_id($link) / PDO::lastInsertId()',
  mysql_real_escape_string: 'prepared statements (mysqli_prepare / PDO::prepare)',
  mysql_escape_string: 'prepared statements (mysqli_prepare / PDO::prepare)',
  mysql_error: 'mysqli_error($link) / PDO exceptions',
  mysql_errno: 'mysqli_errno($link)',
  mysql_close: 'mysqli_close($link)',
  mysql_free_result: 'mysqli_free_result($result)',
  mysql_result: 'mysqli_fetch_row() / mysqli_data_seek()',
  mysql_num_fields: 'mysqli_num_fields($result)',
  mysql_set_charset: "mysqli_set_charset($link, 'utf8mb4')",
  mysql_data_seek: 'mysqli_data_seek($result, $offset)',
};

const EREG_MAP = {
  ereg: "preg_match('/pattern/', $str)",
  eregi: "preg_match('/pattern/i', $str)",
  ereg_replace: "preg_replace('/pattern/', $repl, $str)",
  eregi_replace: "preg_replace('/pattern/i', $repl, $str)",
  split: "preg_split('/pattern/', $str) or explode()",
  spliti: "preg_split('/pattern/i', $str)",
  sql_regcase: 'a case-insensitive preg_* pattern (/i)',
};

const REMOVED80_MAP = {
  money_format: 'NumberFormatter::formatCurrency() (intl)',
  ezmlm_hash: 'a custom implementation',
  restore_include_path: "ini_restore('include_path')",
  hebrevc: 'nl2br(hebrev($str))',
  convert_cyr_string: 'mb_convert_encoding() or iconv()',
  image2wbmp: 'imagewbmp()',
  jpeg2wbmp: 'imagecreatefromjpeg() + imagewbmp()',
  png2wbmp: 'imagecreatefrompng() + imagewbmp()',
  fgetss: 'fgets() + strip_tags()',
  gzgetss: 'gzgets() + strip_tags()',
  is_real: 'is_float()',
  read_exif_data: 'exif_read_data()',
  ldap_sort: 'sorting the results in PHP (usort)',
  ldap_control_paged_result: 'ldap_search() with LDAP_CONTROL_PAGEDRESULTS controls',
  ldap_control_paged_result_response: 'ldap_parse_result() with controls',
  gmp_random: 'gmp_random_bits() / gmp_random_range()',
  mbregex_encoding: 'mb_regex_encoding()',
  mbereg: 'mb_ereg()',
  mberegi: 'mb_eregi()',
  mbereg_replace: 'mb_ereg_replace()',
  mberegi_replace: 'mb_eregi_replace()',
  mbsplit: 'mb_split()',
  mbereg_match: 'mb_ereg_match()',
  mbereg_search: 'mb_ereg_search()',
  mbereg_search_pos: 'mb_ereg_search_pos()',
  mbereg_search_regs: 'mb_ereg_search_regs()',
  mbereg_search_init: 'mb_ereg_search_init()',
  mbereg_search_getregs: 'mb_ereg_search_getregs()',
  mbereg_search_getpos: 'mb_ereg_search_getpos()',
  mbereg_search_setpos: 'mb_ereg_search_setpos()',
};

const SANITIZERS = /htmlspecialchars|htmlentities|intval|\(int\)|\(float\)|filter_var|filter_input|urlencode|rawurlencode|json_encode|strip_tags|escapeshellarg|escapeshellcmd|number_format|basename|\babs\s*\(/i;
const USER_INPUT = String.raw`\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b`;

// ---------------------------------------------------------------------------
// Shared structural parsing (classes / function signatures), cached per file.
// ---------------------------------------------------------------------------

function matchBrace(code, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < code.length; i++) {
    const c = code[i];
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return i; }
  }
  return code.length - 1;
}

function matchParen(code, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < code.length; i++) {
    const c = code[i];
    if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

/** Text of a block where everything nested deeper than one level is blanked. */
function topLevel(code, start, end) {
  let out = '';
  let depth = 0;
  for (let i = start; i < end; i++) {
    const c = code[i];
    if (c === '{') { depth++; out += c; continue; }
    if (c === '}') { depth--; out += c; continue; }
    out += depth > 0 && c !== '\n' ? ' ' : c;
  }
  return out;
}

function getClasses(ctx) {
  if (ctx._classes) return ctx._classes;
  const code = ctx.views.code;
  const re = /(?<![\w$:>])((?:abstract\s+|final\s+|readonly\s+)*)(class|trait|interface)\s+([A-Za-z_]\w*)([^{;]*)\{/gi;
  const list = [];
  let m;
  while ((m = re.exec(code))) {
    const before = code.slice(Math.max(0, m.index - 6), m.index);
    if (/new\s*$/i.test(before)) continue;
    const open = m.index + m[0].length - 1;
    const close = matchBrace(code, open);
    list.push({
      kind: m[2].toLowerCase(),
      name: m[3],
      header: m[4],
      index: m.index,
      nameIndex: m.index + m[0].indexOf(m[3], m[1].length + m[2].length),
      bodyStart: open + 1,
      bodyEnd: close,
      body: code.slice(open + 1, close),
      top: topLevel(code, open + 1, close),
    });
    re.lastIndex = open + 1;
  }
  ctx._classes = list;
  return list;
}

function splitTopLevel(s, sep) {
  const parts = [];
  let depth = 0, cur = '', offs = 0, start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    if (c === sep && depth === 0) { parts.push({ text: cur, offset: start }); cur = ''; start = i + 1; continue; }
    cur += c;
  }
  if (cur.trim() || parts.length) parts.push({ text: cur, offset: start });
  void offs;
  return parts;
}

function getFunctions(ctx) {
  if (ctx._functions) return ctx._functions;
  const code = ctx.views.code;
  const re = /\b(function|fn)\b\s*&?\s*([A-Za-z_]\w*)?\s*\(/gi;
  const list = [];
  let m;
  while ((m = re.exec(code))) {
    const before = code.slice(Math.max(0, m.index - 2), m.index);
    if (/(->|::|\$)$/.test(before)) continue;
    const open = m.index + m[0].length - 1;
    const close = matchParen(code, open);
    if (close === -1) continue;
    const inner = code.slice(open + 1, close);
    const params = splitTopLevel(inner, ',')
      .filter(p => p.text.trim())
      .map(p => {
        const t = p.text;
        const dollar = t.indexOf('$');
        const eq = t.indexOf('=', dollar);
        const typeRaw = dollar >= 0 ? t.slice(0, dollar) : t;
        const type = typeRaw
          .replace(/\b(public|private|protected|readonly)\b/gi, '')
          .replace(/&|\.\.\./g, '')
          .trim();
        const name = (/\$(\w+)/.exec(t) || [])[1] || '?';
        const def = eq >= 0 ? t.slice(eq + 1).trim() : null;
        return {
          name, type, def,
          variadic: t.includes('...'),
          promoted: /\b(public|private|protected)\b/i.test(typeRaw),
          index: open + 1 + p.offset + (dollar >= 0 ? dollar : 0),
        };
      });
    list.push({ name: m[2] || null, index: m.index, open, close, params });
  }
  ctx._functions = list;
  return list;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

const rules = [
  // ======================= REMOVED EXTENSIONS / FUNCTIONS =====================
  {
    id: 'PHP-MYSQL', title: 'Removed mysql_* extension', category: 'compatibility',
    severity: 'blocker', deprecated: '5.5', removed: '7.0', effort: 15, view: 'code',
    pattern: fnCall(['mysql_\\w+']),
    message: replMsg(MYSQL_MAP, 'belongs to the mysql extension, removed in PHP 7.0', 'Rewrite with mysqli or PDO (prepared statements).'),
    description: 'The original MySQL extension (mysql_*) was deprecated in PHP 5.5 and removed in PHP 7.0. Any call is a fatal "Call to undefined function" error on PHP 7+.',
    fix: 'Migrate to PDO (recommended, database-agnostic) or mysqli. Use prepared statements instead of manual escaping. Pass the connection explicitly. If the code base is large, create a thin DB wrapper class first and replace calls with it.',
    before: `$link = mysql_connect('localhost', 'user', 'pass');
mysql_select_db('shop', $link);
$r = mysql_query("SELECT * FROM users WHERE id = " . mysql_real_escape_string($id));
while ($row = mysql_fetch_assoc($r)) { ... }`,
    after: `$pdo = new PDO('mysql:host=localhost;dbname=shop;charset=utf8mb4', 'user', 'pass', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
]);
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);
foreach ($stmt as $row) { ... }`,
    docs: 'https://www.php.net/manual/en/mysqlinfo.api.choosing.php',
  },
  {
    id: 'PHP-EREG', title: 'Removed POSIX regex (ereg) functions', category: 'compatibility',
    severity: 'blocker', deprecated: '5.3', removed: '7.0', effort: 10, view: 'code',
    pattern: fnCall(['ereg', 'eregi', 'ereg_replace', 'eregi_replace', 'split', 'spliti', 'sql_regcase']),
    message: replMsg(EREG_MAP, 'was removed in PHP 7.0', 'Use the preg_* (PCRE) functions.'),
    description: 'The POSIX regex extension (ereg, eregi, ereg_replace, split, ...) was removed in PHP 7.0.',
    fix: 'Replace with PCRE functions. Add delimiters to the pattern (e.g. /.../), use the i modifier for case-insensitive variants, and escape the delimiter inside the pattern. For split() with a plain string separator use explode().',
    before: `if (eregi("^[a-z0-9]+$", $user)) { ... }
$parts = split(",", $csv);`,
    after: `if (preg_match('/^[a-z0-9]+$/i', $user)) { ... }
$parts = explode(',', $csv);`,
    docs: DOC.m70,
  },
  {
    id: 'PHP-MCRYPT', title: 'Removed mcrypt extension', category: 'compatibility',
    severity: 'blocker', deprecated: '7.1', removed: '7.2', effort: 60, view: 'code',
    pattern: fnCall(['mcrypt_\\w+', 'mdecrypt_generic']),
    message: (m) => `${m[1]}() belongs to mcrypt, removed in PHP 7.2. Use openssl_encrypt()/openssl_decrypt() or libsodium (sodium_crypto_secretbox).`,
    description: 'mcrypt has been unmaintained since 2007, was deprecated in 7.1 and removed from core in 7.2.',
    fix: 'Use OpenSSL (openssl_encrypt with AES-256-GCM) or Sodium (sodium_crypto_secretbox). Note that mcrypt used zero-padding; data encrypted with mcrypt must be decrypted with the same algorithm/padding once and re-encrypted.',
    before: `$enc = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);`,
    after: `$iv  = random_bytes(12);
$enc = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);`,
    docs: DOC.m72,
  },
  {
    id: 'PHP-MSSQL', title: 'Removed mssql / sybase extensions', category: 'compatibility',
    severity: 'blocker', removed: '7.0', effort: 30, view: 'code',
    pattern: fnCall(['mssql_\\w+', 'sybase_\\w+']),
    message: (m) => `${m[1]}() was removed in PHP 7.0. Use PDO with the sqlsrv/dblib driver or the sqlsrv_* functions.`,
    description: 'The mssql and sybase_ct extensions were removed in PHP 7.0.',
    fix: 'Use PDO_SQLSRV (Microsoft driver) or PDO_DBLIB, or the sqlsrv_* extension.',
    before: `$c = mssql_connect($srv, $u, $p);\n$r = mssql_query("SELECT ...", $c);`,
    after: `$pdo = new PDO("sqlsrv:Server=$srv;Database=db", $u, $p);\n$r = $pdo->query('SELECT ...');`,
    docs: DOC.m70r,
  },
  {
    id: 'PHP-EXT74', title: 'Extension removed in PHP 7.4 (wddx, recode, interbase)', category: 'compatibility',
    severity: 'blocker', removed: '7.4', effort: 30, view: 'code',
    pattern: fnCall(['wddx_\\w+', 'recode_\\w+', 'recode', 'ibase_\\w+', 'fbird_\\w+']),
    message: (m) => `${m[1]}() belongs to an extension removed from core in PHP 7.4 (moved to PECL).`,
    description: 'ext/wddx, ext/recode and ext/interbase were unbundled in PHP 7.4.',
    fix: 'wddx: use json_encode/serialize. recode: use mb_convert_encoding()/iconv(). interbase: install the PECL extension or use PDO_FIREBIRD.',
    before: `$packet = wddx_serialize_value($data);`, after: `$packet = json_encode($data);`,
    docs: DOC.m74i,
  },
  {
    id: 'PHP-XMLRPC', title: 'xmlrpc extension removed in PHP 8.0', category: 'compatibility',
    severity: 'blocker', removed: '8.0', effort: 30, view: 'code',
    pattern: fnCall(['xmlrpc_\\w+']),
    message: (m) => `${m[1]}() — ext/xmlrpc was moved to PECL in PHP 8.0. Use a userland library such as phpxmlrpc/phpxmlrpc.`,
    description: 'The xmlrpc extension was unbundled in PHP 8.0.',
    fix: 'Install phpxmlrpc/phpxmlrpc via Composer, or the PECL extension.',
    before: `$req = xmlrpc_encode_request('method', $params);`,
    after: `$req = new PhpXmlRpc\\Request('method', [new PhpXmlRpc\\Value($params)]);`,
    docs: DOC.m80,
  },
  {
    id: 'PHP-EXT84', title: 'Extension unbundled in PHP 8.4 (imap, pspell, oci8)', category: 'compatibility',
    severity: 'critical', removed: '8.4', effort: 30, view: 'code',
    pattern: fnCall(['imap_\\w+', 'pspell_\\w+', 'oci_\\w+', 'ocilogon', 'ociplogon', 'ocinlogon', 'ociparse', 'ociexecute', 'ocifetch\\w*', 'ocicommit', 'ocirollback', 'ocilogoff', 'ocibindbyname', 'ocidefinebyname', 'ociresult', 'ocinumcols', 'ocicolumnname', 'ocierror', 'ocifreestatement']),
    message: (m) => `${m[1]}() — this extension was removed from PHP core in 8.4 and must be installed from PECL.`,
    description: 'ext/imap, ext/pspell and ext/oci8 were moved to PECL in PHP 8.4.',
    fix: 'Install the PECL extension on the server, or switch library: imap → webklex/php-imap or ddeboer/imap; oci8 → PDO_OCI or PECL oci8; pspell → enchant.',
    before: `$mbox = imap_open($server, $user, $pass);`,
    after: `// composer require webklex/php-imap\n$client = (new ClientManager())->make([...]);`,
    docs: DOC.m84r,
  },
  {
    id: 'PHP-PREG-E', title: 'preg_replace() /e modifier', category: 'compatibility',
    severity: 'blocker', deprecated: '5.5', removed: '7.0', effort: 20, view: 'src',
    pattern: /\bpreg_replace\s*\(\s*(['"])([^\w\s\\])[^\n]*?\2([a-zA-Z]*)\1/gi,
    filter: (m) => m[3].includes('e'),
    message: () => 'preg_replace() with the /e (eval) modifier was removed in PHP 7.0. Use preg_replace_callback().',
    description: 'The /e modifier evaluated the replacement as PHP code (a code-injection risk). It was removed in 7.0 and now produces a warning and returns NULL.',
    fix: 'Rewrite with preg_replace_callback() and a closure.',
    before: `$s = preg_replace('/(\\w+)/e', 'strtoupper("$1")', $s);`,
    after: `$s = preg_replace_callback('/(\\w+)/', fn($m) => strtoupper($m[1]), $s);`,
    docs: DOC.m70,
  },
  {
    id: 'PHP-ASP-TAGS', title: 'ASP-style / <script language="php"> tags', category: 'compatibility',
    severity: 'blocker', removed: '7.0', effort: 5, view: 'raw',
    pattern: /<script\s+language\s*=\s*["']?php["']?\s*>|<%(?=[\s=])/gi,
    message: () => 'ASP tags (<% %>) and <script language="php"> were removed in PHP 7.0. Use <?php ?>.',
    description: 'Alternative PHP tags were removed in PHP 7.0; the code inside will be sent to the browser as plain text.',
    fix: 'Replace <% with <?php, <%= with <?=, %> with ?>, and <script language="php"> ... </script> with <?php ... ?>. (Ignore if this is a JS template engine such as EJS/underscore.)',
    before: `<% echo $title; %>`, after: `<?php echo $title; ?>`,
    docs: DOC.m70,
  },
  {
    id: 'PHP-CALLTIME-REF', title: 'Call-time pass-by-reference', category: 'compatibility',
    severity: 'blocker', deprecated: '5.3', removed: '5.4', effort: 5, view: 'code',
    pattern: /(?<!function\s+&?)(?<![\w$])(?!(?:function|use|array|list|fn|isset|unset|empty|foreach|for|if|while|elseif|switch|catch|return|echo|print)\b)([A-Za-z_]\w*)\s*\(\s*(?:[^()]*?,\s*)?&\s*\$\w+/gi,
    message: (m) => `Call-time pass-by-reference in ${m[1]}(...&$var) is a fatal error since PHP 5.4. Declare the parameter by reference in the function signature instead.`,
    description: 'Passing a variable by reference at call time (foo(&$x)) is a parse error since PHP 5.4.',
    fix: 'Remove the & from the call; declare the parameter as &$param in the function definition.',
    before: `function inc($n) { $n++; }\ninc(&$count);`, after: `function inc(&$n) { $n++; }\ninc($count);`,
    docs: DOC.m54,
  },
  {
    id: 'PHP-HTTP-VARS', title: 'Removed $HTTP_*_VARS long arrays', category: 'compatibility',
    severity: 'blocker', deprecated: '5.3', removed: '5.4', effort: 2, view: 'code',
    pattern: /\$HTTP_(GET|POST|COOKIE|SERVER|ENV|SESSION|POST_FILES)_VARS\b/g,
    message: (m) => {
      const map = { GET: '$_GET', POST: '$_POST', COOKIE: '$_COOKIE', SERVER: '$_SERVER', ENV: '$_ENV', SESSION: '$_SESSION', POST_FILES: '$_FILES' };
      return `$HTTP_${m[1]}_VARS was removed in PHP 5.4. Use ${map[m[1]]}.`;
    },
    description: 'The long predefined arrays ($HTTP_GET_VARS etc.) were removed together with register_long_arrays in 5.4.',
    fix: 'Replace with the superglobals $_GET, $_POST, $_COOKIE, $_SERVER, $_ENV, $_SESSION, $_FILES.',
    before: `$id = $HTTP_GET_VARS['id'];`, after: `$id = $_GET['id'] ?? null;`,
    docs: DOC.m54,
  },
  {
    id: 'PHP-RAW-POST', title: '$HTTP_RAW_POST_DATA removed', category: 'compatibility',
    severity: 'blocker', deprecated: '5.6', removed: '7.0', effort: 2, view: 'code',
    pattern: /\$HTTP_RAW_POST_DATA\b/g,
    message: () => "$HTTP_RAW_POST_DATA was removed in PHP 7.0. Use file_get_contents('php://input').",
    description: 'always_populate_raw_post_data and $HTTP_RAW_POST_DATA were removed in PHP 7.0.',
    fix: "Read the raw request body with file_get_contents('php://input').",
    before: `$xml = $HTTP_RAW_POST_DATA;`, after: `$xml = file_get_contents('php://input');`,
    docs: DOC.m70,
  },
  {
    id: 'PHP-SESSION-REG', title: 'session_register() family removed', category: 'compatibility',
    severity: 'blocker', deprecated: '5.3', removed: '5.4', effort: 5, view: 'code',
    pattern: fnCall(['session_register', 'session_unregister', 'session_is_registered']),
    message: (m) => `${m[1]}() was removed in PHP 5.4. Read/write $_SESSION directly (isset($_SESSION['x']), unset($_SESSION['x'])).`,
    description: 'session_register(), session_unregister() and session_is_registered() relied on register_globals and were removed in 5.4.',
    fix: "Use $_SESSION['name'] = $value; unset($_SESSION['name']); isset($_SESSION['name']).",
    before: `session_register('user');\n$user = 'bob';`, after: `$_SESSION['user'] = 'bob';`,
    docs: DOC.m54,
  },
  {
    id: 'PHP-REMOVED-54', title: 'Function removed in PHP 5.4', category: 'compatibility',
    severity: 'blocker', removed: '5.4', effort: 5, view: 'code',
    pattern: fnCall(['define_syslog_variables', 'import_request_variables', 'mysqli_bind_param', 'mysqli_bind_result', 'mysqli_client_encoding', 'mysqli_fetch', 'mysqli_param_count', 'mysqli_get_metadata', 'mysqli_send_long_data']),
    message: replMsg({
      import_request_variables: 'explicit $_GET/$_POST access',
      mysqli_bind_param: 'mysqli_stmt_bind_param()', mysqli_bind_result: 'mysqli_stmt_bind_result()',
      mysqli_client_encoding: 'mysqli_character_set_name()', mysqli_fetch: 'mysqli_stmt_fetch()',
      mysqli_param_count: 'mysqli_stmt_param_count()', mysqli_get_metadata: 'mysqli_stmt_result_metadata()',
      mysqli_send_long_data: 'mysqli_stmt_send_long_data()', define_syslog_variables: 'the LOG_* constants directly',
    }, 'was removed in PHP 5.4', ''),
    description: 'Several legacy functions and mysqli aliases were removed in PHP 5.4.',
    fix: 'Use the documented replacement.',
    before: `import_request_variables('gp');`, after: `$id = $_GET['id'] ?? null;`,
    docs: DOC.m54,
  },
  {
    id: 'PHP-MAGIC-QUOTES-RT', title: 'set_magic_quotes_runtime() removed', category: 'compatibility',
    severity: 'blocker', deprecated: '5.3', removed: '7.0', effort: 2, view: 'code',
    pattern: fnCall(['set_magic_quotes_runtime', 'magic_quotes_runtime']),
    message: (m) => `${m[1]}() was removed in PHP 7.0. Delete the call (magic quotes no longer exist).`,
    description: 'Magic quotes were removed in 5.4; the runtime setter was removed in 7.0.',
    fix: 'Remove the call. Make sure the code no longer depends on automatic escaping; use prepared statements and output escaping.',
    before: `set_magic_quotes_runtime(0);`, after: `// removed`,
    docs: DOC.m70,
  },
  {
    id: 'PHP-GET-MAGIC-QUOTES', title: 'get_magic_quotes_gpc() / _runtime()', category: 'compatibility',
    severity: 'blocker', deprecated: '7.4', removed: '8.0', effort: 5, view: 'code',
    pattern: fnCall(['get_magic_quotes_gpc', 'get_magic_quotes_runtime']),
    message: (m) => `${m[1]}() was deprecated in 7.4 and removed in 8.0 (it always returned false since 5.4). Remove the check and the stripslashes() branch.`,
    description: 'These always return false since PHP 5.4 and were removed in 8.0.',
    fix: 'Delete the condition and keep the "magic quotes off" code path.',
    before: `if (get_magic_quotes_gpc()) { $v = stripslashes($v); }`, after: `// magic quotes no longer exist – nothing to do`,
    docs: DOC.m74,
  },
  {
    id: 'PHP-CALL-USER-METHOD', title: 'call_user_method() removed', category: 'compatibility',
    severity: 'blocker', deprecated: '5.3', removed: '7.0', effort: 5, view: 'code',
    pattern: fnCall(['call_user_method', 'call_user_method_array']),
    message: (m) => `${m[1]}() was removed in PHP 7.0. Use call_user_func([$obj, 'method'], ...) / call_user_func_array().`,
    description: 'call_user_method() and call_user_method_array() were removed in PHP 7.0.',
    fix: "Use call_user_func([$object, 'method'], ...$args) or simply $object->$method(...$args).",
    before: `call_user_method('save', $obj, $a);`, after: `$obj->save($a);`,
    docs: DOC.m70,
  },
  {
    id: 'PHP-REMOVED-70', title: 'Function removed in PHP 7.0', category: 'compatibility',
    severity: 'blocker', removed: '7.0', effort: 10, view: 'code',
    pattern: fnCall(['set_socket_blocking', 'datefmt_set_timezone_id', 'imagepsbbox', 'imagepsencodefont', 'imagepsextendcharacter', 'imagepsfreefont', 'imagepsloadfont', 'imagepsslantfont', 'imagepstext']),
    message: replMsg({
      set_socket_blocking: 'stream_set_blocking()', datefmt_set_timezone_id: 'datefmt_set_timezone()',
    }, 'was removed in PHP 7.0', 'PostScript Type1 font support was removed; use TrueType fonts (imagettftext()).'),
    description: 'Functions removed from core in PHP 7.0.',
    fix: 'Use the documented replacement.',
    before: `set_socket_blocking($fp, false);`, after: `stream_set_blocking($fp, false);`,
    docs: DOC.m70,
  },
  {
    id: 'PHP-NEW-BY-REF', title: 'Assigning new by reference (=& new)', category: 'compatibility',
    severity: 'blocker', deprecated: '5.3', removed: '7.0', effort: 1, view: 'code',
    pattern: /=\s*&\s*new\b/gi,
    message: () => '"$x =& new Foo" is a parse error in PHP 7.0. Objects are always handles — use "$x = new Foo".',
    description: 'Assigning the result of new by reference is a parse error since PHP 7.0.',
    fix: 'Remove the &.',
    before: `$db =& new Database();`, after: `$db = new Database();`,
    docs: DOC.m70,
  },
  {
    id: 'PHP-PHP4-CTOR', title: 'PHP 4 style constructor', category: 'compatibility',
    severity: 'blocker', deprecated: '7.0', removed: '8.0', effort: 5, view: 'code',
    check(ctx) {
      const out = [];
      if (/\bnamespace\s+[\w\\]+\s*[;{]/i.test(ctx.views.code)) return out;
      for (const c of getClasses(ctx)) {
        if (c.kind !== 'class') continue;
        if (/\bfunction\s+&?\s*__construct\s*\(/i.test(c.body)) continue;
        const re = new RegExp('\\bfunction\\s+&?\\s*(' + c.name + ')\\s*\\(', 'i');
        const mm = re.exec(c.top);
        if (mm) out.push({ index: c.bodyStart + mm.index, message: `${c.name}::${mm[1]}() is a PHP 4 style constructor. Deprecated in 7.0; in PHP 8.0 it is a normal method and will NOT be called on "new ${c.name}". Rename it to __construct().` });
        const ext = /\bextends\s+\\?([\w\\]+)/i.exec(c.header);
        if (ext) {
          const base = ext[1].split('\\').pop();
          const re2 = new RegExp('\\bparent\\s*::\\s*' + base + '\\s*\\(', 'gi');
          let p;
          while ((p = re2.exec(c.body))) out.push({ index: c.bodyStart + p.index, message: `parent::${base}() calls a PHP 4 style parent constructor. Use parent::__construct().` });
        }
      }
      return out;
    },
    description: 'Methods with the same name as their class were treated as constructors. Deprecated in 7.0; since PHP 8.0 they are ordinary methods — objects silently stop being initialised.',
    fix: 'Rename the method to __construct(). Update subclasses that call parent::ClassName() to parent::__construct().',
    before: `class Cart {\n    function Cart() { $this->items = array(); }\n}`,
    after: `class Cart {\n    private array $items;\n    public function __construct() { $this->items = []; }\n}`,
    docs: DOC.m70,
  },
  {
    id: 'PHP-EACH', title: 'each() removed', category: 'compatibility',
    severity: 'blocker', deprecated: '7.2', removed: '8.0', effort: 5, view: 'code',
    pattern: fnCall(['each']),
    message: () => 'each() was deprecated in 7.2 and removed in 8.0. Use foreach ($array as $key => $value).',
    description: 'each() was removed in PHP 8.0. The classic while (list($k, $v) = each($a)) loop must be rewritten.',
    fix: 'Replace the while/list/each loop with foreach. If the internal pointer is required, use key()/current()/next().',
    before: `reset($arr);\nwhile (list($k, $v) = each($arr)) { ... }`, after: `foreach ($arr as $k => $v) { ... }`,
    docs: DOC.m72,
  },
  {
    id: 'PHP-CREATE-FUNCTION', title: 'create_function() removed', category: 'compatibility',
    severity: 'blocker', deprecated: '7.2', removed: '8.0', effort: 10, view: 'code',
    pattern: fnCall(['create_function']),
    message: () => 'create_function() was deprecated in 7.2 and removed in 8.0 (it uses eval). Use an anonymous function / arrow function.',
    description: 'create_function() compiled code with eval() — slow and insecure. Removed in 8.0.',
    fix: 'Replace with a closure: function ($a, $b) use ($x) { ... } or fn($a) => ...',
    before: `usort($a, create_function('$x,$y', 'return $x - $y;'));`, after: `usort($a, fn($x, $y) => $x <=> $y);`,
    docs: DOC.m72,
  },
  {
    id: 'PHP-AUTOLOAD', title: '__autoload() removed', category: 'compatibility',
    severity: 'blocker', deprecated: '7.2', removed: '8.0', effort: 15, view: 'code',
    pattern: /\bfunction\s+__autoload\s*\(/gi,
    message: () => '__autoload() was deprecated in 7.2 and removed in 8.0. Use spl_autoload_register() or Composer PSR-4 autoloading.',
    description: 'The magic __autoload() function is no longer called in PHP 8.0.',
    fix: 'Register the loader with spl_autoload_register(), or better, adopt Composer autoloading (composer.json "autoload": {"psr-4": {...}}).',
    before: `function __autoload($class) { require "classes/$class.php"; }`,
    after: `spl_autoload_register(function (string $class) {\n    require __DIR__ . "/classes/$class.php";\n});`,
    docs: DOC.m72,
  },
  {
    id: 'PHP-UNSET-CAST', title: '(unset) cast removed', category: 'compatibility',
    severity: 'blocker', deprecated: '7.2', removed: '8.0', effort: 1, view: 'code',
    pattern: /\(\s*unset\s*\)/gi,
    message: () => 'The (unset) cast was removed in PHP 8.0. Assign null instead.',
    description: '(unset)$x always returned null; removed in 8.0.', fix: 'Use null.',
    before: `$x = (unset) $y;`, after: `$x = null;`, docs: DOC.m72,
  },
  {
    id: 'PHP-PARSE-STR', title: 'parse_str() without result argument', category: 'compatibility',
    severity: 'blocker', deprecated: '7.2', removed: '8.0', effort: 3, view: 'code',
    pattern: /(?<![\w$>:])\bparse_str\s*\(\s*(?:[^,()]|\([^()]*\))+\)/gi,
    message: () => 'parse_str() without a second argument (creating variables in the local scope) was removed in PHP 8.0. Pass a result array.',
    description: 'Calling parse_str() with one argument emulated register_globals. The second argument is mandatory in 8.0.',
    fix: 'parse_str($query, $params); then read $params[...].',
    before: `parse_str($_SERVER['QUERY_STRING']);\necho $id;`, after: `parse_str($_SERVER['QUERY_STRING'], $params);\necho $params['id'] ?? '';`,
    docs: DOC.m72,
  },
  {
    id: 'PHP-ASSERT-STRING', title: 'assert() with string argument', category: 'compatibility',
    severity: 'blocker', deprecated: '7.2', removed: '8.0', effort: 3, view: 'code',
    pattern: /(?<![\w$>:])\bassert\s*\(\s*['"]/gi,
    message: () => 'assert() with a string (evaluated as code) was removed in PHP 8.0. Pass a boolean expression.',
    description: 'String assertions were evaluated with eval(). Removed in 8.0.',
    fix: 'Pass the expression itself: assert($x > 0).',
    before: `assert('$x > 0');`, after: `assert($x > 0);`, docs: DOC.m72,
  },
  {
    id: 'PHP-ERRORMSG', title: '$php_errormsg removed', category: 'compatibility',
    severity: 'blocker', deprecated: '7.2', removed: '8.0', effort: 5, view: 'code',
    pattern: /\$php_errormsg\b/g,
    message: () => '$php_errormsg (track_errors) was removed in PHP 8.0. Use error_get_last().',
    description: 'track_errors and $php_errormsg were removed in 8.0.',
    fix: "Use error_get_last()['message'] or, better, exceptions.",
    before: `$f = @fopen($p, 'r'); if (!$f) echo $php_errormsg;`,
    after: `$f = @fopen($p, 'r'); if (!$f) echo error_get_last()['message'] ?? '';`,
    docs: DOC.m72,
  },
  {
    id: 'PHP-REMOVED-80', title: 'Function removed in PHP 8.0', category: 'compatibility',
    severity: 'blocker', deprecated: '7.4', removed: '8.0', effort: 10, view: 'code',
    pattern: fnCall(Object.keys(REMOVED80_MAP)),
    message: replMsg(REMOVED80_MAP, 'was removed in PHP 8.0', ''),
    description: 'Functions deprecated during 7.x and removed in PHP 8.0.',
    fix: 'Use the documented replacement.',
    before: `if (is_real($v)) echo money_format('%i', $v);`,
    after: `if (is_float($v)) echo (new NumberFormatter('en_US', NumberFormatter::CURRENCY))->formatCurrency($v, 'USD');`,
    docs: DOC.m80,
  },
  {
    id: 'PHP-STRING-BRACES', title: 'Curly brace string/array offset $s{0}', category: 'compatibility',
    severity: 'blocker', deprecated: '7.4', removed: '8.0', effort: 1, view: 'code',
    pattern: /(?:\$[A-Za-z_]\w*(?:->\w+)*|\])\{/g,
    filter: (m, ctx, idx) => {
      // ignore "$var {" followed by statements (e.g. alt. syntax is impossible here) – require closing brace on same line
      const rest = ctx.views.code.slice(idx + m[0].length, idx + m[0].length + 60);
      return /^[^{}\n;]*\}/.test(rest);
    },
    message: () => 'Accessing offsets with curly braces ($str{0}) is a fatal error since PHP 8.0. Use square brackets ($str[0]).',
    description: 'Array and string offset access using curly braces was deprecated in 7.4 and removed in 8.0.',
    fix: 'Replace {} with [].',
    before: `$first = $name{0};`, after: `$first = $name[0];`, docs: DOC.m74,
  },
  {
    id: 'PHP-NESTED-TERNARY', title: 'Unparenthesized nested ternary', category: 'compatibility',
    severity: 'blocker', deprecated: '7.4', removed: '8.0', effort: 3, view: 'code',
    pattern: /(?<![?])\?(?![?>:=])[^;:?()\n]*(?<!:):(?![:])[^;?()\n]*(?<!\?)\?(?![?>:=-])/g,
    message: () => 'Nested ternary without parentheses (a ? b : c ? d : e) is a fatal error since PHP 8.0. Add parentheses or use if/match.',
    description: 'PHP\'s left-associative ternary was confusing; nesting without explicit parentheses is a compile error in 8.0.',
    fix: 'Add explicit parentheses, or rewrite with if/elseif or a match expression (PHP 8).',
    before: `$r = $a ? 'A' : $b ? 'B' : 'C';`, after: `$r = $a ? 'A' : ($b ? 'B' : 'C');`, docs: DOC.m74,
  },
  {
    id: 'PHP-CONCAT-PRECEDENCE', title: 'Concatenation with unparenthesized +/-', category: 'compatibility',
    severity: 'major', deprecated: '7.4', changed: '8.0', effort: 2, view: 'code',
    pattern: /['"]\s*\.\s*\$[A-Za-z_]\w*(?:(?:->|::)\w+|\[[^\]\n]*\])*\s*[+\-](?![+\-=>])\s*[$\d(]/g,
    message: () => 'In PHP 8.0 "+" and "-" bind tighter than "." — "Sum: " . $a + $b now means "Sum: " . ($a + $b). Add parentheses to make intent explicit.',
    description: 'The precedence of the concatenation operator was lowered in PHP 8.0. Code relying on the old precedence silently produces different output.',
    fix: 'Wrap the arithmetic part in parentheses.',
    before: `echo "Total: " . $a + $b;`, after: `echo "Total: " . ($a + $b);`, docs: DOC.m74,
  },
  {
    id: 'PHP-RESERVED-NAME', title: 'Class name is a reserved word', category: 'compatibility',
    severity: 'blocker', removed: '7.0', effort: 30, view: 'code',
    pattern: /(?<![\w$])(?:class|interface|trait)\s+(int|float|bool|string|null|true|false|void|iterable|object|mixed|never|resource|numeric)\b(?!\s*::)/gi,
    filter: (m, ctx) => ctx.v(RESERVED[m[1].toLowerCase()]) <= ctx.target,
    message: (m) => `"${m[1]}" is reserved since PHP ${RESERVED[m[1].toLowerCase()]} and cannot be used as a class/interface/trait name. Rename it (e.g. ${m[1][0].toUpperCase() + m[1].slice(1)}Value) and update all references.`,
    description: 'PHP 7+ reserves scalar type names (int, float, bool, string, null, true, false, void, iterable, object, mixed, never…).',
    fix: 'Rename the class and all usages; a namespace does not help.',
    before: `class String { ... }`, after: `class StringHelper { ... }`, docs: DOC.m70,
  },
  {
    id: 'PHP-MATCH-KEYWORD', title: 'match is a reserved keyword', category: 'compatibility',
    severity: 'critical', removed: '8.0', effort: 15, view: 'code',
    pattern: /(?<![\w$>:\\])(?<!function\s+&?)\bmatch\s*\(/gi,
    filter: (m, ctx, idx) => {
      const close = matchParen(ctx.views.code, idx + m[0].length - 1);
      return !(close > 0 && /^\s*\{/.test(ctx.views.code.slice(close + 1, close + 20)));
    },
    message: () => 'A global function called match() cannot be called in PHP 8.0 — match is now a keyword. Rename the function.',
    description: '"match" became a reserved keyword in PHP 8.0 (match expression). Global functions/classes named match must be renamed. Methods ($obj->match()) are fine.',
    fix: 'Rename the function (e.g. matchPattern) and update callers.',
    before: `function match($a, $b) { ... }\nmatch($x, $y);`, after: `function matchValues($a, $b) { ... }\nmatchValues($x, $y);`, docs: DOC.m80,
  },
  {
    id: 'PHP-GLOBAL-VARVAR', title: 'global with complex variable-variable', category: 'compatibility',
    severity: 'blocker', removed: '7.0', effort: 3, view: 'code',
    pattern: /\bglobal\s+[^;]*\$\$\w+\s*(?:->|\[)/gi,
    message: () => '"global $$foo->bar" is no longer allowed in PHP 7.0. Use global ${$foo->bar}.',
    description: 'The global keyword only accepts simple variables since PHP 7.0.',
    fix: 'Wrap the expression in braces: global ${$foo->bar}; or avoid globals entirely.',
    before: `global $$conf['db'];`, after: `global \${$conf['db']};`, docs: DOC.m70,
  },
  {
    id: 'PHP-UVS', title: 'Uniform variable syntax change', category: 'compatibility',
    severity: 'critical', changed: '7.0', effort: 10, view: 'code',
    pattern: /\$\$[A-Za-z_]\w*\s*\[|->\$[A-Za-z_]\w*\s*\[|::\$[A-Za-z_]\w*\s*\[[^\]\n]*\]\s*\(/g,
    message: (m) => `Expression "${m[0].trim()}…" is evaluated left-to-right since PHP 7.0 (uniform variable syntax). Add braces to make the intended meaning explicit, e.g. \${$name['key']} or $obj->{$prop['key']}.`,
    description: 'PHP 7.0 changed how indirect variable, property and method references are evaluated. $$foo[\'bar\'] meant ${$foo[\'bar\']} in PHP 5 but ($$foo)[\'bar\'] in PHP 7.',
    fix: 'Add explicit curly braces to restore the PHP 5 meaning.',
    before: `echo $$name['key'];\n$obj->$prop['key'];`, after: `echo \${$name['key']};\n$obj->{$prop['key']};`, docs: DOC.m70,
  },
  {
    id: 'PHP-THIS-REASSIGN', title: 'Re-assigning $this', category: 'compatibility',
    severity: 'blocker', removed: '7.1', effort: 5, view: 'code',
    pattern: /\$this\s*=(?![=>])|\bunset\s*\(\s*\$this\s*\)|\bglobal\s+\$this\b|\bcatch\s*\([^)]*\$this\s*\)/gi,
    message: () => '$this cannot be re-assigned, unset or used as a global/catch variable since PHP 7.1.',
    description: 'PHP 7.1 forbids re-assigning $this.', fix: 'Use another variable name.',
    before: `$this = new Foo();`, after: `$self = new Foo();`, docs: DOC.m71,
  },
  {
    id: 'PHP-REAL-CAST', title: '(real) cast removed', category: 'compatibility',
    severity: 'blocker', deprecated: '7.4', removed: '8.0', effort: 1, view: 'code',
    pattern: /\(\s*real\s*\)/gi,
    message: () => 'The (real) cast was removed in PHP 8.0. Use (float).',
    description: '(real) was an alias of (float). Removed in 8.0.', fix: 'Use (float).',
    before: `$f = (real) $s;`, after: `$f = (float) $s;`, docs: DOC.m74,
  },
  {
    id: 'PHP-DEFINE-CI', title: 'Case-insensitive constants', category: 'compatibility',
    severity: 'blocker', deprecated: '7.3', removed: '8.0', effort: 5, view: 'code',
    pattern: /(?<![\w$>:])\bdefine\s*\([^;]*,\s*(?:true|1)\s*\)\s*;/gi,
    message: () => 'define() with the case-insensitive flag (third argument true) was removed in PHP 8.0.',
    description: 'Case-insensitive constants were deprecated in 7.3 and removed in 8.0. The 3rd argument is ignored with a warning.',
    fix: 'Drop the third argument and use the constant with its exact case everywhere.',
    before: `define('APP_NAME', 'Shop', true);\necho app_name;`, after: `define('APP_NAME', 'Shop');\necho APP_NAME;`, docs: DOC.m73,
  },
  {
    id: 'PHP-FILTER-FLAGS', title: 'FILTER_FLAG_SCHEME/HOST_REQUIRED removed', category: 'compatibility',
    severity: 'blocker', deprecated: '7.3', removed: '8.0', effort: 1, view: 'code',
    pattern: /\bFILTER_FLAG_(?:SCHEME|HOST)_REQUIRED\b/g,
    message: (m) => `${m[0]} was removed in PHP 8.0 (it is implied by FILTER_VALIDATE_URL). Remove the flag.`,
    description: 'These flags have always been implied by FILTER_VALIDATE_URL.', fix: 'Remove the flag.',
    before: `filter_var($u, FILTER_VALIDATE_URL, FILTER_FLAG_SCHEME_REQUIRED);`, after: `filter_var($u, FILTER_VALIDATE_URL);`, docs: DOC.m73,
  },
  {
    id: 'PHP-STRPOS-INT-NEEDLE', title: 'Integer needle in string search functions', category: 'compatibility',
    severity: 'major', deprecated: '7.3', changed: '8.0', effort: 2, view: 'code',
    pattern: /(?<![\w$>:])\b(strpos|stripos|strrpos|strripos|strstr|stristr|strrchr|strchr|substr_count)\s*\([^,()]+,\s*\d+\s*[,)]/gi,
    message: (m) => `${m[1]}() with an integer needle: PHP < 8 treated it as a character code (chr()); PHP 8 searches for the digits as a string.`,
    description: 'Non-string needles were interpreted as ASCII codes before PHP 8.0.',
    fix: "Pass a string: chr(65) if the character code was intended, or '65' for the digits.",
    before: `strpos($s, 65);`, after: `strpos($s, chr(65)); // or '65'`, docs: DOC.m73,
  },
  {
    id: 'PHP-IMPLODE-ORDER', title: 'implode() with reversed arguments', category: 'compatibility',
    severity: 'blocker', deprecated: '7.4', removed: '8.0', effort: 1, view: 'code',
    pattern: /(?<![\w$>:])\b(implode|join)\s*\(\s*\$\w+(?:->\w+|\[[^\]\n]*\])*\s*,\s*['"][^'"\n]*['"]\s*\)/gi,
    message: (m) => `${m[1]}($array, $glue) — the legacy argument order was removed in PHP 8.0. Use ${m[1]}($glue, $array).`,
    description: 'Passing the separator after the array was deprecated in 7.4 and removed in 8.0.',
    fix: 'Swap the arguments.',
    before: `implode($ids, ',');`, after: `implode(',', $ids);`, docs: DOC.m74,
  },
  {
    id: 'PHP-HASH-COMMENT-ATTR', title: '#[ comment becomes an attribute', category: 'compatibility',
    severity: 'critical', changed: '8.0', effort: 1, view: 'raw',
    pattern: /(?:^|\n)[ \t]*#\[(?!\s*\\?(?:ReturnTypeWillChange|AllowDynamicProperties|Attribute|SensitiveParameter|Override|Deprecated)\b)/g,
    filter: (m, ctx) => !/\b(?:declare\s*\(\s*strict_types|\?->|match\s*\()/.test(ctx.views.code),
    message: () => 'A comment starting with "#[" is parsed as an attribute in PHP 8.0. Change it to "// [" or "# [".',
    description: 'PHP 8 attributes use #[...]. Old comments starting with #[ become syntax errors or attributes.',
    fix: 'Insert a space ("# [") or use // comments.',
    before: `#[TODO] fix later`, after: `// [TODO] fix later`, docs: DOC.m80,
  },
  {
    id: 'PHP-REQUIRED-AFTER-OPTIONAL', title: 'Optional parameter before required parameter', category: 'compatibility',
    severity: 'major', deprecated: '8.0', effort: 3, view: 'code',
    check(ctx) {
      const out = [];
      for (const f of getFunctions(ctx)) {
        let optional = null;
        for (const p of f.params) {
          if (p.def !== null && !p.variadic) {
            const nullableTyped = p.type && /^null$/i.test(p.def);
            if (!nullableTyped && !optional) optional = p;
          } else if (!p.variadic && optional) {
            out.push({ index: optional.index, message: `Optional parameter $${optional.name} is declared before required parameter $${p.name}${f.name ? ' in ' + f.name + '()' : ''}. Deprecated in PHP 8.0 – the default value is ignored.` });
            break;
          }
        }
      }
      return out;
    },
    description: 'Declaring a required parameter after an optional one is deprecated since PHP 8.0; the default value has no effect.',
    fix: 'Remove the default value, or move optional parameters to the end of the list.',
    before: `function connect($host = 'localhost', $port) {}`, after: `function connect($port, $host = 'localhost') {}`, docs: DOC.m80d,
  },
  {
    id: 'PHP-ZIP-PROCEDURAL', title: 'Procedural zip_* API deprecated', category: 'compatibility',
    severity: 'major', deprecated: '8.0', effort: 15, view: 'code',
    pattern: fnCall(['zip_open', 'zip_read', 'zip_close', 'zip_entry_\\w+']),
    message: (m) => `${m[1]}() is deprecated since PHP 8.0. Use the ZipArchive class.`,
    description: 'The procedural Zip API is deprecated in favour of ZipArchive.',
    fix: 'Use ZipArchive::open(), ::getFromIndex(), ::extractTo().',
    before: `$z = zip_open($file);\nwhile ($e = zip_read($z)) { ... }`, after: `$z = new ZipArchive();\n$z->open($file);\n$z->extractTo($dir);`, docs: DOC.m80d,
  },
  {
    id: 'PHP-LIBXML-ENTITY', title: 'libxml_disable_entity_loader() deprecated', category: 'compatibility',
    severity: 'major', deprecated: '8.0', effort: 2, view: 'code',
    pattern: fnCall(['libxml_disable_entity_loader']),
    message: () => 'libxml_disable_entity_loader() is deprecated since PHP 8.0; external entity loading is disabled by default with libxml >= 2.9. Remove the call.',
    description: 'Unnecessary since libxml 2.9.', fix: 'Remove the call; never pass LIBXML_NOENT on untrusted input.',
    before: `libxml_disable_entity_loader(true);`, after: `// not needed in PHP 8`, docs: DOC.m80d,
  },
  {
    id: 'PHP-SET-EXC-HANDLER', title: 'Exception handler typed with Exception', category: 'compatibility',
    severity: 'major', changed: '7.0', effort: 2, view: 'code',
    pattern: /\bset_exception_handler\s*\(\s*function\s*\(\s*\\?Exception\b/gi,
    message: () => 'In PHP 7+ the exception handler may receive Error objects (Throwable). Typing the parameter as Exception causes a TypeError. Use Throwable.',
    description: 'Engine errors are thrown as Error (not Exception) in PHP 7.', fix: 'Type the parameter as \\Throwable.',
    before: `set_exception_handler(function (Exception $e) { ... });`, after: `set_exception_handler(function (Throwable $e) { ... });`, docs: DOC.m70,
  },
  {
    id: 'PHP-SUPPRESS-OP', title: 'Error suppression operator @', category: 'compatibility',
    severity: 'minor', changed: '8.0', effort: 5, view: 'code',
    pattern: /(?<![\w)\]])@\s*(?=[$\\A-Za-z_(])/g,
    message: () => 'The @ operator no longer silences fatal errors in PHP 8.0 and hides problems. Handle the error explicitly (check return values, try/catch).',
    description: 'In PHP 8 @ no longer suppresses fatal errors (E_ERROR, E_CORE_ERROR, …) and many warnings became exceptions.',
    fix: 'Check pre-conditions (file_exists, isset) or catch exceptions instead of silencing.',
    before: `$v = @$arr['key'];\n$f = @fopen($path, 'r');`, after: `$v = $arr['key'] ?? null;\nif (is_readable($path)) { $f = fopen($path, 'r'); }`, docs: DOC.m80,
  },
  {
    id: 'PHP-LOOSE-ZERO', title: 'Loose comparison with 0 / empty string', category: 'compatibility',
    severity: 'minor', changed: '8.0', effort: 2, view: 'code',
    pattern: /(?<![=!<>])(?:==|!=|<>)(?!=)\s*(?:0(?![\d.xXbB])|''|"")|(?<![\w.$'"])(?:0|''|"")\s*(?:==|!=|<>)(?!=)/g,
    message: () => 'PHP 8 changed string-to-number comparison: 0 == "abc" is now false (was true). Review this loose comparison; prefer === / !==.',
    description: 'Saner string to number comparisons (PHP 8.0): non-numeric strings are no longer converted to 0 when compared with numbers.',
    fix: 'Use strict comparison (===, !==) and explicit casts, or empty()/is_numeric() where intended.',
    before: `if ($status == 0) { ... }   // true for "pending" in PHP 5/7, false in PHP 8`, after: `if ((int) $status === 0) { ... }`, docs: DOC.m80,
  },
  {
    id: 'PHP-RETURN-TYPE-WILL-CHANGE', title: 'Internal interface method without return type', category: 'compatibility',
    severity: 'major', deprecated: '8.1', effort: 2, view: 'code',
    check(ctx) {
      const out = [];
      const ifaceRe = /\b(?:implements\b[^{]*\b(?:ArrayAccess|Iterator|IteratorAggregate|Countable|JsonSerializable|SeekableIterator|RecursiveIterator|OuterIterator)\b|extends\s+\\?(?:ArrayObject|ArrayIterator|IteratorIterator|FilterIterator|RecursiveIteratorIterator|SplObjectStorage|SplDoublyLinkedList|SplFixedArray|SplHeap|SplPriorityQueue))/i;
      for (const c of getClasses(ctx)) {
        if (c.kind === 'interface' || !ifaceRe.test(c.header)) continue;
        const re = /\bfunction\s+&?\s*(offsetGet|offsetSet|offsetExists|offsetUnset|current|key|next|rewind|valid|count|getIterator|jsonSerialize|seek|hasChildren|getChildren|accept)\s*\(/gi;
        let m;
        while ((m = re.exec(c.top))) {
          const abs = c.bodyStart + m.index;
          const close = matchParen(ctx.views.code, abs + m[0].length - 1);
          if (close < 0) continue;
          if (/^\s*:/.test(ctx.views.code.slice(close + 1, close + 10))) continue;
          if (/ReturnTypeWillChange/.test(ctx.views.raw.slice(Math.max(0, abs - 300), abs))) continue;
          out.push({ index: abs, message: `${c.name}::${m[1]}() must declare a return type compatible with the internal interface (or add #[\\ReturnTypeWillChange]). Deprecated in PHP 8.1.` });
        }
      }
      return out;
    },
    description: 'PHP 8.1 added tentative return types to internal interfaces (ArrayAccess, Iterator, Countable, JsonSerializable...). Implementations without a compatible return type raise a deprecation notice.',
    fix: 'Add the return type (offsetGet(mixed $offset): mixed, count(): int, ...). If you still need PHP 7 compatibility, add #[\\ReturnTypeWillChange] above the method.',
    before: `public function count() { return count($this->items); }`, after: `public function count(): int { return count($this->items); }`, docs: DOC.m81,
  },
  {
    id: 'PHP-STRFTIME', title: 'strftime() / gmstrftime() deprecated', category: 'compatibility',
    severity: 'major', deprecated: '8.1', effort: 10, view: 'code',
    pattern: fnCall(['strftime', 'gmstrftime', 'strptime']),
    message: (m) => `${m[1]}() is deprecated since PHP 8.1. Use date()/DateTime::format() or IntlDateFormatter for localised dates.`,
    description: 'strftime family is deprecated in 8.1 (platform-dependent behaviour).',
    fix: 'Use DateTimeInterface::format(), or IntlDateFormatter for locale-aware formatting (e.g. Thai month names).',
    before: `echo strftime('%d %B %Y', $ts);`, after: `$fmt = new IntlDateFormatter('th_TH', IntlDateFormatter::LONG, IntlDateFormatter::NONE);\necho $fmt->format($ts);`, docs: DOC.m81,
  },
  {
    id: 'PHP-MHASH', title: 'mhash() functions deprecated', category: 'compatibility',
    severity: 'major', deprecated: '8.1', effort: 5, view: 'code',
    pattern: fnCall(['mhash', 'mhash_\\w+']),
    message: (m) => `${m[1]}() is deprecated since PHP 8.1. Use hash() / hash_hmac().`,
    description: 'mhash functions are deprecated in 8.1.', fix: 'Use the hash extension.',
    before: `mhash(MHASH_SHA256, $data, $key);`, after: `hash_hmac('sha256', $data, $key, true);`, docs: DOC.m81,
  },
  {
    id: 'PHP-DATE-SUN', title: 'date_sunrise()/date_sunset() deprecated', category: 'compatibility',
    severity: 'minor', deprecated: '8.1', effort: 5, view: 'code',
    pattern: fnCall(['date_sunrise', 'date_sunset']),
    message: (m) => `${m[1]}() is deprecated since PHP 8.1. Use date_sun_info().`,
    description: 'Deprecated in 8.1.', fix: 'Use date_sun_info().',
    before: `date_sunrise($ts, SUNFUNCS_RET_STRING, $lat, $lng);`, after: `date_sun_info($ts, $lat, $lng)['sunrise'];`, docs: DOC.m81,
  },
  {
    id: 'PHP-FILTER-SANITIZE-STRING', title: 'FILTER_SANITIZE_STRING deprecated', category: 'compatibility',
    severity: 'major', deprecated: '8.1', effort: 5, view: 'code',
    pattern: /\bFILTER_SANITIZE_(?:STRING|STRIPPED)\b/g,
    message: (m) => `${m[0]} is deprecated since PHP 8.1. Use htmlspecialchars() when outputting, or FILTER_UNSAFE_RAW + validation.`,
    description: 'The filter was misleading (it does not protect against XSS in all contexts). Deprecated in 8.1.',
    fix: 'Validate input with a specific filter, escape on output with htmlspecialchars().',
    before: `$name = filter_input(INPUT_POST, 'name', FILTER_SANITIZE_STRING);`, after: `$name = trim((string) filter_input(INPUT_POST, 'name'));\necho htmlspecialchars($name, ENT_QUOTES, 'UTF-8');`, docs: DOC.m81,
  },
  {
    id: 'PHP-ODBC-RESULT-ALL', title: 'odbc_result_all() deprecated', category: 'compatibility',
    severity: 'minor', deprecated: '8.1', effort: 10, view: 'code',
    pattern: fnCall(['odbc_result_all']),
    message: () => 'odbc_result_all() is deprecated since PHP 8.1. Build the HTML table yourself with odbc_fetch_array().',
    description: 'Deprecated in 8.1.', fix: 'Loop over odbc_fetch_array().',
    before: `odbc_result_all($r);`, after: `while ($row = odbc_fetch_array($r)) { ... }`, docs: DOC.m81,
  },
  {
    id: 'PHP-SERIALIZABLE', title: 'Serializable interface without __serialize()', category: 'compatibility',
    severity: 'minor', deprecated: '8.1', effort: 15, view: 'code',
    pattern: /\bimplements\b[^{]*\bSerializable\b/gi,
    filter: (m, ctx) => !/function\s+__serialize\s*\(/i.test(ctx.views.code),
    message: () => 'Implementing Serializable without __serialize()/__unserialize() is deprecated since PHP 8.1.',
    description: 'The Serializable interface is superseded by the __serialize()/__unserialize() magic methods (7.4).',
    fix: 'Add __serialize(): array and __unserialize(array $data): void.',
    before: `class A implements Serializable { function serialize() {...} function unserialize($s) {...} }`,
    after: `class A {\n    public function __serialize(): array { return ['x' => $this->x]; }\n    public function __unserialize(array $d): void { $this->x = $d['x']; }\n}`, docs: DOC.m81,
  },
  {
    id: 'PHP-GLOBALS-WRITE', title: 'Writing to $GLOBALS as a whole', category: 'compatibility',
    severity: 'blocker', removed: '8.1', effort: 5, view: 'code',
    pattern: /\$GLOBALS\s*(?:=(?![=>])|\+=)|\bunset\s*\(\s*\$GLOBALS\s*\)|&\s*\$GLOBALS\b(?!\s*\[)|\barray_\w+\s*\(\s*\$GLOBALS\s*[,)]/g,
    filter: (m) => !/^array_(key_exists|keys|values|search|filter|map|slice)/i.test(m[0]),
    message: () => 'Since PHP 8.1 $GLOBALS can no longer be written/modified as a whole (only $GLOBALS[\'name\'] = ... is allowed).',
    description: 'PHP 8.1 restricted $GLOBALS usage: it is now a read-only copy when used as a whole.',
    fix: "Write individual entries: $GLOBALS['x'] = 1; better, remove global state.",
    before: `$GLOBALS = array();`, after: `foreach (array_keys($GLOBALS) as $k) { /* explicit */ }`, docs: DOC.m81i,
  },
  {
    id: 'PHP-CTYPE-INT', title: 'ctype_* with integer argument', category: 'compatibility',
    severity: 'minor', deprecated: '8.1', effort: 2, view: 'code',
    pattern: /(?<![\w$>:])\b(ctype_\w+)\s*\(\s*-?\d+\s*\)/gi,
    message: (m) => `${m[1]}() with an int argument is deprecated since PHP 8.1. Pass a string.`,
    description: 'ctype functions treated ints as ASCII codes. Deprecated in 8.1.', fix: 'Cast to string.',
    before: `ctype_digit(5);`, after: `ctype_digit('5');`, docs: DOC.m81,
  },
  {
    id: 'PHP-UTF8-ENCODE', title: 'utf8_encode() / utf8_decode() deprecated', category: 'compatibility',
    severity: 'major', deprecated: '8.2', effort: 5, view: 'code',
    pattern: fnCall(['utf8_encode', 'utf8_decode']),
    message: (m) => `${m[1]}() is deprecated since PHP 8.2 (it only converts ISO-8859-1). Use mb_convert_encoding($s, 'UTF-8', 'ISO-8859-1') or the correct source encoding (e.g. 'TIS-620', 'Windows-1252').`,
    description: 'These functions only convert Latin-1 and were commonly misused. Deprecated in 8.2.',
    fix: 'Use mb_convert_encoding() with an explicit source encoding.',
    before: `$s = utf8_encode($legacy);`, after: `$s = mb_convert_encoding($legacy, 'UTF-8', 'ISO-8859-1');`, docs: DOC.m82,
  },
  {
    id: 'PHP-DOLLAR-BRACE-INTERP', title: '"${var}" string interpolation', category: 'compatibility',
    severity: 'major', deprecated: '8.2', effort: 1, view: 'dq',
    pattern: /(?<![{\\])\$\{/g,
    message: () => '"${var}" and "${expr}" interpolation is deprecated since PHP 8.2. Use "{$var}".',
    description: 'Dollar-brace interpolation inside strings is deprecated in PHP 8.2.',
    fix: 'Use "{$var}" or "{$arr[\'key\']}".',
    before: `echo "Hello \${name}";`, after: `echo "Hello {$name}";`, docs: DOC.m82,
  },
  {
    id: 'PHP-PARTIAL-CALLABLE', title: '"self::method" style callables', category: 'compatibility',
    severity: 'major', deprecated: '8.2', effort: 3, view: 'src',
    pattern: /(?:\[|array\s*\()\s*(['"])(?:self|parent|static)\1\s*,|(['"])(?:self|parent|static)::\w+\2/gi,
    message: () => 'Callables like "self::method" / [\'self\', \'method\'] are deprecated since PHP 8.2. Use self::class . \'::method\', [self::class, \'method\'] or first-class callables (self::method(...)).',
    description: 'Partially supported callables are deprecated in PHP 8.2.',
    fix: 'Use [static::class, \'method\'] or the PHP 8.1 first-class callable syntax.',
    before: `array_map('self::format', $rows);`, after: `array_map(self::format(...), $rows);`, docs: DOC.m82,
  },
  {
    id: 'PHP-MB-ENCODINGS', title: 'mbstring HTML-ENTITIES / BASE64 / QPrint / UUencode', category: 'compatibility',
    severity: 'major', deprecated: '8.2', effort: 3, view: 'src',
    pattern: /\bmb_\w+\s*\([^;]*?(['"])(HTML-ENTITIES|HTML|BASE64|UUENCODE|QUOTED-PRINTABLE|Quoted-Printable|QPrint)\1/gi,
    message: (m) => `mbstring "${m[2]}" pseudo-encoding is deprecated since PHP 8.2. Use htmlspecialchars()/htmlentities(), base64_encode(), quoted_printable_encode() or convert_uuencode().`,
    description: 'Using mbstring for non-text encodings is deprecated in 8.2.',
    fix: 'Use the dedicated function for that encoding.',
    before: `mb_convert_encoding($html, 'HTML-ENTITIES', 'UTF-8');`, after: `htmlspecialchars_decode(htmlentities($html, ENT_QUOTES, 'UTF-8'));`, docs: DOC.m82,
  },
  {
    id: 'PHP-DYNAMIC-PROPERTY', title: 'Dynamic property creation', category: 'compatibility',
    severity: 'major', deprecated: '8.2', effort: 3, view: 'code',
    check(ctx) {
      const out = [];
      for (const c of getClasses(ctx)) {
        if (c.kind !== 'class') continue;
        if (/\bextends\b/i.test(c.header)) continue;
        if (/function\s+__set\s*\(/i.test(c.body)) continue;
        if (/AllowDynamicProperties/.test(ctx.views.raw.slice(Math.max(0, c.index - 200), c.index))) continue;
        const declared = new Set();
        let d;
        // drop method signatures (keep promoted constructor params)
        let top = c.top;
        const sig = /\bfunction\s+&?\s*(\w+)\s*\(/gi;
        let s;
        while ((s = sig.exec(top))) {
          const close = matchParen(top, s.index + s[0].length - 1);
          if (close < 0) break;
          const params = top.slice(s.index + s[0].length, close);
          const keep = /^__construct$/i.test(s[1])
            ? splitTopLevel(params, ',').map(p => p.text).filter(p => /\b(public|private|protected|readonly)\b/i.test(p)).join(',')
            : '';
          top = top.slice(0, s.index) + keep.padEnd(close + 1 - s.index, ' ') + top.slice(close + 1);
          sig.lastIndex = s.index + 1;
        }
        const decl = /\$(\w+)/g;
        while ((d = decl.exec(top))) declared.add(d[1].toLowerCase());
        const seen = new Set();
        const asg = /\$this\s*->\s*([A-Za-z_]\w*)\s*(?:\[[^\]\n]*\]\s*)*(?:=(?![=>])|\.=|\+=|-=|\[\]\s*=)/g;
        let a;
        while ((a = asg.exec(c.body))) {
          const n = a[1].toLowerCase();
          if (declared.has(n) || seen.has(n)) continue;
          seen.add(n);
          out.push({ index: c.bodyStart + a.index, message: `Property ${c.name}::$${a[1]} is not declared. Creating dynamic properties is deprecated since PHP 8.2 (an Error in PHP 9). Declare it in the class.` });
        }
      }
      return out;
    },
    description: 'Assigning undeclared properties is deprecated in 8.2. Very common in PHP 4/5 style classes.',
    fix: 'Declare the property (with visibility and type). As a temporary workaround add #[\\AllowDynamicProperties] to the class.',
    before: `class User {\n    function __construct($n) { $this->name = $n; }\n}`, after: `class User {\n    public string $name;\n    public function __construct(string $n) { $this->name = $n; }\n}`, docs: DOC.m82,
  },
  {
    id: 'PHP-GET-CLASS-NOARGS', title: 'get_class() / get_parent_class() without argument', category: 'compatibility',
    severity: 'minor', deprecated: '8.3', effort: 1, view: 'code',
    pattern: /(?<![\w$>:])\bget_(parent_)?class\s*\(\s*\)/gi,
    message: (m) => (m[1] ? 'get_parent_class() without arguments is deprecated in 8.3. Use get_parent_class($this) or parent::class.' : 'get_class() without arguments is deprecated in 8.3. Use self::class or static::class.'),
    description: 'Calling these without arguments is deprecated in PHP 8.3.', fix: 'Use self::class / static::class.',
    before: `$c = get_class();`, after: `$c = self::class;`, docs: DOC.m83,
  },
  {
    id: 'PHP-ASSERT-OPTIONS', title: 'assert_options() deprecated', category: 'compatibility',
    severity: 'minor', deprecated: '8.3', effort: 3, view: 'code',
    pattern: fnCall(['assert_options']),
    message: () => 'assert_options() is deprecated since PHP 8.3. Configure zend.assertions in php.ini.',
    description: 'Deprecated in 8.3.', fix: 'Use zend.assertions / assert.exception ini settings.',
    before: `assert_options(ASSERT_ACTIVE, 1);`, after: `; php.ini\nzend.assertions = 1`, docs: DOC.m83,
  },
  {
    id: 'PHP-MT-RAND-PHP', title: 'MT_RAND_PHP mode deprecated', category: 'compatibility',
    severity: 'minor', deprecated: '8.3', effort: 2, view: 'code',
    pattern: /\bMT_RAND_PHP\b/g,
    message: () => 'MT_RAND_PHP is deprecated since PHP 8.3. Use the default mode or the Random\\Randomizer API.',
    description: 'The broken legacy Mt19937 mode is deprecated.', fix: 'Remove the mode argument.',
    before: `mt_srand(42, MT_RAND_PHP);`, after: `mt_srand(42);`, docs: DOC.m83,
  },
  {
    id: 'PHP-IMPLICIT-NULLABLE', title: 'Implicitly nullable parameter type', category: 'compatibility',
    severity: 'major', deprecated: '8.4', effort: 1, view: 'code',
    check(ctx) {
      const out = [];
      for (const f of getFunctions(ctx)) {
        for (const p of f.params) {
          if (!p.type || p.def === null || !/^null$/i.test(p.def)) continue;
          if (/^\?|(^|\|)\s*null\s*(\||$)|^mixed$/i.test(p.type)) continue;
          out.push({ index: p.index, message: `Parameter "${p.type} $${p.name} = null" is implicitly nullable — deprecated in PHP 8.4. Write "?${p.type} $${p.name} = null".` });
        }
      }
      return out;
    },
    description: 'Implicitly marking a typed parameter nullable via a null default is deprecated in 8.4.',
    fix: 'Use an explicit nullable type: ?Type $x = null (or Type|null).',
    before: `function find(array $opts = null) {}`, after: `function find(?array $opts = null) {}`, docs: DOC.m84,
  },
  {
    id: 'PHP-E-STRICT', title: 'E_STRICT constant deprecated', category: 'compatibility',
    severity: 'minor', deprecated: '8.4', effort: 1, view: 'code',
    pattern: /\bE_STRICT\b/g,
    message: () => 'E_STRICT is deprecated in PHP 8.4 (no errors of this level have been raised since 8.0). Remove it from error_reporting().',
    description: 'Strict-standards notices were reclassified in PHP 7/8.', fix: 'Use E_ALL.',
    before: `error_reporting(E_ALL | E_STRICT);`, after: `error_reporting(E_ALL);`, docs: DOC.m84,
  },
  {
    id: 'PHP-TRIGGER-USER-ERROR', title: 'trigger_error() with E_USER_ERROR', category: 'compatibility',
    severity: 'minor', deprecated: '8.4', effort: 3, view: 'code',
    pattern: /\btrigger_error\s*\([^;]*\bE_USER_ERROR\b/gi,
    message: () => 'trigger_error(..., E_USER_ERROR) is deprecated in PHP 8.4. Throw an exception or call exit() instead.',
    description: 'Deprecated in 8.4.', fix: 'Throw an exception.',
    before: `trigger_error('Fatal config error', E_USER_ERROR);`, after: `throw new RuntimeException('Fatal config error');`, docs: DOC.m84,
  },
  {
    id: 'PHP-DEPRECATED-84', title: 'Function deprecated in PHP 8.4', category: 'compatibility',
    severity: 'minor', deprecated: '8.4', effort: 3, view: 'code',
    pattern: fnCall(['mysqli_ping', 'mysqli_kill', 'mysqli_refresh', 'lcg_value', 'xml_set_object']),
    message: replMsg({
      mysqli_ping: 'reconnect logic (ping is a no-op since 8.2)', mysqli_kill: "a KILL query: $mysqli->query('KILL CONNECTION ' . $id)",
      mysqli_refresh: "FLUSH queries", lcg_value: 'random_int() or (new Random\\Randomizer())->getFloat(0, 1)',
      xml_set_object: 'closures / [$obj, \'method\'] callables with xml_set_*_handler()',
    }, 'is deprecated in PHP 8.4', ''),
    description: 'Functions deprecated in PHP 8.4.', fix: 'Use the documented replacement.',
    before: `$r = lcg_value();`, after: `$r = (new Random\\Randomizer())->getFloat(0, 1);`, docs: DOC.m84,
  },
  {
    id: 'PHP-NONCANONICAL-CAST', title: 'Non-canonical cast names', category: 'compatibility',
    severity: 'minor', deprecated: '8.5', effort: 1, view: 'code',
    pattern: /\(\s*(integer|boolean|double|binary)\s*\)/gi,
    message: (m) => `(${m[1]}) cast is deprecated in PHP 8.5. Use (${({ integer: 'int', boolean: 'bool', double: 'float', binary: 'string' })[m[1].toLowerCase()]}).`,
    description: 'Alias cast names are deprecated in 8.5.', fix: 'Use (int), (bool), (float), (string).',
    before: `$n = (integer) $s;`, after: `$n = (int) $s;`, docs: DOC.m85,
  },
  {
    id: 'PHP-BACKTICK', title: 'Backtick shell execution operator', category: 'compatibility',
    severity: 'minor', deprecated: '8.5', effort: 5, view: 'code',
    pattern: /`/g,
    filter: (m, ctx, idx) => {
      // only report the opening backtick
      const before = ctx.views.code.slice(0, idx);
      return (before.split('`').length - 1) % 2 === 0;
    },
    message: () => 'The backtick operator `...` is deprecated in PHP 8.5. Use shell_exec() (with escapeshellarg()).',
    description: 'Backticks as an alias for shell_exec() are deprecated in 8.5.', fix: 'Use shell_exec() explicitly.',
    before: "$out = `ls -la $dir`;", after: '$out = shell_exec(\'ls -la \' . escapeshellarg($dir));', docs: DOC.m85,
  },
  {
    id: 'PHP-NOOP-CLOSE', title: 'No-op resource close function', category: 'compatibility',
    severity: 'info', deprecated: '8.5', effort: 1, view: 'code',
    pattern: fnCall(['curl_close', 'curl_share_close', 'imagedestroy', 'finfo_close', 'xml_parser_free']),
    message: (m) => `${m[1]}() has had no effect since PHP 8.0 (objects are freed automatically) and is deprecated in 8.5. Remove the call or unset() the variable.`,
    description: 'These functions became no-ops when resources were converted to objects.', fix: 'Remove the call.',
    before: `curl_close($ch);`, after: `unset($ch); // optional`, docs: DOC.m85,
  },

  // ============================= CONFIG / COMPOSER ============================
  {
    id: 'PHP-INI-DIRECTIVE', title: 'Removed / deprecated php.ini directive', category: 'compatibility',
    severity: 'blocker', removed: '5.4', effort: 5, view: 'raw', fileTypes: ['ini'],
    check(ctx) {
      const out = [];
      const re = /^[ \t]*(?:php_(?:admin_)?(?:value|flag)[ \t]+)?([A-Za-z_][\w.]*)[ \t]*(?:=|[ \t])/gm;
      let m;
      while ((m = re.exec(ctx.views.raw))) {
        const key = m[1].toLowerCase();
        let info = INI[key];
        if (!info && /^mysql\./.test(key)) info = { removed: '7.0', msg: 'mysql extension was removed in 7.0' };
        if (!info && /^mcrypt\./.test(key)) info = { removed: '7.2', msg: 'mcrypt was removed in 7.2' };
        if (!info) continue;
        out.push({
          index: m.index + m[0].indexOf(m[1]),
          removed: info.removed || null, deprecated: info.deprecated || null,
          message: `ini directive "${m[1]}": ${info.msg}`,
        });
      }
      return out;
    },
    description: 'Configuration directives in php.ini, .user.ini or .htaccess (php_value/php_flag) that no longer exist. Unknown php_value in .htaccess causes HTTP 500 errors with mod_php.',
    fix: 'Remove the directive and fix the code that relied on it (e.g. register_globals, magic_quotes_gpc).',
    before: `php_flag register_globals on\nphp_flag magic_quotes_gpc on`, after: `# removed – code reads $_GET/$_POST explicitly`, docs: 'https://www.php.net/manual/en/ini.list.php',
  },
  {
    id: 'PHP-COMPOSER', title: 'Composer dependency / platform constraint', category: 'compatibility',
    severity: 'major', effort: 30, view: 'raw', fileTypes: ['composer'],
    check(ctx) {
      const out = [];
      let json;
      try { json = JSON.parse(ctx.views.raw); } catch { return out; }
      const raw = ctx.views.raw;
      const at = (needle) => Math.max(0, raw.indexOf(needle));
      const targetMajor = Math.floor(ctx.target / 100);
      const phpReq = json.require && json.require.php;
      const allows = phpReq && (/(^|\|)\s*>=?\s*\d/.test(phpReq) || new RegExp('(^|[\\s|^~=])' + targetMajor + '(\\.|\\*|\\s|\\||$)').test(phpReq));
      if (phpReq && !allows) {
        out.push({ index: at('"php"'), message: `require.php is "${phpReq}" – it does not allow PHP ${ctx.targetStr}. Update it (e.g. "^${ctx.targetStr}").` });
      } else if (phpReq && /(^|\|)\s*>=?\s*5/.test(phpReq)) {
        out.push({ index: at('"php"'), message: `require.php is "${phpReq}". Raise the minimum to "^${ctx.targetStr}" so Composer installs compatible dependencies.` });
      }
      const plat = json.config && json.config.platform && json.config.platform.php;
      if (plat && /^[5-7]\./.test(plat)) out.push({ index: at('"platform"'), message: `config.platform.php is pinned to ${plat}. Composer resolves dependencies for that version – update it to ${ctx.targetStr}.` });
      const deps = Object.assign({}, json.require || {}, json['require-dev'] || {});
      for (const [pkg, ver] of Object.entries(deps)) {
        const info = PACKAGES[pkg.toLowerCase()];
        if (!info) continue;
        const major = parseInt((/(\d+)/.exec(String(ver)) || [])[1], 10);
        if (info.abandoned) out.push({ index: at('"' + pkg + '"'), message: `${pkg} is abandoned. ${info.abandoned}` });
        else if (!isNaN(major) && major < info.min) out.push({ index: at('"' + pkg + '"'), message: `${pkg} ${ver} does not support PHP 8. Upgrade to ${info.minLabel || '^' + info.min} or later.` });
      }
      return out;
    },
    description: 'composer.json constraints that block installing on modern PHP, abandoned packages and libraries whose old major versions do not run on PHP 8.',
    fix: 'Raise "php" requirement, remove config.platform pin, replace abandoned packages and upgrade libraries, then run composer update and the test suite.',
    before: `"require": { "php": ">=5.3", "phpunit/phpunit": "4.*" }`, after: `"require": { "php": "^8.3" },\n"require-dev": { "phpunit/phpunit": "^10.5" }`, docs: 'https://getcomposer.org/doc/04-schema.md#package-links',
  },

  // ================================= SECURITY ==================================
  {
    id: 'SEC-SQL-INJECTION', title: 'SQL query built from variables (SQL injection)', category: 'security',
    severity: 'critical', effort: 30, view: 'src',
    pattern: new RegExp(String.raw`(?:\b(?:mysql_query|mysql_db_query|mysql_unbuffered_query|mysqli_query|mysqli_multi_query|mysqli_real_query|pg_query|sqlsrv_query|mssql_query|odbc_exec|sqlite_query)\s*\(|->\s*(?:query|exec|multi_query|real_query|prepare)\s*\()[^;]*?(?:${USER_INPUT}|['"]\s*\.\s*\$\w|"[^"\n]*\$\w|\$\w+\s*\.\s*['"])` +
      String.raw`|"\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)\s[^"\n]*?(?:\$\w|"\s*\.\s*\$)|'\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)\s[^'\n]*'\s*\.\s*\$`, 'gi'),
    message: () => 'SQL statement is built by concatenating/interpolating variables. Use prepared statements with bound parameters (PDO / mysqli_prepare).',
    description: 'Concatenating variables into SQL is the #1 cause of SQL injection (OWASP A03). Legacy PHP 5 code often relied on magic_quotes, which no longer exists — so migrating can make existing code MORE vulnerable.',
    fix: 'Use placeholders and bind values. Whitelist identifiers (column/table names) that cannot be bound.',
    before: `$r = mysqli_query($db, "SELECT * FROM users WHERE email = '$email'");`,
    after: `$stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email');\n$stmt->execute(['email' => $email]);`, docs: 'https://owasp.org/www-community/attacks/SQL_Injection',
  },
  {
    id: 'SEC-XSS', title: 'Unescaped user input echoed (XSS)', category: 'security',
    severity: 'critical', effort: 10, view: 'src',
    pattern: new RegExp(String.raw`(?:\becho\b|\bprint\b|<\?=)(?:(?!\?>)[^;])*?(?:${USER_INPUT}|\$_SERVER\s*\[\s*['"](?:PHP_SELF|REQUEST_URI|QUERY_STRING|HTTP_REFERER|HTTP_USER_AGENT)['"]\s*\])`, 'gi'),
    filter: (m) => !SANITIZERS.test(m[0]),
    message: () => 'User-controlled data is printed without escaping. Wrap it with htmlspecialchars($v, ENT_QUOTES, \'UTF-8\').',
    description: 'Reflected XSS: request data echoed to the page lets attackers inject scripts.',
    fix: "Escape on output: htmlspecialchars($value, ENT_QUOTES, 'UTF-8'). Use a template engine with auto-escaping (Twig, Blade).",
    before: `echo "Hello " . $_GET['name'];\n<form action="<?= $_SERVER['PHP_SELF'] ?>">`, after: `echo 'Hello ' . htmlspecialchars($_GET['name'] ?? '', ENT_QUOTES, 'UTF-8');\n<form action="">`, docs: 'https://owasp.org/www-community/attacks/xss/',
  },
  {
    id: 'SEC-FILE-INCLUSION', title: 'include/require with user input', category: 'security',
    severity: 'blocker', effort: 20, view: 'src',
    pattern: new RegExp(String.raw`\b(?:include|include_once|require|require_once)\b[^;]*?${USER_INPUT}`, 'gi'),
    filter: (m) => !/basename\s*\(|in_array\s*\(/.test(m[0]),
    message: () => 'File inclusion path contains request data — Local/Remote File Inclusion. Use a whitelist of allowed pages.',
    description: 'Including files based on request parameters allows attackers to read files or execute code.',
    fix: 'Map allowed values to fixed file names (whitelist), never build paths from raw input.',
    before: `include $_GET['page'] . '.php';`, after: `$pages = ['home' => 'home.php', 'about' => 'about.php'];\ninclude __DIR__ . '/pages/' . ($pages[$_GET['page'] ?? 'home'] ?? 'home.php');`, docs: DOC.owasp,
  },
  {
    id: 'SEC-COMMAND-INJECTION', title: 'Shell command with user input', category: 'security',
    severity: 'blocker', effort: 20, view: 'src',
    pattern: new RegExp(String.raw`\b(?:exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^;]*?${USER_INPUT}`, 'gi'),
    filter: (m) => !/escapeshellarg/.test(m[0]),
    message: () => 'Shell command contains request data — command injection. Use escapeshellarg() or avoid the shell.',
    description: 'Passing user input to a shell allows arbitrary command execution.',
    fix: 'Validate input strictly and use escapeshellarg() on every argument, or use a native PHP API instead of the shell.',
    before: `system('ping -c 1 ' . $_GET['host']);`, after: `$host = filter_var($_GET['host'] ?? '', FILTER_VALIDATE_IP);\nif ($host) system('ping -c 1 ' . escapeshellarg($host));`, docs: DOC.owasp,
  },
  {
    id: 'SEC-EVAL', title: 'Use of eval()', category: 'security',
    severity: 'major', effort: 30, view: 'code',
    pattern: /(?<![\w$>:])\beval\s*\(/gi,
    message: () => 'eval() executes arbitrary code. Refactor to avoid dynamic code evaluation.',
    description: 'eval() is dangerous and prevents opcode caching / static analysis.', fix: 'Use closures, callbacks or data-driven logic.',
    before: `eval('$v = ' . $expr . ';');`, after: `// parse $expr explicitly or use a lookup table / callback`, docs: DOC.owasp,
  },
  {
    id: 'SEC-UNSERIALIZE', title: 'unserialize() on user input', category: 'security',
    severity: 'critical', effort: 20, view: 'src',
    pattern: new RegExp(String.raw`\bunserialize\s*\([^;]*?(?:${USER_INPUT}|\bbase64_decode\s*\(\s*\$_)`, 'gi'),
    message: () => 'unserialize() on request data enables PHP object injection. Use json_decode(), or pass [\'allowed_classes\' => false].',
    description: 'Object injection via unserialize() can lead to remote code execution.', fix: 'Use JSON for data exchange.',
    before: `$cart = unserialize($_COOKIE['cart']);`, after: `$cart = json_decode($_COOKIE['cart'] ?? '[]', true, 512, JSON_THROW_ON_ERROR);`, docs: 'https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection',
  },
  {
    id: 'SEC-REGISTER-GLOBALS', title: 'register_globals emulation (extract / $$ from request)', category: 'security',
    severity: 'critical', effort: 30, view: 'code',
    pattern: /\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES|SESSION)\b|\bforeach\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s+as\s+\$(\w+)\s*=>\s*\$\w+\s*\)[^;]*\$\$\1/gi,
    message: () => 'Request variables are imported into the local scope (register_globals emulation). An attacker can overwrite any variable. Read the specific keys you need.',
    description: 'Legacy code often re-creates register_globals after it was removed in 5.4 — this is a serious vulnerability.',
    fix: "Access $_GET['key'] / $_POST['key'] explicitly with validation (filter_input).",
    before: `extract($_POST);\nif ($is_admin) { ... }`, after: `$name = filter_input(INPUT_POST, 'name');`, docs: DOC.m54,
  },
  {
    id: 'SEC-WEAK-PASSWORD-HASH', title: 'Weak password hashing (md5/sha1)', category: 'security',
    severity: 'critical', effort: 30, view: 'src',
    pattern: /(?<![$\w>:])(?:(md5|sha1|crypt)\s*\(|(hash)\s*\(\s*['"](?:md5|sha1|sha256)['"]\s*,)[^;]{0,80}?(pass|pwd)/gi,
    message: (m) => `Passwords hashed with ${m[1] || 'hash()'} can be cracked quickly. Use password_hash() / password_verify() (PHP 5.5+).`,
    description: 'Fast hashes (md5, sha1, unsalted sha256) are unsuitable for passwords.',
    fix: 'Store password_hash($pw, PASSWORD_DEFAULT); verify with password_verify(). Rehash on login with password_needs_rehash() to migrate old hashes.',
    before: `$hash = md5($password);`, after: `$hash = password_hash($password, PASSWORD_DEFAULT);\nif (password_verify($input, $hash)) { ... }`, docs: 'https://www.php.net/manual/en/faq.passwords.php',
  },
  {
    id: 'SEC-WEAK-RANDOM', title: 'Insecure randomness for secrets', category: 'security',
    severity: 'major', effort: 5, view: 'src',
    pattern: /\$\w*(?:token|salt|csrf|nonce|secret|api_?key|reset|otp)\w*\s*=\s*[^;]*\b(rand|mt_rand|uniqid|microtime|lcg_value|time)\s*\(/gi,
    message: (m) => `${m[1]}() is predictable and must not be used for tokens/salts. Use random_bytes() / random_int() (PHP 7.0+).`,
    description: 'rand(), mt_rand() and uniqid() are not cryptographically secure.', fix: 'bin2hex(random_bytes(32)).',
    before: `$token = md5(uniqid(rand(), true));`, after: `$token = bin2hex(random_bytes(32));`, docs: 'https://www.php.net/manual/en/function.random-bytes.php',
  },
  {
    id: 'SEC-SSL-VERIFY', title: 'TLS certificate verification disabled', category: 'security',
    severity: 'critical', effort: 5, view: 'code',
    pattern: /\bCURLOPT_SSL_VERIFY(?:PEER|HOST)\s*(?:,|=>)\s*(?:false|0)\b|['"]verify_peer['"]\s*=>\s*false/gi,
    message: () => 'TLS certificate verification is disabled — traffic can be intercepted (MITM). Keep verification on and configure the CA bundle (curl.cainfo).',
    description: 'Disabling peer verification defeats HTTPS.', fix: 'Remove the option; install an up-to-date CA bundle.',
    before: `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);`, after: `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);`, docs: DOC.owasp,
  },
  {
    id: 'SEC-OPEN-REDIRECT', title: 'Redirect to user-supplied URL', category: 'security',
    severity: 'major', effort: 10, view: 'src',
    pattern: new RegExp(String.raw`\bheader\s*\(\s*['"]Location:[^;]*?${USER_INPUT}`, 'gi'),
    message: () => 'Location header built from request data (open redirect / header injection). Validate against a whitelist of allowed URLs.',
    description: 'Attackers can redirect users to phishing sites.', fix: 'Only allow relative paths or whitelisted hosts.',
    before: `header('Location: ' . $_GET['next']);`, after: `$next = $_GET['next'] ?? '/';\nif (!str_starts_with($next, '/') || str_starts_with($next, '//')) $next = '/';\nheader('Location: ' . $next);`, docs: DOC.owasp,
  },
  {
    id: 'SEC-HARDCODED-PASSWORD', title: 'Hard-coded credentials', category: 'security',
    severity: 'major', effort: 15, view: 'src',
    pattern: /\$\w*(?:pass|password|passwd|pwd|secret|api_?key)\w*\s*=\s*(['"])[^'"\s]{3,}\1/gi,
    filter: (m) => !/\$\w*(?:pass|pwd)\w*(?:_?(?:field|label|len|length|min|max|regex|confirm|placeholder|msg|error))/i.test(m[0]),
    message: () => 'Credential appears to be hard-coded in source. Move secrets to environment variables or a config file outside the web root (e.g. vlucas/phpdotenv).',
    description: 'Secrets in source code leak through version control and backups.', fix: "Read from getenv('DB_PASSWORD') / $_ENV.",
    before: `$db_pass = 'S3cret!';`, after: `$db_pass = getenv('DB_PASSWORD');`, docs: DOC.owasp,
  },
  {
    id: 'SEC-ADDSLASHES-SQL', title: 'addslashes() used for escaping', category: 'security',
    severity: 'major', effort: 10, view: 'code',
    pattern: fnCall(['addslashes']),
    message: () => 'addslashes() is not a safe SQL escaping method (multi-byte charset bypasses). Use prepared statements.',
    description: 'Often used to emulate magic_quotes; not safe for SQL.', fix: 'Use bound parameters.',
    before: `$sql = "... WHERE name='" . addslashes($n) . "'";`, after: `$stmt = $pdo->prepare('... WHERE name = ?');\n$stmt->execute([$n]);`, docs: DOC.owasp,
  },
  {
    id: 'SEC-DISPLAY-ERRORS', title: 'Errors displayed / hidden at runtime', category: 'security',
    severity: 'minor', effort: 2, view: 'src',
    pattern: /\bini_set\s*\(\s*['"]display_errors['"]\s*,\s*(?:['"]?(?:1|on|true)['"]?|true)\s*\)|\berror_reporting\s*\(\s*0\s*\)/gi,
    message: (m) => (/error_reporting/i.test(m[0]) ? 'error_reporting(0) hides problems — log errors instead (log_errors=On, display_errors=Off in production).' : 'display_errors enabled in code — leaks paths and SQL in production. Configure per environment in php.ini.'),
    description: 'Error display should be configured per environment, not hard-coded.', fix: 'Production: display_errors=Off, log_errors=On, error_reporting=E_ALL.',
    before: `ini_set('display_errors', 1);`, after: `// configured in php.ini per environment`, docs: 'https://www.php.net/manual/en/errorfunc.configuration.php',
  },
  {
    id: 'SEC-REQUEST-SUPERGLOBAL', title: 'Use of $_REQUEST', category: 'security',
    severity: 'minor', effort: 2, view: 'code',
    pattern: /\$_REQUEST\b/g,
    message: () => '$_REQUEST mixes GET, POST and COOKIE (order depends on request_order). Use $_GET or $_POST explicitly.',
    description: 'Ambiguous input source; enables CSRF via GET.', fix: 'Use $_GET / $_POST / filter_input().',
    before: `$id = $_REQUEST['id'];`, after: `$id = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT);`, docs: DOC.owasp,
  },

  // =============================== BEST PRACTICES ==============================
  {
    id: 'BP-VAR-KEYWORD', title: '"var" property declaration', category: 'best-practice',
    severity: 'minor', effort: 1, view: 'code',
    pattern: /^[ \t]*var\s+\$/gim,
    message: () => '"var" is a PHP 4 leftover. Declare the visibility (public/protected/private) and a type.',
    description: 'PHP 4 style property declaration.', fix: 'Use private/protected/public with a type (7.4+).',
    before: `var $name;`, after: `private string $name;`, docs: DOC.psr12,
  },
  {
    id: 'BP-METHOD-VISIBILITY', title: 'Method without visibility', category: 'best-practice',
    severity: 'minor', effort: 1, view: 'code',
    check(ctx) {
      const out = [];
      for (const c of getClasses(ctx)) {
        if (c.kind === 'interface') continue;
        const re = /(^|[;{}\n])([ \t]*)((?:(?:abstract|final|static)\s+)*)function\s+&?\s*([A-Za-z_]\w*)/g;
        let m;
        while ((m = re.exec(c.top))) {
          out.push({ index: c.bodyStart + m.index + m[1].length + m[2].length, message: `Method ${c.name}::${m[4]}() has no visibility modifier. Declare public/protected/private (PSR-12).` });
        }
      }
      return out;
    },
    description: 'Implicit public methods are a PHP 4 style; PSR-12 requires explicit visibility.', fix: 'Add public/protected/private.',
    before: `function save() {}`, after: `public function save(): void {}`, docs: DOC.psr12,
  },
  {
    id: 'BP-GLOBAL', title: 'Use of global variables', category: 'best-practice',
    severity: 'minor', effort: 10, view: 'code',
    pattern: /\bglobal\s+\$/gi,
    message: () => 'global creates hidden dependencies and makes code hard to test. Pass dependencies as parameters / constructor injection.',
    description: 'Global state is common in PHP 5 apps ($db, $config).', fix: 'Inject dependencies.',
    before: `function getUser($id) { global $db; ... }`, after: `function getUser(PDO $db, int $id) { ... }`, docs: DOC.psr12,
  },
  {
    id: 'BP-LONG-ARRAY', title: 'Long array() syntax', category: 'best-practice',
    severity: 'info', effort: 1, view: 'code', minTarget: '5.4',
    pattern: /(?<![\w$>:])\barray\s*\(/gi,
    message: () => 'Use the short array syntax [] (PHP 5.4+). Tools like Rector/PHP-CS-Fixer can convert this automatically.',
    description: 'Modern PHP code uses [] for arrays.', fix: 'Run php-cs-fixer with the array_syntax rule.',
    before: `$a = array(1, 2, 3);`, after: `$a = [1, 2, 3];`, docs: 'https://cs.symfony.com/doc/rules/array_notation/array_syntax.html',
  },
  {
    id: 'BP-NULL-COALESCE', title: 'isset() ternary → ?? operator', category: 'best-practice',
    severity: 'info', effort: 1, view: 'src', minTarget: '7.0',
    pattern: /\bisset\s*\(\s*(\$[\w\->\[\]'"]+)\s*\)\s*\?\s*(\$[\w\->\[\]'"]+)\s*:/g,
    filter: (m) => m[1].replace(/\s/g, '') === m[2].replace(/\s/g, ''),
    message: (m) => `Use the null coalescing operator: ${m[1]} ?? default (PHP 7.0+).`,
    description: 'isset($x) ? $x : $y is verbose.', fix: 'Use ??.',
    before: `$p = isset($_GET['p']) ? $_GET['p'] : 1;`, after: `$p = $_GET['p'] ?? 1;`, docs: 'https://www.php.net/manual/en/migration70.new-features.php',
  },
  {
    id: 'BP-STR-CONTAINS', title: 'strpos() !== false → str_contains()', category: 'best-practice',
    severity: 'info', effort: 1, view: 'code', minTarget: '8.0',
    pattern: /(?<![\w$>:])\bstrpos\s*\((?:[^()]|\([^()]*\))*\)\s*(?:!==?|===?)\s*false\b|\bfalse\s*(?:!==?|===?)\s*strpos\s*\(/gi,
    message: () => 'Use str_contains($haystack, $needle) (PHP 8.0+) for readability.',
    description: 'PHP 8 adds str_contains / str_starts_with / str_ends_with.', fix: 'Use str_contains().',
    before: `if (strpos($s, 'abc') !== false) {}`, after: `if (str_contains($s, 'abc')) {}`, docs: 'https://www.php.net/manual/en/function.str-contains.php',
  },
  {
    id: 'BP-DIRNAME-FILE', title: 'dirname(__FILE__) → __DIR__', category: 'best-practice',
    severity: 'info', effort: 1, view: 'code', minTarget: '5.3',
    pattern: /\bdirname\s*\(\s*__FILE__\s*\)/gi,
    message: () => 'Use __DIR__ instead of dirname(__FILE__) (PHP 5.3+).',
    description: 'Shorter and resolved at compile time.', fix: 'Use __DIR__.',
    before: `require dirname(__FILE__) . '/config.php';`, after: `require __DIR__ . '/config.php';`, docs: 'https://www.php.net/manual/en/language.constants.magic.php',
  },
  {
    id: 'BP-FUNC-GET-ARGS', title: 'func_get_args() → variadic parameters', category: 'best-practice',
    severity: 'info', effort: 3, view: 'code', minTarget: '5.6',
    pattern: fnCall(['func_get_args', 'func_num_args']),
    message: (m) => `${m[1]}() hides the function signature. Use variadic parameters (...$args) (PHP 5.6+).`,
    description: 'Variadics make the signature explicit and type-able.', fix: 'function sum(int ...$numbers)',
    before: `function sum() { return array_sum(func_get_args()); }`, after: `function sum(int ...$n): int { return array_sum($n); }`, docs: 'https://www.php.net/manual/en/functions.arguments.php#functions.variable-arg-list',
  },
  {
    id: 'BP-SHORT-OPEN-TAG', title: 'Short open tag <?', category: 'best-practice',
    severity: 'major', effort: 1, view: 'raw',
    pattern: /<\?(?!php\b|=|xml\b)(?=\s)/gi,
    message: () => 'Short open tag "<?" only works when short_open_tag=On (default Off on most modern installs) — otherwise the PHP source is sent to the browser. Use "<?php".',
    description: 'Portability and source disclosure risk.', fix: 'Replace "<?" with "<?php" (keep "<?=" which is always available since 5.4).',
    before: `<? echo $title; ?>`, after: `<?php echo $title; ?>`, docs: 'https://www.php.net/manual/en/language.basic-syntax.phptags.php',
  },
  {
    id: 'BP-CLOSING-TAG', title: 'Closing ?> tag at end of PHP-only file', category: 'best-practice',
    severity: 'info', effort: 1, view: 'raw',
    check(ctx) {
      if (ctx.hasHtml) return [];
      const m = /\?>\s*$/.exec(ctx.views.raw);
      return m ? [{ index: m.index, message: 'Omit the closing ?> in pure PHP files to avoid accidental whitespace output ("headers already sent").' }] : [];
    },
    description: 'PSR-12: the closing tag must be omitted from files containing only PHP.', fix: 'Delete the final ?>.',
    before: `<?php\nclass A {}\n?>\n`, after: `<?php\nclass A {}\n`, docs: DOC.psr12,
  },
  {
    id: 'BP-DEBUG-OUTPUT', title: 'Debug output left in code', category: 'best-practice',
    severity: 'minor', effort: 1, view: 'code',
    pattern: /(?<![\w$>:])\b(var_dump|print_r|debug_zval_dump|debug_print_backtrace)\s*\(/gi,
    filter: (m, ctx, idx) => {
      if (!/print_r/i.test(m[1])) return true;
      const close = matchParen(ctx.views.code, idx + m[0].length - 1);
      return !(close > 0 && /,\s*(?:true|1)\s*$/i.test(ctx.views.code.slice(idx, close)));
    },
    message: (m) => `${m[1]}() looks like leftover debug output. Use a logger (e.g. Monolog) instead.`,
    description: 'Debug output can leak data in production.', fix: 'Remove or replace with logging.',
    before: `var_dump($user);`, after: `$logger->debug('user', ['user' => $user]);`, docs: 'https://github.com/Seldaek/monolog',
  },
  {
    id: 'BP-GOTO', title: 'Use of goto', category: 'best-practice',
    severity: 'minor', effort: 15, view: 'code',
    pattern: /\bgoto\s+\w+\s*;/gi,
    message: () => 'goto makes control flow hard to follow. Use loops, functions or early returns.',
    description: 'Avoid goto.', fix: 'Refactor.', before: `goto retry;`, after: `while (!$ok) { ... }`, docs: DOC.psr12,
  },
  {
    id: 'BP-CATCH-EXCEPTION', title: 'Top-level catch (Exception) misses PHP 7 Errors', category: 'best-practice',
    severity: 'info', effort: 2, view: 'code', minTarget: '7.0',
    pattern: /\bcatch\s*\(\s*\\?Exception\s+\$\w+\s*\)/gi,
    message: () => 'catch (Exception) does not catch engine errors (TypeError, Error) in PHP 7+. Use catch (\\Throwable $e) for top-level/global handlers.',
    description: 'PHP 7 introduced the Throwable hierarchy: Exception and Error.', fix: 'Catch Throwable where you need a catch-all.',
    before: `try { run(); } catch (Exception $e) { log($e); }`, after: `try { run(); } catch (\\Throwable $e) { log($e); }`, docs: 'https://www.php.net/manual/en/language.errors.php7.php',
  },
];

const RESERVED = {
  int: '7.0', float: '7.0', bool: '7.0', string: '7.0', null: '7.0', true: '7.0', false: '7.0',
  resource: '7.0', numeric: '7.0', void: '7.1', iterable: '7.1', object: '7.2', mixed: '8.0', never: '8.1',
};

const INI = {
  register_globals: { removed: '5.4', msg: 'removed in 5.4 – variables from the request are no longer created automatically' },
  register_long_arrays: { removed: '5.4', msg: 'removed in 5.4' },
  magic_quotes_gpc: { removed: '5.4', msg: 'removed in 5.4 – input is no longer escaped automatically (check SQL injection!)' },
  magic_quotes_runtime: { removed: '5.4', msg: 'removed in 5.4' },
  magic_quotes_sybase: { removed: '5.4', msg: 'removed in 5.4' },
  allow_call_time_pass_reference: { removed: '5.4', msg: 'removed in 5.4' },
  safe_mode: { removed: '5.4', msg: 'safe_mode was removed in 5.4 – use open_basedir and OS permissions' },
  safe_mode_gid: { removed: '5.4', msg: 'removed in 5.4' },
  safe_mode_include_dir: { removed: '5.4', msg: 'removed in 5.4' },
  safe_mode_exec_dir: { removed: '5.4', msg: 'removed in 5.4' },
  safe_mode_allowed_env_vars: { removed: '5.4', msg: 'removed in 5.4' },
  safe_mode_protected_env_vars: { removed: '5.4', msg: 'removed in 5.4' },
  define_syslog_variables: { removed: '5.4', msg: 'removed in 5.4' },
  'highlight.bg': { removed: '5.4', msg: 'removed in 5.4' },
  'session.bug_compat_42': { removed: '5.4', msg: 'removed in 5.4' },
  'session.bug_compat_warn': { removed: '5.4', msg: 'removed in 5.4' },
  y2k_compliance: { removed: '5.4', msg: 'removed in 5.4' },
  'zend.ze1_compatibility_mode': { removed: '5.3', msg: 'removed in 5.3' },
  asp_tags: { removed: '7.0', msg: 'removed in 7.0 together with ASP tags' },
  always_populate_raw_post_data: { removed: '7.0', msg: "removed in 7.0 – use file_get_contents('php://input')" },
  'xsl.security_prefs': { removed: '7.0', msg: 'removed in 7.0 – use XsltProcessor::setSecurityPrefs()' },
  'opcache.load_comments': { removed: '7.0', msg: 'removed in 7.0' },
  'iconv.input_encoding': { deprecated: '5.6', msg: 'deprecated in 5.6 – use default_charset' },
  'iconv.output_encoding': { deprecated: '5.6', msg: 'deprecated in 5.6 – use default_charset' },
  'iconv.internal_encoding': { deprecated: '5.6', msg: 'deprecated in 5.6 – use default_charset' },
  'mbstring.http_input': { deprecated: '5.6', msg: 'deprecated in 5.6 – use default_charset' },
  'mbstring.http_output': { deprecated: '5.6', msg: 'deprecated in 5.6 – use default_charset' },
  'mbstring.internal_encoding': { deprecated: '5.6', msg: 'deprecated in 5.6 – use default_charset' },
  'mbstring.func_overload': { deprecated: '7.2', removed: '8.0', msg: 'removed in 8.0 – call mb_* functions explicitly' },
  track_errors: { deprecated: '7.2', removed: '8.0', msg: 'removed in 8.0 – use error_get_last()' },
  'session.entropy_file': { removed: '7.1', msg: 'removed in 7.1' },
  'session.entropy_length': { removed: '7.1', msg: 'removed in 7.1' },
  'session.hash_function': { removed: '7.1', msg: 'removed in 7.1 – use session.sid_length' },
  'session.hash_bits_per_character': { removed: '7.1', msg: 'removed in 7.1 – use session.sid_bits_per_character' },
  allow_url_include: { deprecated: '7.4', msg: 'deprecated in 7.4 – and a security risk (remote code inclusion)' },
  'assert.quiet_eval': { removed: '8.0', msg: 'removed in 8.0' },
  'filter.default': { deprecated: '8.1', msg: 'deprecated in 8.1' },
  'filter.default_flags': { deprecated: '8.1', msg: 'deprecated in 8.1' },
  auto_detect_line_endings: { deprecated: '8.1', msg: 'deprecated in 8.1' },
  'assert.active': { deprecated: '8.3', msg: 'deprecated in 8.3 – use zend.assertions' },
  'assert.bail': { deprecated: '8.3', msg: 'deprecated in 8.3' },
  'assert.callback': { deprecated: '8.3', msg: 'deprecated in 8.3' },
  'assert.exception': { deprecated: '8.3', msg: 'deprecated in 8.3' },
  'assert.warning': { deprecated: '8.3', msg: 'deprecated in 8.3' },
  'session.sid_length': { deprecated: '8.4', msg: 'deprecated in 8.4' },
  'session.sid_bits_per_character': { deprecated: '8.4', msg: 'deprecated in 8.4' },
};

const PACKAGES = {
  'phpunit/phpunit': { min: 9, minLabel: '^9.5 (PHP 8.0) / ^10 / ^11' },
  'laravel/framework': { min: 8 },
  'illuminate/support': { min: 8 },
  'symfony/symfony': { min: 5, minLabel: '^5.4 LTS / ^6.4 LTS' },
  'symfony/http-kernel': { min: 5, minLabel: '^5.4 / ^6.4' },
  'guzzlehttp/guzzle': { min: 7, minLabel: '^7.0' },
  'monolog/monolog': { min: 2 },
  'phpmailer/phpmailer': { min: 6, minLabel: '^6.5' },
  'smarty/smarty': { min: 4, minLabel: '^4.0 / ^5.0' },
  'twig/twig': { min: 3 },
  'doctrine/orm': { min: 2, minLabel: '^2.10 / ^3.0' },
  'slim/slim': { min: 4 },
  'cakephp/cakephp': { min: 4 },
  'yiisoft/yii2': { min: 2, minLabel: '^2.0.45' },
  'codeigniter4/framework': { min: 4 },
  'mockery/mockery': { min: 1, minLabel: '^1.4' },
  'phpoffice/phpword': { min: 1 },
  'tecnickcom/tcpdf': { min: 6, minLabel: '^6.4' },
  'mpdf/mpdf': { min: 8 },
  'zendframework/zendframework': { abandoned: 'Replace with laminas/* (Zend Framework → Laminas).' },
  'zendframework/zend-mvc': { abandoned: 'Replace with laminas/laminas-mvc.' },
  'fzaninotto/faker': { abandoned: 'Replace with fakerphp/faker.' },
  'swiftmailer/swiftmailer': { abandoned: 'Replace with symfony/mailer.' },
  'phpoffice/phpexcel': { abandoned: 'Replace with phpoffice/phpspreadsheet.' },
  'mtdowling/cron-expression': { abandoned: 'Replace with dragonmantank/cron-expression.' },
  'jakub-onderka/php-parallel-lint': { abandoned: 'Replace with php-parallel-lint/php-parallel-lint.' },
  'ircmaxell/password-compat': { abandoned: 'Not needed since PHP 5.5 – remove it.' },
  'paragonie/random_compat': { abandoned: 'Not needed on PHP 7+ – remove it (or require ^9.99).' },
  'satooshi/php-coveralls': { abandoned: 'Replace with php-coveralls/php-coveralls.' },
  'phpseclib/mcrypt_compat': { abandoned: 'Only a stop-gap for mcrypt – migrate to openssl/sodium.' },
};

/** Syntax features used to estimate the PHP version the code base was written for. */
const FEATURES = [
  { name: 'Namespaces', version: '5.3', re: /^\s*namespace\s+[A-Za-z_\\]/m },
  { name: 'Closures', version: '5.3', re: /\bfunction\s*\([^)]*\)\s*(?:use\s*\(|\{)/ },
  { name: '__DIR__', version: '5.3', re: /\b__DIR__\b/ },
  { name: 'Short array syntax []', version: '5.4', re: /(?:=|=>|\(|,|return)\s*\[\s*(?:['"\d$\]]|\w+\s*=>)/ },
  { name: 'Traits', version: '5.4', re: /^\s*trait\s+\w+/m },
  { name: 'finally / generators', version: '5.5', re: /\bfinally\s*\{|\byield\b/ },
  { name: '::class', version: '5.5', re: /\w::class\b/ },
  { name: 'Variadics / ** operator', version: '5.6', re: /\(\s*(?:\w+\s+)?\.\.\.\$|\*\*(?!=)/ },
  { name: 'Null coalescing ??', version: '7.0', re: /\?\?(?!=)/ },
  { name: 'Spaceship <=>', version: '7.0', re: /<=>/ },
  { name: 'Scalar type / return types', version: '7.0', re: /\)\s*:\s*\??(?:int|string|bool|float|array|void|self)\b|\(\s*(?:int|string|float|bool)\s+\$/ },
  { name: 'strict_types', version: '7.0', re: /declare\s*\(\s*strict_types/ },
  { name: 'Nullable types', version: '7.1', re: /[(,]\s*\?[A-Za-z_\\]\w*\s+\$/ },
  { name: 'Typed properties', version: '7.4', re: /\b(?:public|protected|private)\s+(?:static\s+)?\??(?:int|string|bool|float|array|[A-Z]\w+)\s+\$/ },
  { name: 'Arrow functions', version: '7.4', re: /\bfn\s*\([^)]*\)\s*=>/ },
  { name: '??= operator', version: '7.4', re: /\?\?=/ },
  { name: 'match expression', version: '8.0', re: /\bmatch\s*\([^)]*\)\s*\{/ },
  { name: 'Nullsafe ?->', version: '8.0', re: /\?->/ },
  { name: 'Constructor promotion', version: '8.0', re: /function\s+__construct\s*\([^)]*\b(?:public|private|protected)\s+/ },
  { name: 'Enums', version: '8.1', re: /^\s*enum\s+\w+/m },
  { name: 'readonly', version: '8.1', re: /\breadonly\s+(?:public|private|protected|class|\w+\s+\$)/ },
];

module.exports = { rules, FEATURES };
