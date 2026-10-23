'use strict';

/**
 * Minimal test runner: each case is a PHP snippet plus the rule ids that must
 * (and must not) be reported for the given target version.
 */
const assert = require('assert');
const { analyzeFile, v, scanProject } = require('../src/scanner');
const { rules } = require('../src/rules');
const { lex } = require('../src/lexer');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('  ✓ ' + name); }
  catch (e) { failed++; console.log('  ✕ ' + name + '\n      ' + e.message); }
}
const scan = (code, target = '8.4', type = 'php') =>
  analyzeFile(code, 'test.php', type, v(target), rules, { targetStr: target }).issues.map((i) => i.rule);
const has = (code, rule, target) => assert.ok(scan(code, target).includes(rule), `expected ${rule} in: ${code}\n      got: ${scan(code, target).join(', ')}`);
const not = (code, rule, target) => assert.ok(!scan(code, target).includes(rule), `did not expect ${rule} in: ${code}`);

console.log('lexer');
test('views keep length and line breaks', () => {
  const src = "<?php\n// mysql_query()\n$a = 'x'; /* c\n */ echo \"$b\";\n?>\n<p>html</p>";
  const l = lex(src);
  for (const k of ['code', 'src', 'str', 'dq']) {
    assert.strictEqual(l[k].length, src.length, k);
    assert.strictEqual(l[k].split('\n').length, src.split('\n').length, k);
  }
  assert.ok(!l.code.includes('mysql_query'));
  assert.ok(l.dq.includes('$b'));
});
test('heredoc / nowdoc contents are strings', () => {
  const l = lex("<?php\n$s = <<<EOT\nmysql_query(\$x)\nEOT;\n$t = <<<'N'\neach(\$a)\nN;\nfoo();");
  assert.ok(!l.code.includes('mysql_query'));
  assert.ok(!l.code.includes('each('));
  assert.ok(l.code.includes('foo()'));
});

console.log('compatibility rules');
test('mysql_*', () => { has('<?php mysql_query($q);', 'PHP-MYSQL'); not('<?php mysqli_query($l, $q);', 'PHP-MYSQL'); not('<?php $db->mysql_query($q);', 'PHP-MYSQL'); not('<?php // mysql_query($q)', 'PHP-MYSQL'); });
test('ereg / split', () => { has('<?php ereg("a", $s);', 'PHP-EREG'); has('<?php $p = split(",", $s);', 'PHP-EREG'); not('<?php preg_split("/,/", $s);', 'PHP-EREG'); not('<?php $str->split(",");', 'PHP-EREG'); });
test('each()', () => { has('<?php while (list($k,$v) = each($a)) {}', 'PHP-EACH'); has('<?php each($a);', 'PHP-EACH', '7.2'); not('<?php each($a);', 'PHP-EACH', '7.1'); });
test('create_function', () => has("<?php $f = create_function('$a', 'return 1;');", 'PHP-CREATE-FUNCTION'));
test('PHP 4 constructor', () => {
  has('<?php class Foo { function Foo() {} }', 'PHP-PHP4-CTOR');
  not('<?php class Foo { function __construct() {} function Foo() {} }', 'PHP-PHP4-CTOR');
  not('<?php namespace A; class Foo { function Foo() {} }', 'PHP-PHP4-CTOR');
});
test('curly offset', () => { has('<?php $c = $s{0};', 'PHP-STRING-BRACES'); not('<?php if ($s) { echo 1; }', 'PHP-STRING-BRACES'); not('<?php echo "{$s}";', 'PHP-STRING-BRACES'); });
test('nested ternary', () => { has("<?php $x = $a ? 1 : $b ? 2 : 3;", 'PHP-NESTED-TERNARY'); not("<?php $x = $a ? 1 : ($b ? 2 : 3);", 'PHP-NESTED-TERNARY'); not('<?php $x = $a ?? $b ?? 3;', 'PHP-NESTED-TERNARY'); not('<?php $x = $o?->a ? 1 : 2;', 'PHP-NESTED-TERNARY'); });
test('call-time pass-by-ref', () => { has('<?php foo(&$x);', 'PHP-CALLTIME-REF'); not('<?php function foo(&$x) {}', 'PHP-CALLTIME-REF'); not('<?php $f = function (&$x) use (&$y) {};', 'PHP-CALLTIME-REF'); not('<?php $a = array(&$x);', 'PHP-CALLTIME-REF'); });
test('preg /e', () => { has("<?php preg_replace('/a/e', 'b', $s);", 'PHP-PREG-E'); not("<?php preg_replace('/a/i', 'b', $s);", 'PHP-PREG-E'); });
test('implode order', () => { has("<?php implode($a, ',');", 'PHP-IMPLODE-ORDER'); not("<?php implode(',', $a);", 'PHP-IMPLODE-ORDER'); });
test('dynamic property', () => { has('<?php class A { function f() { $this->x = 1; } }', 'PHP-DYNAMIC-PROPERTY'); not('<?php class A { public $x; function f() { $this->x = 1; } }', 'PHP-DYNAMIC-PROPERTY'); not('<?php class A { function __construct(private int $x) { $this->x = 1; } }', 'PHP-DYNAMIC-PROPERTY'); });
test('dynamic property only for target >= 8.2', () => not('<?php class A { function f() { $this->x = 1; } }', 'PHP-DYNAMIC-PROPERTY', '8.1'));
test('implicit nullable', () => { has('<?php function f(array $a = null) {}', 'PHP-IMPLICIT-NULLABLE'); not('<?php function f(?array $a = null) {}', 'PHP-IMPLICIT-NULLABLE'); not('<?php function f(int|null $a = null) {}', 'PHP-IMPLICIT-NULLABLE'); });
test('required after optional', () => { has('<?php function f($a = 1, $b) {}', 'PHP-REQUIRED-AFTER-OPTIONAL'); not('<?php function f($b, $a = 1) {}', 'PHP-REQUIRED-AFTER-OPTIONAL'); });
test('ReturnTypeWillChange', () => { has('<?php class C implements Countable { public function count() { return 1; } }', 'PHP-RETURN-TYPE-WILL-CHANGE'); not('<?php class C implements Countable { public function count(): int { return 1; } }', 'PHP-RETURN-TYPE-WILL-CHANGE'); });
test('${} interpolation', () => { has('<?php echo "a ${b}";', 'PHP-DOLLAR-BRACE-INTERP'); not('<?php echo "a {$b}";', 'PHP-DOLLAR-BRACE-INTERP'); not("<?php echo 'a \${b}';", 'PHP-DOLLAR-BRACE-INTERP'); });
test('reserved class names', () => { has('<?php class String {}', 'PHP-RESERVED-NAME'); not('<?php class Strings {}', 'PHP-RESERVED-NAME'); not('<?php class Mixed {}', 'PHP-RESERVED-NAME', '7.4'); });
test('ini directives', () => {
  const r = analyzeFile('php_flag register_globals on\nphp_value allow_url_include 0\n', '.htaccess', 'ini', v('8.4'), rules, { targetStr: '8.4' }).issues;
  assert.strictEqual(r.length, 2);
  assert.strictEqual(r[0].severity, 'blocker');
  assert.strictEqual(r[1].severity, 'major');
});

console.log('security rules');
test('SQL injection', () => { has('<?php mysqli_query($db, "SELECT * FROM t WHERE id = $id");', 'SEC-SQL-INJECTION'); not("<?php $pdo->prepare('SELECT * FROM t WHERE id = ?');", 'SEC-SQL-INJECTION'); });
test('XSS', () => { has("<?php echo $_GET['q'];", 'SEC-XSS'); not("<?php echo htmlspecialchars($_GET['q']);", 'SEC-XSS'); });
test('file inclusion', () => has("<?php include $_GET['p'];", 'SEC-FILE-INCLUSION'));

console.log('modern code has no compatibility issues');
test('PHP 8.3 style class', () => {
  const code = `<?php
declare(strict_types=1);
namespace App;
#[\\Attribute]
final class A implements \\Countable {
    private array $items = [];
    public function __construct(private readonly ?string $name = null) {}
    public function count(): int { return \\count($this->items); }
    public function m(int $n): string {
        $r = match (true) { $n > 1 => 'a', default => 'b' };
        $x = $n ? 'y' : ($n > 2 ? 'z' : 'w');
        return "{$r}{$x}" . implode(',', $this->items) . ($this->name ?? '');
    }
}`;
  const res = analyzeFile(code, 'A.php', 'php', v('8.4'), rules, { targetStr: '8.4' }).issues.filter((i) => i.category !== 'best-practice');
  assert.deepStrictEqual(res.map((i) => i.rule + ':' + i.line), []);
});

(async () => {
  console.log('sample project');
  const r = await scanProject(require('path').join(__dirname, '..', 'samples', 'legacy-shop'), { target: '8.4' });
  test('sample project fails the gate with blockers', () => {
    assert.strictEqual(r.summary.qualityGate.status, 'FAILED');
    assert.ok(r.summary.bySeverity.blocker > 10);
  });
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
