const { test } = require('node:test');
const assert = require('node:assert/strict');
const { parseDiff, downloadName } = require('../static/js/diff-viewer.js');

test('identifies file, removed and added lines without counting Git headers', () => {
  const result = parseDiff('--- a/src/service.py\n+++ b/src/service.py\n@@ -1 +1,2 @@\n-eval(data)\n+import ast\n+ast.literal_eval(data)\n');
  assert.equal(result.filePath, 'src/service.py');
  assert.equal(result.removals, 1);
  assert.equal(result.additions, 2);
  assert.equal(result.rows[0].kind, 'meta');
  assert.equal(result.rows.at(-1).text, '+ast.literal_eval(data)');
});

test('handles CRLF and preserves indentation and HTML as code text', () => {
  const result = parseDiff('--- a/web.js\r\n+++ b/web.js\r\n@@ -1 +1 @@\r\n-  node.innerHTML = "<img onerror=alert(1)>";\r\n+  node.textContent = userInput;\r\n');
  assert.equal(result.rows[3].text, '-  node.innerHTML = "<img onerror=alert(1)>";');
  assert.equal(result.rows[4].text, '+  node.textContent = userInput;');
  assert.equal(result.additions, 1);
});

test('handles empty diff', () => {
  assert.deepEqual(parseDiff('').rows, []);
  assert.equal(parseDiff('').additions, 0);
});

test('creates clear patch and text download names', () => {
  assert.equal(downloadName('src/service.py', 'patch'), 'service.py.patch');
  assert.equal(downloadName('src/service.py', 'txt'), 'service.py.diff.txt');
  assert.equal(downloadName('src/bad:name.py', 'txt'), 'bad_name.py.diff.txt');
});
