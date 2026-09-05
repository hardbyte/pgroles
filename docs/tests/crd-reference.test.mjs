import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import Markdoc from "@markdoc/markdoc";

test("generated paths and constraints retain their literal spelling in Markdoc", () => {
  const source = fs.readFileSync(new URL("../src/pages/docs/reference/postgrespolicy-v1alpha1.md", import.meta.url), "utf8");
  const html = Markdoc.renderers.html(Markdoc.transform(Markdoc.parse(source))).replaceAll("&quot;", '"');
  assert.match(html, /<code>spec\.profiles\.&lt;name&gt;\.grants\[\]\.privileges<\/code>/);
  assert.doesNotMatch(html, /&amp;lt;name/);
  assert.match(html, /<code>[^<]*"pattern":"\^\[A-Za-z_\]\[A-Za-z0-9_\$-\]\*\$"[^<]*<\/code>/);
  assert.match(html, /<code>\{"required":\["type"\]\}<\/code>/);
});

test("table code preserves delimiters, pipes, and regular-expression escapes", () => {
  // The Rust code() unit test pins this table-safe code-span format.
  const source = '| Path | Definition |\n| --- | --- |\n| `` a`b\\|<name>\\d+$ `` | value |';
  const html = Markdoc.renderers.html(Markdoc.transform(Markdoc.parse(source)));
  assert.ok(html.includes('<code>a`b|&lt;name&gt;\\d+$</code>'));
  assert.equal((html.match(/<td>/g) || []).length, 2);
});
