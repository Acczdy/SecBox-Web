const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync('templates/tools/search_hacking_tool.html', 'utf8');
const script = html.match(/{% block scripts %}\s*<script>([\s\S]*?)<\/script>/)[1]
  .replace(/\ninit\(\);\s*$/, '\n');

const context = {
  URL,
  console,
  localStorage: { getItem() { return null; }, setItem() {}, removeItem() {} },
  window: { open() { return { opener: {} }; } },
  document: { getElementById() { return null; }, querySelectorAll() { return []; }, querySelector() { return null; } },
  setTimeout
};
vm.createContext(context);
vm.runInContext(script, context);
const rules = vm.runInContext('RAW_RULES', context);

assert.strictEqual(context.normalizeDomainInput('https://WWW.Example.com:8443/path?q=1'), 'www.example.com');
assert.strictEqual(context.normalizeDomainInput('site:*.example.com'), 'example.com');
assert.strictEqual(context.normalizeDomainInput('not a domain'), '');

const google = Array.from(context.buildEngineQueries('google', 'site:{domain} inurl:admin | inurl:login'));
assert.deepStrictEqual(google, ['site:{domain} inurl:admin | login']);
assert.deepStrictEqual(
  Array.from(context.buildEngineQueries('google', 'site:{domain} filetype:docx | filetype:pdf')),
  ['site:{domain} filetype:docx | pdf']
);
assert.deepStrictEqual(
  Array.from(context.buildEngineQueries('google', 'site:{domain} filetype:doc | filetype:docx | filetype:pdf')),
  ['site:{domain} filetype:doc | docx | pdf']
);

const baidu = Array.from(context.buildEngineQueries('baidu', 'site:{domain} filetype:bak | intext:"后台管理"'));
assert.deepStrictEqual(baidu, ['site:{domain} inurl:.bak', 'site:{domain} "后台管理"']);
assert(!baidu.some(query => /\b(?:intext|inbody):/i.test(query)));

const bing = Array.from(context.buildEngineQueries('bing', 'site:{domain} inurl:admin | intext:password'));
assert.deepStrictEqual(bing, ['site:{domain} "admin"', 'site:{domain} inbody:password']);
assert(!bing.some(query => /\binurl:/i.test(query)));

for (const engine of ['google', 'baidu', 'bing']) {
  for (const rule of rules) {
    const queries = Array.from(context.buildEngineQueries(engine, rule.dork));
    assert(queries.length > 0, `${engine}/${rule.id} produced no query`);
    if (engine === 'google') {
      assert.strictEqual(queries.length, 1, `${engine}/${rule.id} must use one combined results page`);
    }
    for (const query of queries) {
      assert(query.includes('{domain}') || !rule.dork.includes('{domain}'), `${engine}/${rule.id} lost domain scope`);
      if (engine !== 'google') {
        assert(!/\s(?:OR|\|)\s/i.test(query), `${engine}/${rule.id} still contains a compound OR query`);
      }
      assert(!/\b(?:site|filetype|ext|intitle|inurl|intext|inbody):\s+/i.test(query),
        `${engine}/${rule.id} contains a space after an operator colon`);
    }
  }
}

console.log('search hacking syntax tests passed');
