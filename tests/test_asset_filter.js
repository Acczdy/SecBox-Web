const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync('templates/tools/assetdata_filter.html', 'utf8');
const script = html.match(/{% block scripts %}\s*<script>([\s\S]*?)<\/script>/)[1];
const ids = ['input', 'sortBtn', 'mainDomain', 'subDomain', 'emailList', 'ipList',
  'phoneList', 'idCardList', 'ipPortList', 'urlList', 'ipSegmentList', 'scanResult',
  'hashList', 'cveList', 'cidrList', 'ipv6List', 'macList', 'statsBar', 'toast', 'txt'];
const elements = Object.fromEntries(ids.map(id => [id, {
  value: '', textContent: '', innerHTML: '', disabled: false,
  style: {}, className: '', select() {},
  classList: { add() {}, remove() {} }
}]));
for (const id of ids.filter(id => !['input', 'sortBtn', 'statsBar', 'toast', 'txt'].includes(id))) {
  elements[id + 'Count'] = { textContent: '' };
}

const context = {
  document: { getElementById: id => elements[id], execCommand: () => true },
  URL, console, setTimeout: fn => fn()
};
vm.createContext(context);
vm.runInContext(script, context);

elements.input.value = [
  '[+] found https://api.dev.example.com:8443/login, vulnerability exists',
  'admin@EXAMPLE.COM 8.8.8.8:53 192.168.1.10:8080',
  '999.999.999.999:70000',
  'https://portal.example.co.uk/path',
  'shop.example.co.uk',
  'cbpc-1.130.0-latest.exe',
  '联系人 138-0013-8000，身份证 11010519491231002X',
  'CVE-2026-12345 d41d8cd98f00b204e9800998ecf8427e 10.20.0.0/16 2001:db8::1 AA-BB-CC-DD-EE-FF'
].join('\n');
context.sortAll();

assert.deepStrictEqual(elements.ipList.value.split('\n'), ['10.20.0.0', '192.168.1.10', '8.8.8.8']);
assert.deepStrictEqual(elements.ipPortList.value.split('\n'), ['192.168.1.10:8080', '8.8.8.8:53']);
assert(elements.urlList.value.includes('https://api.dev.example.com:8443/login'));
assert(!elements.urlList.value.includes('[+] found'));
assert(elements.mainDomain.value.split('\n').includes('example.co.uk'));
assert(elements.subDomain.value.split('\n').includes('portal.example.co.uk'));
assert.strictEqual(elements.emailList.value, 'admin@example.com');
assert.strictEqual(elements.phoneList.value, '13800138000');
assert.strictEqual(elements.idCardList.value, '11010519491231002X');
assert(!elements.mainDomain.value.includes('latest.exe'));
assert(!elements.subDomain.value.includes('cbpc-1.130.0-latest.exe'));
assert(elements.hashList.value.includes('MD5 d41d8cd98f00b204e9800998ecf8427e'));
assert.strictEqual(elements.cveList.value, 'CVE-2026-12345');
assert.strictEqual(elements.cidrList.value, '10.20.0.0/16');
assert.strictEqual(elements.ipv6List.value, '2001:db8::1');
assert.strictEqual(elements.macList.value, 'AA:BB:CC:DD:EE:FF');

context.filterPrivate();
assert.strictEqual(elements.ipList.value, '8.8.8.8');
assert.strictEqual(elements.ipPortList.value, '8.8.8.8:53');
assert.strictEqual(elements.ipSegmentList.value, '8.8.8.0/24');
assert(elements.statsBar.innerHTML.includes('IP'));

console.log('asset filter tests passed');
