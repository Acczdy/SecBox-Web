const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync('templates/tools/file_analysis.html', 'utf8');
const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)];
const elements = {};
function element() { return {files: [], classList:{add(){},remove(){}}, addEventListener(){}, style:{}}; }
const context = {
  window: {}, console, Promise, Uint8Array, Uint32Array, ArrayBuffer,
  document: {getElementById(id){return elements[id]||(elements[id]=element());}},
  setTimeout(){}, alert(){}, URL, Blob
};
vm.createContext(context);
vm.runInContext(scripts[scripts.length - 1][1], context);

assert.strictEqual(context.identify(new Uint8Array([0x4d,0x5a,0,0]), 'sample.exe'), 'PE/Windows 可执行文件');
assert.strictEqual(context.identify(new Uint8Array([0x25,0x50,0x44,0x46]), 'a.bin'), 'PDF');
assert.strictEqual(context.entropy(new Uint8Array(100)), 0);
assert(context.entropy(new Uint8Array(Array.from({length:256},(_,i)=>i))) > 7.9);
assert.deepStrictEqual(Array.from(context.extractStrings(new Uint8Array(Buffer.from('abc\0hello-world\0xyz')))), ['hello-world']);

const secrets = context.scanSensitiveStrings([
  'AKIAABCDEFGHIJKLMNOP',
  'postgresql://analyst:secret@localhost/audit',
  '-----BEGIN PRIVATE KEY-----'
]);
assert.deepStrictEqual(Array.from(secrets, item => item.type), ['AWS Access Key', 'PEM 私钥', '数据库连接串']);
assert(context.extensionMismatch('invoice.pdf', 'PE/Windows 可执行文件').includes('不一致'));
assert.strictEqual(context.extensionMismatch('photo.png', 'PNG'), '');

const pe = new Uint8Array(1024);
pe[0] = 0x4d; pe[1] = 0x5a;
new DataView(pe.buffer).setUint32(0x3c, 0x80, true);
pe.set([0x50, 0x45, 0, 0], 0x80);
const peView = new DataView(pe.buffer);
peView.setUint16(0x84, 0x8664, true);
peView.setUint16(0x86, 1, true);
peView.setUint32(0x88, 1710000000, true);
peView.setUint16(0x94, 0, true);
pe.set(Buffer.from('.text'), 0x98);
peView.setUint32(0x98 + 16, 256, true);
peView.setUint32(0x98 + 20, 512, true);
for (let i = 0; i < 256; i += 1) pe[512 + i] = i;
const peInfo = context.readPeInfo(pe);
assert.strictEqual(peInfo.architecture, 'x64');
assert.strictEqual(peInfo.sections, 1);
assert(peInfo.sectionList[0].entropy > 7.9);
assert(context.analyzeFormat('PE/Windows 可执行文件', pe, []).risks[0].includes('高熵节'));
console.log('file analysis tests passed');
