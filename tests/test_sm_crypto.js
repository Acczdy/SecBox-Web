const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const context = { console };
context.window = context;
context.self = context;
vm.createContext(context);
for (const file of ['sm2.min.js', 'sm3.min.js', 'sm4.min.js']) {
  vm.runInContext(fs.readFileSync(`static/js/vendor/${file}`, 'utf8'), context);
}

assert.strictEqual(context.sm3('abc'), '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0');

const keyPair = context.sm2.generateKeyPairHex();
const plaintext = '本地国密测试';
const encrypted = context.sm2.doEncrypt(plaintext, keyPair.publicKey, 1);
assert.strictEqual(context.sm2.doDecrypt(encrypted, keyPair.privateKey, 1), plaintext);

const sm4Key = '0123456789abcdeffedcba9876543210';
const sm4Encrypted = context.sm4.encrypt(plaintext, sm4Key);
assert.strictEqual(context.sm4.decrypt(sm4Encrypted, sm4Key), plaintext);

console.log('vendored sm-crypto tests passed');
