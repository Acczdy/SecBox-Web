const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

const context = { window: {} };
vm.createContext(context);
vm.runInContext(fs.readFileSync('static/js/cyberchef_helpers.js', 'utf8'), context);
const detect = context.window.CyberChefHelpers.detectInput;

function types(value) {
    return Array.from(detect(value), item => item.type);
}

assert(types('{"name":"demo"}').includes('json'));
assert(types('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature').includes('jwt'));
assert(types('dGVzdCBkYXRh').includes('base64'));
assert(types('SGVsbG8td29ybGQ_').includes('base64url'));
assert(types('48 65 6c 6c 6f').includes('hex'));
assert(types('hello%20world').includes('url'));
assert(types('1710000000').includes('timestamp'));
assert(types('a'.repeat(64)).includes('hash'));
assert(types('-----BEGIN PRIVATE KEY-----\nabc').includes('pem'));
assert(types('plain text').length === 0);

console.log('cyberchef helper tests passed');
