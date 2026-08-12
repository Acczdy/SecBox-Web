const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync('templates/tools/process_check.html', 'utf8');
const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].pop()[1]
  .replace(/"\{\{ url_for\([^\n]+/, '"/static/Process.json", true);');
const elements = {};
const context = {
  console, setTimeout() {},
  document: {
    getElementById(id) { return elements[id] || (elements[id] = {value:'',textContent:'',style:{},addEventListener(){}}); },
    createElement() {
      const el = {textContent:'',innerText:''};
      Object.defineProperty(el, 'innerHTML', {set(v){el.textContent=String(v).replace(/<[^>]*>/g,'');}});
      return el;
    }
  }
};
vm.createContext(context);
vm.runInContext(script, context);

const data = {
  'S.exe': '不应该因其他文本误命中',
  'MsMpEng.exe': '<font color=red>Microsoft Defender</font>',
  'mimikatz.exe': 'Mimikatz 凭据工具'
};
const input = 'Image Name                     PID Services\nMsMpEng.exe                   1200 WinDefend\nnotepad.exe                   2200 N/A\nMIMIKATZ.EXE                  3300 N/A';
const result = context.matchProcessData(data, input);
assert.deepStrictEqual(Array.from(result, x => x.process), ['mimikatz.exe', 'MsMpEng.exe']);
assert.strictEqual(result[1].name, 'Microsoft Defender');
assert.strictEqual(result[0].risk, '高');
assert.strictEqual(context.classifyProcessBehavior('powershell.exe', 'powershell.exe -EncodedCommand AAA').risk, '高');
assert.strictEqual(context.classifyProcessBehavior('AnyDesk.exe', 'AnyDesk.exe').risk, '中');
console.log('process matching tests passed');
