const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync('templates/tools/scan_parser.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
const context = { window: {}, console, navigator: {}, alert() {}, setTimeout() {}, clearTimeout() {} };
vm.createContext(context);
vm.runInContext(scripts[scripts.length - 1][1], context);

let result = context.parseNmap(context.NMAP_SAMPLE);
assert.strictEqual(result.data.summary['主机'], 1);
assert.strictEqual(result.data.summary['开放端口'], 2);
assert.strictEqual(result.data.records[0].service, 'ssh');

result = context.parseMasscan(context.MASSCAN_SAMPLE);
assert.strictEqual(result.data.summary['主机'], 2);
assert.strictEqual(result.data.records.length, 3);

result = context.parseSecurityLog(context.LOG_SAMPLE);
assert.strictEqual(result.data.summary['事件'], 4);
assert.strictEqual(result.data.summary['登录失败'], 1);
assert.strictEqual(result.data.summary['高风险'], 1);

result = context.parseNuclei(context.NUCLEI_SAMPLE);
assert.strictEqual(result.data.records.length, 2);
assert.strictEqual(result.data.summary['高危'], 1);
result = context.parseNessus(context.NESSUS_SAMPLE);
assert.strictEqual(result.data.records[0].risk, 'High');
const nessusComplex = '\ufeffPlugin ID,Risk,Host,Protocol,Port,Plugin Name,Description\r\n'
  + '10002,Critical,192.0.2.20,tcp,443,"TLS, certificate issue","Line one\r\nLine two"\r\n';
result = context.parseNessus(nessusComplex);
assert.strictEqual(result.data.records.length, 1);
assert.strictEqual(result.data.records[0].name, 'TLS, certificate issue');
assert(result.data.records[0].synopsis.includes('Line two'));
const nessusSemicolon = 'Plugin ID;Severity;Hostname;Protocol;Port;Name;Synopsis\n10003;Medium;host.local;tcp;80;Web issue;Review config';
result = context.parseNessus(nessusSemicolon);
assert.strictEqual(result.data.records[0].host, 'host.local');
assert.strictEqual(result.data.records[0].risk, 'Medium');
assert.strictEqual(context.detectCsvDelimiter(nessusSemicolon), ';');
result = context.parseWebDiscovery(context.WEBSCAN_SAMPLE);
assert.strictEqual(result.data.records.length, 2);

for (const tab of ['nmap', 'masscan', 'log', 'nuclei', 'nessus', 'webscan']) {
  const parser = {nmap:'parseNmap',masscan:'parseMasscan',log:'parseSecurityLog',nuclei:'parseNuclei',nessus:'parseNessus',webscan:'parseWebDiscovery'}[tab];
  const sample = {nmap:'NMAP_SAMPLE',masscan:'MASSCAN_SAMPLE',log:'LOG_SAMPLE',nuclei:'NUCLEI_SAMPLE',nessus:'NESSUS_SAMPLE',webscan:'WEBSCAN_SAMPLE'}[tab];
  const report = {tab, time: 'now', data: tab === 'nmap' ? context.parseNmap(context.NMAP_SAMPLE).data :
    context[parser](context[sample]).data};
  assert(context.buildTxt(report).length > 20);
  assert(context.buildMd(report).includes('#'));
  assert(context.buildExcel(report).includes('<Workbook'));
  assert(context.buildHtmlReport(report).includes('<table>'));
}

console.log('scan parser tests passed');
