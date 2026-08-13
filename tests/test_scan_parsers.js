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
assert(result.data.analysis.some(x => x.title === '资产攻击面排行'));
assert(result.sectionsHtml.includes('高关注攻击面'));

result = context.parseMasscan(context.MASSCAN_SAMPLE);
assert.strictEqual(result.data.summary['主机'], 2);
assert.strictEqual(result.data.records.length, 3);
assert(result.data.analysis.some(x => x.title === '服务暴露聚合'));

result = context.parseSecurityLog(context.LOG_SAMPLE);
assert.strictEqual(result.data.summary['事件'], 4);
assert.strictEqual(result.data.summary['登录失败'], 1);
assert.strictEqual(result.data.summary['高风险'], 1);
assert(result.sectionsHtml.includes('攻击源/相关地址排行'));

result = context.parseNuclei(context.NUCLEI_SAMPLE);
assert.strictEqual(result.data.records.length, 2);
assert.strictEqual(result.data.summary['高危'], 1);
assert(result.sectionsHtml.includes('模板命中聚合'));
result = context.parseNessus(context.NESSUS_SAMPLE);
assert.strictEqual(result.data.records[0].risk, 'High');
assert.strictEqual(result.data.records[0].cve, 'CVE-2026-1234');
assert.strictEqual(result.data.assets[0].host, '192.0.2.10');
assert.strictEqual(result.data.vulnerabilities[0].hostCount, 1);
assert(result.sectionsHtml.includes('优先处置队列'));
assert(result.sectionsHtml.includes('资产风险排行'));
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
const nessusActionable = 'Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Solution,Exploit Available\n'
  + '20001,CVE-2026-9999,9.8,Critical,10.0.0.8,tcp,443,RCE,Remote code execution,Apply vendor patch,true\n'
  + '20001,CVE-2026-9999,9.8,Critical,10.0.0.9,tcp,443,RCE,Remote code execution,Apply vendor patch,true';
result = context.parseNessus(nessusActionable);
assert.strictEqual(result.data.summary['可利用'], 2);
assert.strictEqual(result.data.vulnerabilities.length, 1);
assert.strictEqual(result.data.vulnerabilities[0].hostCount, 2);
assert.strictEqual(result.data.assets.length, 2);
assert.strictEqual(result.data.priority.length, 2);
assert(result.sectionsHtml.includes('Apply vendor patch'));
result = context.parseWebDiscovery(context.WEBSCAN_SAMPLE);
assert.strictEqual(result.data.records.length, 2);
assert(result.sectionsHtml.includes('优先复核路径'));

result = context.parseFscan(context.FSCAN_SAMPLE);
assert(result.sectionsHtml.includes('资产风险排行'));
assert(result.data.analysis.length >= 2);
result = context.parseMimikatz(context.MIMIKATZ_SAMPLE);
assert(result.sectionsHtml.includes('凭据处置队列'));
assert(result.sectionsHtml.includes('凭据复用分析'));
assert(result.data.analysis.length >= 2);

const exportCases = [
  ['fscan', context.parseFscan(context.FSCAN_SAMPLE).data, '优先处置队列'],
  ['nmap', context.parseNmap(context.NMAP_SAMPLE).data, '高关注攻击面'],
  ['masscan', context.parseMasscan(context.MASSCAN_SAMPLE).data, '服务暴露聚合'],
  ['log', context.parseSecurityLog(context.LOG_SAMPLE).data, '攻击源/相关地址排行'],
  ['nuclei', context.parseNuclei(context.NUCLEI_SAMPLE).data, '模板命中聚合'],
  ['nessus', context.parseNessus(nessusActionable).data, '优先处置队列'],
  ['webscan', context.parseWebDiscovery(context.WEBSCAN_SAMPLE).data, '优先复核路径'],
  ['mimikatz', context.parseMimikatz(context.MIMIKATZ_SAMPLE).data, '凭据处置队列']
];

for (const [tab, data, analysisTitle] of exportCases) {
  const report = {tab, time: 'now', data};
  const exports = [
    context.buildTxt(report),
    context.buildMd(report),
    context.buildExcel(report),
    context.buildHtmlReport(report)
  ];
  for (const output of exports) {
    assert(output.includes(analysisTitle), `${tab} export is missing ${analysisTitle}`);
  }
  assert(exports[1].includes('#'));
  assert(exports[2].includes('<Workbook'));
  assert(exports[3].includes('<table>'));
}

console.log('scan parser tests passed');
