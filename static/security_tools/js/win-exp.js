(function () {
    'use strict';

    const DATA_URL = '/static/security_tools/json/win-patch-exp-data.json';
    const VERSION_MAP = [
        {key: 'windows2012', patterns: [/windows server 2012/i, /windows 8(?:\.1)?/i]},
        {key: 'windows2008', patterns: [/windows server 2008/i, /windows (?:vista|7)/i]},
        {key: 'windows2003', patterns: [/windows server 2003/i, /windows xp/i]}
    ];

    function escapeHtml(value) {
        return String(value || '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function parseSystemInfo(text) {
        const source = String(text || '');
        const patches = new Set((source.match(/\bKB\d{5,8}\b/ig) || []).map(x => x.toUpperCase()));
        const osLine = source.match(/(?:OS Name|OS 名称|操作系统名称)\s*[:：]\s*([^\r\n]+)/i);
        const versionLine = source.match(/(?:OS Version|OS 版本|操作系统版本)\s*[:：]\s*([^\r\n]+)/i);
        const systemType = source.match(/(?:System Type|系统类型)\s*[:：]\s*([^\r\n]+)/i);
        const osText = [osLine && osLine[1], versionLine && versionLine[1], source.slice(0, 1200)].filter(Boolean).join(' ');
        let family = '';
        VERSION_MAP.some(item => item.patterns.some(pattern => pattern.test(osText)) && (family = item.key));
        return {
            patches,
            family,
            osName: osLine ? osLine[1].trim() : '未识别',
            osVersion: versionLine ? versionLine[1].trim() : '未识别',
            architecture: systemType ? systemType[1].trim() : (/\bx64\b|64-bit|64 位/i.test(source) ? '64 位' : /\bx86\b|32-bit|32 位/i.test(source) ? '32 位' : '未识别')
        };
    }

    function buildHardeningFindings(text) {
        const findings = [];
        if (/hotfix\(s\)\s*:\s*n\/a|修补程序\s*:\s*n\/a/i.test(text)) findings.push('未发现补丁列表，请确认 systeminfo 输出是否完整。');
        if (/windows (?:xp|vista)|server 2003|server 2008(?! r2)/i.test(text)) findings.push('检测到已结束支持的 Windows 版本，建议迁移到受支持版本。');
        if (/domain\s*:\s*workgroup|域\s*:\s*workgroup/i.test(text)) findings.push('主机未加入域；请确认是否符合资产管理基线。');
        return findings;
    }

    function renderSummary(info, findings) {
        const node = document.getElementById('system-summary');
        if (!node) return;
        node.innerHTML = '<div class="system-summary-grid">' +
            '<span>系统 <b>' + escapeHtml(info.osName) + '</b></span>' +
            '<span>版本 <b>' + escapeHtml(info.osVersion) + '</b></span>' +
            '<span>架构 <b>' + escapeHtml(info.architecture) + '</b></span>' +
            '<span>补丁 <b>' + info.patches.size + '</b></span>' +
            '</div>' + (findings.length ? '<div class="baseline-findings">' + findings.map(x => '<div><i class="bi bi-exclamation-circle"></i> ' + escapeHtml(x) + '</div>').join('') + '</div>' : '');
        node.style.display = 'block';
    }

    function candidateRows(data, info) {
        const families = info.family && data[info.family] ? [info.family] : Object.keys(data);
        const rows = [];
        families.forEach(family => Object.entries(data[family] || {}).forEach(([patch, advisory]) => {
            if (!info.patches.has(patch.toUpperCase())) rows.push({family, patch, advisory});
        }));
        return rows;
    }

    function renderCandidates(rows, info) {
        const container = document.getElementById('exp-info-list');
        if (!container) return;
        const scope = info.family ? info.family : '系统版本未识别，展示全部旧版候选';
        if (!rows.length) {
            container.innerHTML = '<div class="alert alert-success">当前离线旧版知识库中未发现缺失补丁候选。</div>';
            return;
        }
        container.innerHTML = '<div class="candidate-note"><b>匹配范围：</b>' + escapeHtml(scope) +
            '。以下仅表示输入中未发现对应 KB，不代表漏洞一定存在或可利用；仍需核对适用产品、版本、累积更新和缓解措施。</div>' +
            '<div class="table-responsive"><table class="table exp-table"><thead><tr><th>系统</th><th>参考补丁</th><th>公告/候选</th></tr></thead><tbody>' +
            rows.map(row => '<tr><td>' + escapeHtml(row.family) + '</td><td>' + escapeHtml(row.patch) + '</td><td>' + escapeHtml(row.advisory) + '</td></tr>').join('') +
            '</tbody></table></div>';
    }

    async function showExpInfo() {
        const input = document.getElementById('patchlist');
        const text = input ? input.value.trim() : '';
        const alertNode = document.getElementById('alert-not-null');
        if (!text) {
            if (alertNode) alertNode.style.display = 'block';
            return;
        }
        if (alertNode) alertNode.style.display = 'none';
        const info = parseSystemInfo(text);
        renderSummary(info, buildHardeningFindings(text));
        try {
            const response = await fetch(DATA_URL, {credentials: 'same-origin'});
            if (!response.ok) throw new Error('HTTP ' + response.status);
            renderCandidates(candidateRows(await response.json(), info), info);
        } catch (error) {
            document.getElementById('exp-info-list').innerHTML = '<div class="alert alert-danger">离线补丁知识库加载失败，请检查静态文件。</div>';
        }
    }

    window.parseWindowsSystemInfo = parseSystemInfo;
    window.show_exp_info = showExpInfo;
    window.close_alert = function (button) { if (button && button.parentElement) button.parentElement.style.display = 'none'; };
})();
