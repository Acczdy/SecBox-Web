/**
 * Pure helpers used by CyberChef-lite.  They do not perform network requests.
 */
(function (root) {
    'use strict';

    function looksLikeBase64(value) {
        if (value.length < 8 || value.length % 4 === 1 || /[^A-Za-z0-9+/=]/.test(value)) return false;
        const padding = (value.match(/=+$/) || [''])[0];
        return padding.length <= 2 && !/=/.test(value.slice(0, value.length - padding.length));
    }

    function isValidDateTimestamp(value) {
        if (!/^\d{10}(?:\d{3})?$/.test(value)) return false;
        const number = Number(value);
        const date = new Date(value.length === 10 ? number * 1000 : number);
        const year = date.getUTCFullYear();
        return year >= 2000 && year <= 2100;
    }

    function detectInput(input) {
        const value = String(input || '').trim();
        if (!value) return [];
        const findings = [];
        const add = (type, label, operation, detail, confidence) => {
            findings.push({ type, label, operation: operation || '', detail: detail || '', confidence: confidence || 'medium' });
        };

        if (/^-----BEGIN (?:RSA |EC |OPENSSH |DSA )?(?:PRIVATE KEY|PUBLIC KEY|CERTIFICATE)-----/.test(value)) {
            add('pem', 'PEM 密钥/证书', '', '请注意私钥等敏感信息，不要复制到非可信环境', 'high');
        }

        if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
            add('jwt', 'JWT', '', '三段式令牌，可使用 JWT 工具进行离线解析', 'high');
        }

        try {
            const parsed = JSON.parse(value);
            if (parsed !== null && typeof parsed === 'object') {
                add('json', 'JSON', 'JSON Beautify', '结构化 JSON 数据', 'high');
            }
        } catch (_) {
            // Not JSON.
        }

        const hashTypes = {32: 'MD5/NTLM', 40: 'SHA1', 64: 'SHA256', 96: 'SHA384', 128: 'SHA512'};
        if (/^[a-fA-F0-9]+$/.test(value) && hashTypes[value.length]) {
            add('hash', hashTypes[value.length], '', `${value.length * 4} 位十六进制摘要；只能识别长度，无法确认算法`, 'high');
        }

        if (isValidDateTimestamp(value)) {
            add('timestamp', value.length === 10 ? 'Unix 秒时间戳' : 'Unix 毫秒时间戳', 'Unix Timestamp to Date', '时间范围在 2000 至 2100 年', 'high');
        }

        if (/%[0-9a-fA-F]{2}/.test(value)) {
            add('url', 'URL 编码', 'URL Decode', '包含百分号编码字节', 'high');
        }

        const compact = value.replace(/\s+/g, '');
        if (/^(?:[0-9a-fA-F]{2}[\s:]*){4,}$/.test(value) && compact.length % 2 === 0) {
            add('hex', '十六进制字节串', 'From Hex', '可尝试按 UTF-8 文本解码', 'high');
        }

        if (/^[A-Za-z0-9_-]{8,}={0,2}$/.test(compact) && /[-_]/.test(compact)) {
            add('base64url', 'Base64URL', 'From Base64', 'URL 安全的 Base64 编码', 'high');
        } else if (looksLikeBase64(compact) && (/[+/=]/.test(compact) || compact.length % 4 === 0)) {
            add('base64', 'Base64', 'From Base64', '可能是 Base64；短纯字母数字文本存在误判可能', 'medium');
        }

        if (/^https?:\/\//i.test(value)) {
            add('url-address', 'HTTP(S) URL', '', '仅识别文本，本工具不会访问该地址', 'high');
        }

        return findings;
    }

    function arrayBufferToWordArray(buffer) {
        const bytes = new Uint8Array(buffer);
        const words = [];
        for (let i = 0; i < bytes.length; i += 1) {
            words[i >>> 2] = (words[i >>> 2] || 0) | (bytes[i] << (24 - (i % 4) * 8));
        }
        if (!root.CryptoJS) throw new Error('CryptoJS 未加载');
        return root.CryptoJS.lib.WordArray.create(words, bytes.length);
    }

    root.CyberChefHelpers = { detectInput, arrayBufferToWordArray };
})(typeof window !== 'undefined' ? window : globalThis);
