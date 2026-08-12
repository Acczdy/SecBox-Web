/**
 * CyberChef-lite Controller
 */

document.addEventListener('DOMContentLoaded', function() {
    
    // --- Data Structures ---
    
    const Categories = {
        '编码转换': ['To Base64', 'From Base64', 'To Base32', 'From Base32', 'To Hex', 'From Hex', 'URL Encode', 'URL Decode', 'To HTML Entity', 'From HTML Entity', 'To ASCII', 'From ASCII'],
        '哈希校验': ['MD5', 'SHA1', 'SHA256', 'SHA512', 'SHA3', 'RIPEMD160', 'HmacMD5', 'HmacSHA256', 'SM3'],
        '加密解密': ['AES Encrypt', 'AES Decrypt', 'DES Encrypt', 'DES Decrypt', 'TripleDES Encrypt', 'TripleDES Decrypt', 'Rabbit Encrypt', 'Rabbit Decrypt', 'RC4 Encrypt', 'RC4 Decrypt', 'RC4Drop Encrypt', 'RC4Drop Decrypt', 'RSA Encrypt', 'RSA Decrypt', 'SM2 Encrypt', 'SM2 Decrypt', 'SM4 Encrypt', 'SM4 Decrypt', 'XOR'],
        '数据格式化': ['JSON Beautify', 'JSON Minify', 'Remove Whitespace', 'Reverse String', 'To Upper Case', 'To Lower Case'],
        '其他': ['Unix Timestamp to Date', 'Date to Unix Timestamp']
    };

    const Operations = {
        // --- Encoding ---
        'To Base64': {
            args: [{name: 'URL安全', type: 'option', options: ['False', 'True'], default: 'False'}],
            exec: (input, args) => {
                try {
                    let res = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(input));
                    if (args[0] === 'True') {
                        res = res.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                    }
                    return res;
                } catch (e) {
                    return 'Base64编码错误: ' + e.message;
                }
            }
        },
        'From Base64': {
            args: [{name: 'URL安全', type: 'option', options: ['Auto', 'False', 'True'], default: 'Auto'}],
            exec: (input, args) => {
                try {
                    let clean = input.replace(/\s/g, '');
                    // Auto detect URL-safe Base64
                    if (args[0] === 'Auto' && (clean.includes('-') || clean.includes('_'))) {
                        clean = clean.replace(/-/g, '+').replace(/_/g, '/');
                        while (clean.length % 4) clean += '=';
                    } else if (args[0] === 'True') {
                        clean = clean.replace(/-/g, '+').replace(/_/g, '/');
                        while (clean.length % 4) clean += '=';
                    }
                    const words = CryptoJS.enc.Base64.parse(clean);
                    return words.toString(CryptoJS.enc.Utf8);
                } catch (e) {
                    return 'Base64解码错误: ' + e.message;
                }
            }
        },
        'To Base32': {
            exec: (input) => {
                try {
                    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
                    // 使用 TextEncoder 正确处理 Unicode 字符
                    const encoder = new TextEncoder();
                    const bytes = encoder.encode(input);
                    let bits = '';
                    let output = '';

                    for (let i = 0; i < bytes.length; i++) {
                        bits += bytes[i].toString(2).padStart(8, '0');
                    }

                    while (bits.length >= 5) {
                        output += alphabet[parseInt(bits.substring(0, 5), 2)];
                        bits = bits.substring(5);
                    }

                    if (bits.length > 0) {
                        output += alphabet[parseInt(bits.padEnd(5, '0'), 2)];
                    }

                    while (output.length % 8 !== 0) {
                        output += '=';
                    }
                    return output;
                } catch (e) {
                    return 'Base32编码错误: ' + e.message;
                }
            }
        },
        'From Base32': {
            exec: (input) => {
                try {
                    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
                    let bits = '';
                    const byteArr = [];

                    input = input.replace(/=/g, '').toUpperCase().replace(/\s/g, '');

                    for (let i = 0; i < input.length; i++) {
                        const val = alphabet.indexOf(input[i]);
                        if (val === -1) continue;
                        bits += val.toString(2).padStart(5, '0');
                    }

                    while (bits.length >= 8) {
                        byteArr.push(parseInt(bits.substring(0, 8), 2));
                        bits = bits.substring(8);
                    }

                    // 使用 TextDecoder 正确解码 UTF-8
                    const decoder = new TextDecoder();
                    return decoder.decode(new Uint8Array(byteArr));
                } catch (e) {
                    return 'Base32解码错误: ' + e.message;
                }
            }
        },
        'To Hex': {
            args: [{name: '分隔符', type: 'option', options: ['None', 'Space', 'Colon', 'Percent', '0x', '\\x'], default: 'None'}],
            exec: (input, args) => {
                try {
                    let hex = CryptoJS.enc.Hex.stringify(CryptoJS.enc.Utf8.parse(input));
                    const delimMap = {'None': '', 'Space': ' ', 'Colon': ':', 'Percent': '%', '0x': '0x', '\\x': '\\x'};
                    const delim = delimMap[args[0]];

                    if (delim === '') return hex;

                    let res = '';
                    for (let i = 0; i < hex.length; i += 2) {
                        if (args[0] === '0x' || args[0] === '\\x') {
                            res += delim + hex.substr(i, 2);
                        } else {
                            res += hex.substr(i, 2) + (i < hex.length - 2 ? delim : '');
                        }
                    }
                    return res;
                } catch (e) {
                    return 'Hex编码错误: ' + e.message;
                }
            }
        },
        'From Hex': {
            args: [{name: '分隔符', type: 'option', options: ['Auto', 'None', 'Space', 'Colon', 'Percent', '0x', '\\x'], default: 'Auto'}],
            exec: (input, args) => {
                try {
                    // Simple cleanup for common delimiters
                    let clean = input.replace(/[\s:%,]/g, '').replace(/0x/gi, '').replace(/\\x/gi, '');
                    const words = CryptoJS.enc.Hex.parse(clean);
                    return words.toString(CryptoJS.enc.Utf8);
                } catch (e) {
                    return 'Hex解码错误: ' + e.message;
                }
            }
        },
        'URL Encode': {
            args: [{name: '编码所有字符', type: 'option', options: ['False', 'True'], default: 'False'}],
            exec: (input, args) => {
                try {
                    if (args[0] === 'True') {
                        // 正确处理多字节字符：先将字符串转为UTF-8字节，再编码
                        const encoder = new TextEncoder();
                        const bytes = encoder.encode(input);
                        let result = '';
                        for (let i = 0; i < bytes.length; i++) {
                            const hex = bytes[i].toString(16).toUpperCase();
                            result += '%' + (hex.length < 2 ? '0' + hex : hex);
                        }
                        return result;
                    }
                    return encodeURIComponent(input);
                } catch (e) {
                    return 'URL编码错误: ' + e.message;
                }
            }
        },
        'URL Decode': {
            exec: (input) => {
                try {
                    return decodeURIComponent(input);
                } catch (e) {
                    return 'URL解码错误: ' + e.message;
                }
            }
        },
        'To HTML Entity': {
            args: [{name: '格式', type: 'option', options: ['十进制 (&#dd;)', '十六进制 (&#xhh;)'], default: '十进制 (&#dd;)'}],
            exec: (input, args) => {
                try {
                    return input.replace(/[\u00A0-\u9999<>\&]/g, function(i) {
                        if (args[0].startsWith('十六进制')) {
                            return '&#x' + i.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0') + ';';
                        }
                        return '&#'+i.charCodeAt(0)+';';
                    });
                } catch (e) {
                    return 'HTML实体编码错误: ' + e.message;
                }
            }
        },
        'From HTML Entity': {
            exec: (input) => {
                try {
                    const txt = document.createElement("textarea");
                    txt.innerHTML = input;
                    return txt.value;
                } catch (e) {
                    return 'HTML实体解码错误: ' + e.message;
                }
            }
        },
        'To ASCII': {
            args: [
                {name: '目标进制', type: 'option', options: ['10进制', '16进制', '8进制', '2进制'], default: '10进制'}
            ],
            exec: (input, args) => {
                try {
                    const baseMap = {'10进制': 10, '16进制': 16, '8进制': 8, '2进制': 2};
                    const base = baseMap[args[0]] || 10;

                    return input.split('').map(c => c.charCodeAt(0).toString(base)).join(' ');
                } catch (e) {
                    return 'ASCII编码错误: ' + e.message;
                }
            }
        },
        'From ASCII': {
            args: [
                {name: '源进制', type: 'option', options: ['10进制', '16进制', '8进制', '2进制'], default: '10进制'}
            ],
            exec: (input, args) => {
                try {
                    const baseMap = {'10进制': 10, '16进制': 16, '8进制': 8, '2进制': 2};
                    const base = baseMap[args[0]] || 10;

                    // Auto split by space or common delimiters
                    const parts = input.trim().split(/[\s,]+/);
                    return parts.map(c => String.fromCharCode(parseInt(c, base))).join('');
                } catch (e) {
                    return 'ASCII解码错误: ' + e.message;
                }
            }
        },

        // --- Hashing ---
        'MD5': {
            exec: (input) => {
                try {
                    return CryptoJS.MD5(input).toString();
                } catch (e) {
                    return 'MD5计算错误: ' + e.message;
                }
            }
        },
        'SHA1': {
            exec: (input) => {
                try {
                    return CryptoJS.SHA1(input).toString();
                } catch (e) {
                    return 'SHA1计算错误: ' + e.message;
                }
            }
        },
        'SHA256': {
            exec: (input) => {
                try {
                    return CryptoJS.SHA256(input).toString();
                } catch (e) {
                    return 'SHA256计算错误: ' + e.message;
                }
            }
        },
        'SHA512': {
            exec: (input) => {
                try {
                    return CryptoJS.SHA512(input).toString();
                } catch (e) {
                    return 'SHA512计算错误: ' + e.message;
                }
            }
        },
        'SHA3': {
            args: [{name: 'Output Length', type: 'option', options: ['256', '224', '384', '512'], default: '512'}],
            exec: (input, args) => {
                try {
                    return CryptoJS.SHA3(input, { outputLength: parseInt(args[0]) }).toString();
                } catch (e) {
                    return 'SHA3计算错误: ' + e.message;
                }
            }
        },
        'RIPEMD160': {
            exec: (input) => {
                try {
                    return CryptoJS.RIPEMD160(input).toString();
                } catch (e) {
                    return 'RIPEMD160计算错误: ' + e.message;
                }
            }
        },
        'HmacMD5': {
            args: [{name: 'Passphrase', type: 'string'}],
            exec: (input, args) => {
                try {
                    return CryptoJS.HmacMD5(input, args[0] || '').toString();
                } catch (e) {
                    return 'HmacMD5计算错误: ' + e.message;
                }
            }
        },
        'HmacSHA256': {
            args: [{name: 'Passphrase', type: 'string'}],
            exec: (input, args) => {
                try {
                    return CryptoJS.HmacSHA256(input, args[0] || '').toString();
                } catch (e) {
                    return 'HmacSHA256计算错误: ' + e.message;
                }
            }
        },
        'SM3': {
            exec: (input) => {
                try {
                    if (!window.sm3) return 'SM3库未加载';
                    return window.sm3(input);
                } catch (e) {
                    return 'SM3计算错误: ' + e.message;
                }
            }
        },

        // --- Encryption ---
        'AES Encrypt': {
            args: [
                {name: 'Key', type: 'string'},
                {name: 'IV (ECB模式可留空)', type: 'string'},
                {name: 'Mode', type: 'option', options: ['CBC', 'ECB', 'CFB', 'CTR', 'OFB'], default: 'CBC'},
                {name: 'Padding', type: 'option', options: ['Pkcs7', 'Iso10126', 'AnsiX923', 'ZeroPadding', 'NoPadding'], default: 'Pkcs7'}
            ],
            exec: (input, args) => {
                try {
                    const key = CryptoJS.enc.Utf8.parse(args[0] || '');
                    const mode = CryptoJS.mode[args[2]];
                    const padding = CryptoJS.pad[args[3]];

                    const config = { mode: mode, padding: padding };

                    // ECB 模式不需要 IV
                    if (args[2] !== 'ECB' && args[1]) {
                        config.iv = CryptoJS.enc.Utf8.parse(args[1]);
                    }

                    return CryptoJS.AES.encrypt(input, key, config).toString();
                } catch (e) {
                    return 'AES加密错误: ' + e.message;
                }
            }
        },
        'AES Decrypt': {
            args: [
                {name: 'Key', type: 'string'},
                {name: 'IV (ECB模式可留空)', type: 'string'},
                {name: 'Mode', type: 'option', options: ['CBC', 'ECB', 'CFB', 'CTR', 'OFB'], default: 'CBC'},
                {name: 'Padding', type: 'option', options: ['Pkcs7', 'Iso10126', 'AnsiX923', 'ZeroPadding', 'NoPadding'], default: 'Pkcs7'}
            ],
            exec: (input, args) => {
                try {
                    const key = CryptoJS.enc.Utf8.parse(args[0] || '');
                    const mode = CryptoJS.mode[args[2]];
                    const padding = CryptoJS.pad[args[3]];

                    const config = { mode: mode, padding: padding };

                    // ECB 模式不需要 IV
                    if (args[2] !== 'ECB' && args[1]) {
                        config.iv = CryptoJS.enc.Utf8.parse(args[1]);
                    }

                    return CryptoJS.AES.decrypt(input, key, config).toString(CryptoJS.enc.Utf8);
                } catch (e) {
                    return 'AES解密错误: ' + e.message;
                }
            }
        },
        'DES Encrypt': {
            args: [
                {name: 'Key', type: 'string'},
                {name: 'IV (ECB模式可留空)', type: 'string'},
                {name: 'Mode', type: 'option', options: ['CBC', 'ECB', 'CFB', 'CTR', 'OFB'], default: 'CBC'},
                {name: 'Padding', type: 'option', options: ['Pkcs7', 'Iso10126', 'AnsiX923', 'ZeroPadding', 'NoPadding'], default: 'Pkcs7'}
            ],
            exec: (input, args) => {
                try {
                    const key = CryptoJS.enc.Utf8.parse(args[0] || '');
                    const mode = CryptoJS.mode[args[2]];
                    const padding = CryptoJS.pad[args[3]];

                    const config = { mode: mode, padding: padding };
                    if (args[2] !== 'ECB' && args[1]) {
                        config.iv = CryptoJS.enc.Utf8.parse(args[1]);
                    }

                    return CryptoJS.DES.encrypt(input, key, config).toString();
                } catch (e) {
                    return 'DES加密错误: ' + e.message;
                }
            }
        },
        'DES Decrypt': {
            args: [
                {name: 'Key', type: 'string'},
                {name: 'IV (ECB模式可留空)', type: 'string'},
                {name: 'Mode', type: 'option', options: ['CBC', 'ECB', 'CFB', 'CTR', 'OFB'], default: 'CBC'},
                {name: 'Padding', type: 'option', options: ['Pkcs7', 'Iso10126', 'AnsiX923', 'ZeroPadding', 'NoPadding'], default: 'Pkcs7'}
            ],
            exec: (input, args) => {
                try {
                    const key = CryptoJS.enc.Utf8.parse(args[0] || '');
                    const mode = CryptoJS.mode[args[2]];
                    const padding = CryptoJS.pad[args[3]];

                    const config = { mode: mode, padding: padding };
                    if (args[2] !== 'ECB' && args[1]) {
                        config.iv = CryptoJS.enc.Utf8.parse(args[1]);
                    }

                    return CryptoJS.DES.decrypt(input, key, config).toString(CryptoJS.enc.Utf8);
                } catch (e) {
                    return 'DES解密错误: ' + e.message;
                }
            }
        },
        'TripleDES Encrypt': {
            args: [
                {name: 'Key', type: 'string'},
                {name: 'IV (ECB模式可留空)', type: 'string'},
                {name: 'Mode', type: 'option', options: ['CBC', 'ECB', 'CFB', 'CTR', 'OFB'], default: 'CBC'},
                {name: 'Padding', type: 'option', options: ['Pkcs7', 'Iso10126', 'AnsiX923', 'ZeroPadding', 'NoPadding'], default: 'Pkcs7'}
            ],
            exec: (input, args) => {
                try {
                    const key = CryptoJS.enc.Utf8.parse(args[0] || '');
                    const mode = CryptoJS.mode[args[2]];
                    const padding = CryptoJS.pad[args[3]];

                    const config = { mode: mode, padding: padding };
                    if (args[2] !== 'ECB' && args[1]) {
                        config.iv = CryptoJS.enc.Utf8.parse(args[1]);
                    }

                    return CryptoJS.TripleDES.encrypt(input, key, config).toString();
                } catch (e) {
                    return 'TripleDES加密错误: ' + e.message;
                }
            }
        },
        'TripleDES Decrypt': {
            args: [
                {name: 'Key', type: 'string'},
                {name: 'IV (ECB模式可留空)', type: 'string'},
                {name: 'Mode', type: 'option', options: ['CBC', 'ECB', 'CFB', 'CTR', 'OFB'], default: 'CBC'},
                {name: 'Padding', type: 'option', options: ['Pkcs7', 'Iso10126', 'AnsiX923', 'ZeroPadding', 'NoPadding'], default: 'Pkcs7'}
            ],
            exec: (input, args) => {
                try {
                    const key = CryptoJS.enc.Utf8.parse(args[0] || '');
                    const mode = CryptoJS.mode[args[2]];
                    const padding = CryptoJS.pad[args[3]];

                    const config = { mode: mode, padding: padding };
                    if (args[2] !== 'ECB' && args[1]) {
                        config.iv = CryptoJS.enc.Utf8.parse(args[1]);
                    }

                    return CryptoJS.TripleDES.decrypt(input, key, config).toString(CryptoJS.enc.Utf8);
                } catch (e) {
                    return 'TripleDES解密错误: ' + e.message;
                }
            }
        },
        'Rabbit Encrypt': {
            args: [{name: 'Passphrase', type: 'string'}],
            exec: (input, args) => {
                try {
                    return CryptoJS.Rabbit.encrypt(input, args[0] || '').toString();
                } catch (e) {
                    return 'Rabbit加密错误: ' + e.message;
                }
            }
        },
        'Rabbit Decrypt': {
            args: [{name: 'Passphrase', type: 'string'}],
            exec: (input, args) => {
                try {
                    return CryptoJS.Rabbit.decrypt(input, args[0] || '').toString(CryptoJS.enc.Utf8);
                } catch (e) {
                    return 'Rabbit解密错误: ' + e.message;
                }
            }
        },
        'RC4 Encrypt': {
            args: [{name: 'Passphrase', type: 'string'}],
            exec: (input, args) => {
                try {
                    return CryptoJS.RC4.encrypt(input, args[0] || '').toString();
                } catch (e) {
                    return 'RC4加密错误: ' + e.message;
                }
            }
        },
        'RC4 Decrypt': {
            args: [{name: 'Passphrase', type: 'string'}],
            exec: (input, args) => {
                try {
                    return CryptoJS.RC4.decrypt(input, args[0] || '').toString(CryptoJS.enc.Utf8);
                } catch (e) {
                    return 'RC4解密错误: ' + e.message;
                }
            }
        },
        'RC4Drop Encrypt': {
            args: [{name: 'Passphrase', type: 'string'}, {name: 'Drop', type: 'number', default: 768}],
            exec: (input, args) => {
                try {
                    const drop = parseInt(args[1]) || 768;
                    return CryptoJS.RC4Drop.encrypt(input, args[0] || '', { drop: drop }).toString();
                } catch (e) {
                    return 'RC4Drop加密错误: ' + e.message;
                }
            }
        },
        'RC4Drop Decrypt': {
            args: [{name: 'Passphrase', type: 'string'}, {name: 'Drop', type: 'number', default: 768}],
            exec: (input, args) => {
                try {
                    const drop = parseInt(args[1]) || 768;
                    return CryptoJS.RC4Drop.decrypt(input, args[0] || '', { drop: drop }).toString(CryptoJS.enc.Utf8);
                } catch (e) {
                    return 'RC4Drop解密错误: ' + e.message;
                }
            }
        },
        'XOR': {
            args: [{name: 'Key', type: 'string'}],
            exec: (input, args) => {
                try {
                    const key = args[0] || '';
                    if (!key) return '请输入XOR密钥';
                    let res = '';
                    for (let i = 0; i < input.length; i++) {
                        res += String.fromCharCode(input.charCodeAt(i) ^ key.charCodeAt(i % key.length));
                    }
                    return res;
                } catch (e) {
                    return 'XOR运算错误: ' + e.message;
                }
            }
        },
        'RSA Encrypt': {
            args: [{name: 'Public Key', type: 'text'}],
            exec: (input, args) => {
                try {
                    if (!args[0]) return '请输入RSA公钥';
                    const encrypt = new JSEncrypt();
                    encrypt.setPublicKey(args[0]);
                    const encrypted = encrypt.encrypt(input);
                    return encrypted ? encrypted : 'RSA加密失败，请检查公钥格式';
                } catch (e) {
                    return 'RSA加密错误: ' + e.message;
                }
            }
        },
        'RSA Decrypt': {
            args: [{name: 'Private Key', type: 'text'}],
            exec: (input, args) => {
                try {
                    if (!args[0]) return '请输入RSA私钥';
                    const decrypt = new JSEncrypt();
                    decrypt.setPrivateKey(args[0]);
                    const decrypted = decrypt.decrypt(input);
                    return decrypted ? decrypted : 'RSA解密失败，请检查私钥格式或密文';
                } catch (e) {
                    return 'RSA解密错误: ' + e.message;
                }
            }
        },
        'SM2 Encrypt': {
            args: [{name: 'Public Key (Hex, 04开头)', type: 'string'}, {name: 'Cipher Mode', type: 'option', options: ['C1C3C2', 'C1C2C3'], default: 'C1C3C2'}],
            exec: (input, args) => {
                try {
                    if (!window.sm2) return 'SM2库未加载';
                    if (!args[0]) return '请输入SM2公钥';

                    const cipherMode = args[1] === 'C1C3C2' ? 1 : 0;
                    return window.sm2.doEncrypt(input, args[0], cipherMode);
                } catch (e) {
                    return 'SM2加密错误: ' + e.message;
                }
            }
        },
        'SM2 Decrypt': {
            args: [{name: 'Private Key (Hex)', type: 'string'}, {name: 'Cipher Mode', type: 'option', options: ['C1C3C2', 'C1C2C3'], default: 'C1C3C2'}],
            exec: (input, args) => {
                try {
                    if (!window.sm2) return 'SM2库未加载';
                    if (!args[0]) return '请输入SM2私钥';

                    const cipherMode = args[1] === 'C1C3C2' ? 1 : 0;
                    const decrypted = window.sm2.doDecrypt(input, args[0], cipherMode);
                    if (decrypted) return decrypted;
                    return 'SM2解密失败';
                } catch (e) {
                    return 'SM2解密错误: ' + e.message;
                }
            }
        },
        'SM4 Encrypt': {
            args: [{name: 'Key (32位Hex字符串)', type: 'string'}],
            exec: (input, args) => {
                try {
                    if (!window.sm4) return 'SM4库未加载';
                    if (!args[0]) return '请输入SM4密钥(32位Hex字符串)';
                    if (args[0].length !== 32) return 'SM4密钥必须是32位Hex字符串(16字节)';
                    return window.sm4.encrypt(input, args[0]);
                } catch (e) {
                    return 'SM4加密错误: ' + e.message;
                }
            }
        },
        'SM4 Decrypt': {
            args: [{name: 'Key (32位Hex字符串)', type: 'string'}],
            exec: (input, args) => {
                try {
                    if (!window.sm4) return 'SM4库未加载';
                    if (!args[0]) return '请输入SM4密钥(32位Hex字符串)';
                    if (args[0].length !== 32) return 'SM4密钥必须是32位Hex字符串(16字节)';
                    return window.sm4.decrypt(input, args[0]);
                } catch (e) {
                    return 'SM4解密错误: ' + e.message;
                }
            }
        },

        // --- Formatting ---
        'JSON Beautify': {
            args: [{name: 'Indent', type: 'number', default: 4}],
            exec: (input, args) => {
                try {
                    return JSON.stringify(JSON.parse(input), null, parseInt(args[0]) || 4);
                } catch (e) {
                    return 'JSON格式化错误: ' + e.message;
                }
            }
        },
        'JSON Minify': {
            exec: (input) => {
                try {
                    return JSON.stringify(JSON.parse(input));
                } catch (e) {
                    return 'JSON压缩错误: ' + e.message;
                }
            }
        },
        'Remove Whitespace': {
            exec: (input) => input.replace(/\s+/g, '')
        },
        'Reverse String': {
            exec: (input) => input.split('').reverse().join('')
        },
        'To Upper Case': {
            exec: (input) => input.toUpperCase()
        },
        'To Lower Case': {
            exec: (input) => input.toLowerCase()
        },
        'Unix Timestamp to Date': {
            exec: (input) => {
                try {
                    const timestamp = parseInt(input);
                    if (isNaN(timestamp)) return '请输入有效的Unix时间戳';
                    // 判断是秒还是毫秒
                    const ms = timestamp > 9999999999 ? timestamp : timestamp * 1000;
                    return new Date(ms).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
                } catch (e) {
                    return '时间戳转换错误: ' + e.message;
                }
            }
        },
        'Date to Unix Timestamp': {
            exec: (input) => {
                try {
                    const date = new Date(input);
                    if (isNaN(date.getTime())) return '请输入有效的日期格式';
                    return Math.floor(date.getTime() / 1000);
                } catch (e) {
                    return '日期转换错误: ' + e.message;
                }
            }
        }
    };

    // --- State ---
    let recipe = []; // Array of { opName: string, args: [] }

    // --- DOM Elements ---
    const opsListEl = document.getElementById('opsList');
    const recipeListEl = document.getElementById('recipeList');
    const inputTextEl = document.getElementById('inputText');
    const outputTextEl = document.getElementById('outputText');
    const autoBakeEl = document.getElementById('autoBake');
    const bakeBtn = document.getElementById('bakeBtn');
    const outputInfoEl = document.getElementById('outputInfo');
    const detectResultsEl = document.getElementById('detectResults');
    const detectSummaryEl = document.getElementById('detectSummary');
    const hashFileInputEl = document.getElementById('hashFileInput');
    const hashFileStatusEl = document.getElementById('hashFileStatus');
    const hashFileResultsEl = document.getElementById('hashFileResults');

    // --- Initialization ---
    renderOpsList();
    
    // --- Event Listeners ---
    document.getElementById('opSearch').addEventListener('input', (e) => filterOps(e.target.value));
    
    bakeBtn.addEventListener('click', bake);
    
    inputTextEl.addEventListener('input', () => {
        renderDetections();
        if (autoBakeEl.checked) bake();
    });

    hashFileInputEl.addEventListener('change', () => {
        if (hashFileInputEl.files && hashFileInputEl.files[0]) hashLocalFile(hashFileInputEl.files[0]);
    });
    
    document.getElementById('clearInputBtn').addEventListener('click', () => {
        inputTextEl.value = '';
        renderDetections();
        if (autoBakeEl.checked) bake();
    });
    
    document.getElementById('clearRecipeBtn').addEventListener('click', () => {
        recipe = [];
        renderRecipe();
        if (autoBakeEl.checked) bake();
    });
    
    document.getElementById('copyOutputBtn').addEventListener('click', () => {
        outputTextEl.select();
        document.execCommand('copy'); // Fallback
        navigator.clipboard.writeText(outputTextEl.value);
        showCopyToast('结果已复制');
    });

    function showCopyToast(msg) {
        let t = document.getElementById('ccToast');
        if (!t) {
            t = document.createElement('div');
            t.id = 'ccToast';
            t.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:1000;display:none;padding:10px 15px;border-radius:6px;border-left:4px solid #009e76;background:rgba(0,158,118,0.15);color:#009e76;font-size:0.9rem;';
            document.body.appendChild(t);
        }
        t.textContent = msg;
        t.style.display = 'block';
        clearTimeout(showCopyToast._timer);
        showCopyToast._timer = setTimeout(() => { t.style.display = 'none'; }, 2000);
    }

    // --- Functions ---

    function escapeHtml(value) {
        return String(value).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
    }

    function renderDetections() {
        const helpers = window.CyberChefHelpers;
        const findings = helpers ? helpers.detectInput(inputTextEl.value) : [];
        detectSummaryEl.textContent = findings.length ? `${findings.length} 项特征` : (inputTextEl.value.trim() ? '未识别常见格式' : '等待输入');
        if (!findings.length) {
            detectResultsEl.innerHTML = `<span class="small text-muted">${inputTextEl.value.trim() ? '未发现明确格式，可继续手动选择操作' : '输入内容后自动识别编码、哈希、JWT、JSON、PEM 和时间戳'}</span>`;
            return;
        }
        detectResultsEl.innerHTML = findings.map(item => {
            const title = escapeHtml(item.detail || item.label);
            if (item.operation) {
                return `<button type="button" class="detect-chip" data-operation="${escapeHtml(item.operation)}" title="${title}">${escapeHtml(item.label)} · 添加 ${escapeHtml(item.operation)}</button>`;
            }
            return `<span class="detect-chip d-inline-block" title="${title}">${escapeHtml(item.label)}</span>`;
        }).join('');
        detectResultsEl.querySelectorAll('[data-operation]').forEach(button => {
            button.addEventListener('click', () => window.addOp(button.dataset.operation));
        });
    }

    async function hashLocalFile(file) {
        const helpers = window.CyberChefHelpers;
        if (!helpers || !window.CryptoJS) {
            hashFileStatusEl.textContent = '本地哈希组件未加载';
            return;
        }
        const algorithms = {
            MD5: CryptoJS.algo.MD5.create(),
            SHA1: CryptoJS.algo.SHA1.create(),
            SHA256: CryptoJS.algo.SHA256.create(),
            SHA512: CryptoJS.algo.SHA512.create()
        };
        const chunkSize = 4 * 1024 * 1024;
        let offset = 0;
        hashFileResultsEl.classList.add('d-none');
        hashFileStatusEl.textContent = `正在计算 ${file.name}（0%）`;
        try {
            while (offset < file.size) {
                const buffer = await file.slice(offset, offset + chunkSize).arrayBuffer();
                const wordArray = helpers.arrayBufferToWordArray(buffer);
                Object.values(algorithms).forEach(hasher => hasher.update(wordArray));
                offset += buffer.byteLength;
                const percent = file.size ? Math.min(100, Math.round(offset / file.size * 100)) : 100;
                hashFileStatusEl.textContent = `正在计算 ${file.name}（${percent}%）`;
                await new Promise(resolve => setTimeout(resolve, 0));
            }
            const rows = Object.entries(algorithms).map(([name, hasher]) => `<strong>${name}</strong><span>${hasher.finalize().toString()}</span>`);
            hashFileResultsEl.innerHTML = rows.join('');
            hashFileResultsEl.classList.remove('d-none');
            hashFileStatusEl.textContent = `${file.name} · ${file.size.toLocaleString()} 字节 · 已在浏览器本地完成`;
        } catch (error) {
            hashFileStatusEl.textContent = `计算失败：${error.message}`;
        }
    }

    function renderOpsList() {
        let html = '';
        for (const [cat, ops] of Object.entries(Categories)) {
            html += `
                <div class="op-category" onclick="toggleCategory(this)">
                    <span>${cat}</span>
                    <i class="bi bi-chevron-down small"></i>
                </div>
                <div class="op-group">
                    ${ops.map(op => `<div class="op-item" onclick="addOp('${op}')">${op}</div>`).join('')}
                </div>
            `;
        }
        opsListEl.innerHTML = html;
    }
    
    window.toggleCategory = function(el) {
        const group = el.nextElementSibling;
        const icon = el.querySelector('i');
        if (group.style.display === 'none') {
            group.style.display = 'block';
            icon.classList.remove('bi-chevron-right');
            icon.classList.add('bi-chevron-down');
        } else {
            group.style.display = 'none';
            icon.classList.remove('bi-chevron-down');
            icon.classList.add('bi-chevron-right');
        }
    };
    
    window.addOp = function(opName) {
        const opDef = Operations[opName];
        if (!opDef) return;
        
        // Init args with defaults
        const args = (opDef.args || []).map(arg => arg.default !== undefined ? arg.default : '');
        
        recipe.push({ name: opName, args: args, id: Date.now() + Math.random() });
        renderRecipe();
        if (autoBakeEl.checked) bake();
    };
    
    window.removeOp = function(id) {
        recipe = recipe.filter(r => r.id !== id);
        renderRecipe();
        if (autoBakeEl.checked) bake();
    };
    
    window.moveOp = function(id, direction) {
        const idx = recipe.findIndex(r => r.id === id);
        if (idx === -1) return;
        
        if (direction === -1 && idx > 0) {
            [recipe[idx], recipe[idx-1]] = [recipe[idx-1], recipe[idx]];
        } else if (direction === 1 && idx < recipe.length - 1) {
            [recipe[idx], recipe[idx+1]] = [recipe[idx+1], recipe[idx]];
        }
        renderRecipe();
        if (autoBakeEl.checked) bake();
    };
    
    window.updateOpArg = function(id, argIdx, value) {
        const item = recipe.find(r => r.id === id);
        if (item) {
            item.args[argIdx] = value;
            if (autoBakeEl.checked) bake();
        }
    };

    function renderRecipe() {
        if (recipe.length === 0) {
            recipeListEl.innerHTML = '<div class="text-center text-muted mt-5 small">点击左侧操作添加到此处</div>';
            return;
        }
        
        let html = '';
        recipe.forEach((item, idx) => {
            const opDef = Operations[item.name];
            
            // Build Args Inputs
            let argsHtml = '';
            if (opDef.args) {
                argsHtml = '<div class="recipe-item-body">';
                opDef.args.forEach((arg, argIdx) => {
                    argsHtml += `<div class="param-row">
                        <label class="param-label">${arg.name}</label>`;
                        
                    if (arg.type === 'option') {
                        argsHtml += `<select class="param-input form-select form-select-sm" onchange="updateOpArg(${item.id}, ${argIdx}, this.value)">`;
                        arg.options.forEach(opt => {
                            const selected = item.args[argIdx] == opt ? 'selected' : '';
                            argsHtml += `<option value="${opt}" ${selected}>${opt}</option>`;
                        });
                        argsHtml += `</select>`;
                    } else {
                        argsHtml += `<input type="${arg.type === 'number' ? 'number' : 'text'}" 
                            class="param-input" 
                            value="${item.args[argIdx]}" 
                            oninput="updateOpArg(${item.id}, ${argIdx}, this.value)">`;
                    }
                    argsHtml += `</div>`;
                });
                argsHtml += '</div>';
            }
            
            html += `
                <div class="recipe-item">
                    <div class="recipe-item-header">
                        <span class="recipe-item-title">${item.name}</span>
                        <div class="recipe-controls">
                            <i class="bi bi-arrow-up-short" onclick="moveOp(${item.id}, -1)"></i>
                            <i class="bi bi-arrow-down-short" onclick="moveOp(${item.id}, 1)"></i>
                            <i class="bi bi-x-lg text-danger" onclick="removeOp(${item.id})"></i>
                        </div>
                    </div>
                    ${argsHtml}
                </div>
            `;
        });
        
        recipeListEl.innerHTML = html;
    }
    
    function filterOps(keyword) {
        keyword = keyword.toLowerCase();
        const items = document.querySelectorAll('.op-item');
        items.forEach(item => {
            const text = item.innerText.toLowerCase();
            if (text.includes(keyword)) {
                item.style.display = 'block';
                // Show parent category
                item.parentElement.style.display = 'block';
                item.parentElement.previousElementSibling.style.display = 'flex';
            } else {
                item.style.display = 'none';
            }
        });
        
        // Hide empty categories
        document.querySelectorAll('.op-group').forEach(group => {
            const visibleChildren = group.querySelectorAll('.op-item[style="display: block;"]').length;
            if (visibleChildren === 0 && keyword) {
                group.style.display = 'none';
                group.previousElementSibling.style.display = 'none';
            }
        });
    }

    function bake() {
        let data = inputTextEl.value;
        let error = null;
        
        try {
            for (const item of recipe) {
                const opDef = Operations[item.name];
                if (opDef) {
                    // Try/Catch per op
                    try {
                        data = opDef.exec(data, item.args);
                    } catch (e) {
                        throw new Error(`Error in ${item.name}: ${e.message}`);
                    }
                }
            }
        } catch (e) {
            error = e.message;
        }
        
        if (error) {
            outputTextEl.value = error;
            outputTextEl.classList.add('text-danger');
        } else {
            outputTextEl.value = data;
            outputTextEl.classList.remove('text-danger');
            outputInfoEl.innerText = `Length: ${data ? data.length : 0}`;
        }
    }
    
});
