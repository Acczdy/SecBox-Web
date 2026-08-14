# SecBox-Web

### 面向授权安全测试与安全运营的一站式 Web 工具箱

把资产整理、扫描报告、请求分析、命令生成、回调验证和安全资料，放进一个清晰、可部署、可审计的工作台。

[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE) [![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg?logo=docker&logoColor=white)](Dockerfile) [![Security](https://img.shields.io/badge/use-authorized%20only-critical.svg)](SECURITY.md)

> SecBox-Web 是 [Test-tools](https://github.com/Acczdy/Test-tools) 的重新设计与持续维护版本，适用于授权渗透测试、应急响应、CTF、实验室和日常安全排查。

![SecBox-Web 资产分拣](docs/images/asset-filter.png)

## 为什么使用 SecBox-Web

- **统一入口**：常用安全小工具不再散落在脚本、网页和临时笔记里。
- **结果可交付**：报告解析不仅展示原始结果，还生成风险排行、优先处置队列和聚合分析。
- **本地优先**：资产过滤、解析、导出和大多数分析在本地完成，不依赖外部服务。
- **部署简单**：Docker 一键启动，也支持 Python 本地运行；亮色/暗色主题和分类导航适合长期使用。
- **安全可控**：OOB 服务后端鉴权、登录失败限流、签名 Cookie 和可重置密码均由服务端控制。

## 核心能力

| 工作台 | 能力 |
|---|---|
| 资产与情报 | 资产分拣、域名/IP/端口过滤、手机号与身份证号识别、Google/Bing/百度检索语法 |
| 报告解析 | fscan、Nmap、Masscan、Nuclei、Nessus、ffuf、dirsearch、安全日志、mimikatz；支持 TXT/Excel/Markdown/PDF 导出 |
| 快速分析 | 文件特征、HTTP 请求/响应、Windows 进程、提权辅助、加解密转换、JWT 分析 |
| 命令与载荷 | Shell 反连、文件传输、FRP 配置、社工字典、载荷武库、默认密码和 Windows 提权 EXP 索引 |
| 回调验证 | RMI、LDAP、HTTP OOB 回调，支持自定义端口、后端密码校验和 7 天登录 Cookie |
| 可选 AI | 邮件与扫描报告深度分析、多轮对话；仅在部署者完成配置并主动发起分析时请求模型服务 |

### 报告解析不止是“转表格”

上传报告后，SecBox-Web 会按类型生成可直接复核的结果：

- 高风险端口、敏感路径和 Critical/High 优先队列
- 资产风险排行、攻击面聚合、服务暴露统计
- 凭据风险、漏洞聚合、利用条件与修复建议
- 安全日志攻击源排行、登录失败和高风险事件分类
- Excel 概览 / 聚合分析 / 完整明细分表

| Shell 反连 | 报告解析 |
|---|---|
| ![Shell 反连](docs/images/reverse-shell.png) | ![报告解析](docs/images/parser.png) |

## 5 分钟启动

### Docker（推荐）

```bash
git clone https://github.com/Acczdy/SecBox-Web.git
cd SecBox-Web
cp .env.example .env
```

编辑 `.env`，为三个 OOB 服务填写互不相同的高位端口：

```dotenv
OOB_RMI_PORT=43101
OOB_LDAP_PORT=43102
OOB_HTTP_CALLBACK_PORT=43103
```

端口范围为 `1024-65535`，不能与 Web 端口 `5001` 重复；公网部署时还需要在安全组/防火墙放行对应端口。

```bash
docker compose up -d --build
docker compose logs security-tools
```

首次启动日志会输出随机 OOB 访问密码。请保存密码，然后访问 `http://服务器地址:5001`。

重置密码：

```bash
docker compose exec security-tools python manage.py reset-oob-password
```

### 本地 Python

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

Windows PowerShell 可使用 `$env:OOB_RMI_PORT="43101"` 等方式设置三个端口后运行 `python app.py`。

## 可选 AI 分析

AI 默认关闭。需要时，在本地 `.env` 中填写兼容 Chat Completions 协议的接口、服务端凭据和模型标识：

```dotenv
AI_API_URL=
AI_API_KEY=
AI_MODEL=
```

三项均填写后才会启用。邮件和扫描报告只发送精简的结构化分析内容；附件二进制、原始邮件和 HTML 正文不会发送。AI 会话默认保留 24 小时，输出仅作辅助研判，仍需结合原始证据复核。

## 安全部署清单

- 仅在获得明确授权的目标和环境中使用
- 公网访问放在 HTTPS 反向代理或 WAF 后，并限制管理页面来源
- OOB 三个回调端口只在需要时开放
- 不要把填写后的 `.env`、运行时目录、密码或模型凭据提交到仓库
- 定期更新 Docker、系统和 Python 依赖
- 安全问题请按 [SECURITY.md](SECURITY.md) 私下报告

## 常用命令

```bash
docker compose ps
docker compose logs -f security-tools
docker compose restart security-tools
docker compose down
```

运行状态保存在 `runtime-data` 卷中。删除该卷会重新生成签名密钥、OOB 密码和运行状态。

## 测试

```bash
python -m unittest discover -s tests -q
for test_file in tests/*.js; do node "$test_file"; done
```

## 项目来源、许可证与免责声明

本项目基于多个公开安全工具、网页工具和公开资料进行整合与二次开发，来源和许可证映射见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。新增与修改代码采用 [MIT License](LICENSE)，第三方代码、数据和素材遵循各自声明。

本软件按“原样”提供，仅限合法授权用途。使用者应自行确认授权范围并承担部署、配置和使用本项目产生的全部责任。

欢迎提交 Issue、改进文档或 Pull Request。贡献前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。
