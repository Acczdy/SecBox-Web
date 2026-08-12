# SecBox-Web

面向授权安全测试、CTF、应急响应与安全学习场景的 Web 工具箱。项目是第一代
[Test-tools](https://github.com/Acczdy/Test-tools) 的重新设计与持续维护版本，统一了页面布局、亮暗主题、路由与 Docker 部署方式。

> [!WARNING]
> 本项目包含反连命令、载荷参考、弱口令资料和 OOB 回调等安全测试能力。仅可用于已获得明确授权的系统、个人实验环境或合法竞赛。禁止用于未授权访问、破坏、数据窃取或规避监管。使用者应自行承担行为及部署产生的全部法律和安全责任。

![SecBox-Web 资产分拣](docs/images/asset-filter.png)

## 功能

- 载荷武库、加解密转换、JSFuck、JWT 分析
- 资产分拣、文件特征分析、HTTP 请求/响应安全分析
- Shell 反连与传输命令生成
- Windows 进程分析、提权辅助、默认密码查询、社工字典生成
- Google / 百度 / Bing 信息收集语法
- fscan、Nmap、Masscan、Nuclei、Nessus、ffuf、dirsearch 与安全日志报告解析
- RMI、LDAP、HTTP OOB 回调服务（后端密码验证、失败限流、7 天签名 Cookie）

更多界面：

| Shell 反连 | 报告解析 |
|---|---|
| ![Shell 反连](docs/images/reverse-shell.png) | ![报告解析](docs/images/parser.png) |

## Docker 启动（推荐）

环境要求：Docker Engine 24+ 和 Docker Compose v2。

```bash
git clone https://github.com/Acczdy/SecBox-Web.git
cd SecBox-Web
cp oob-ports.env.example .env
# 编辑项目根目录 .env，为三个变量分别填写自己选择的高位端口
docker compose up -d --build
docker compose logs security-tools
```

### 必须先设置 OOB 端口

本项目不提供固定的 OOB 端口。Docker 启动前，请编辑项目根目录的 `.env`：

```dotenv
OOB_RMI_PORT=<你的 RMI TCP 端口>
OOB_LDAP_PORT=<你的 LDAP TCP 端口>
OOB_HTTP_CALLBACK_PORT=<你的 HTTP 回调 TCP 端口>
```

三个值必须是 `1024-65535` 范围内互不相同的端口，也不能使用 Web 端口 `5001`。同时需要在服务器安全组或防火墙中放行这三个 TCP 端口。`.env` 已被 Git 忽略，不会上传到仓库；其中只应存放非敏感部署参数，不要写入密码。

未设置、格式错误、端口越界或端口重复时，Compose/应用会拒绝启动并给出错误，不会回退到项目原有端口。

首次启动日志会输出一次随机 OOB 访问密码：

```text
[首次启动] OOB 反连服务访问密码: <随机密码>
```

密码明文不会写入仓库、镜像、环境变量或运行时文件；运行时卷只保存 PBKDF2 哈希。请立即保存首次密码。

访问 `http://服务器地址:5001`。公网部署必须放在 HTTPS 反向代理/WAF 后，并限制允许访问的来源。

### 重置 OOB 密码

安全交互输入（推荐，不进入 Shell 历史）：

```bash
docker compose exec security-tools python manage.py reset-oob-password
```

显式指定自定义密码（至少 12 位）：

```bash
docker compose exec security-tools python manage.py reset-oob-password \
  --password 'Your-New-Strong-Password'
```

重新生成随机密码：

```bash
docker compose exec security-tools python manage.py generate-oob-password
```

重置后，已有 OOB 登录 Cookie 会立即失效。

### 可选环境参数

Compose 不需要 `.env` 密码文件。仅在网络拓扑需要时配置非敏感参数：

| 变量 | 默认值 | 说明 |
|---|---:|---|
| `OOB_HOST` | 自动探测 | RMI/LDAP 回调公网 IP 或域名 |
| `OOB_HTTP_CALLBACK_HOST` | 同 `OOB_HOST` | HTTP 直连回调主机 |
| `OOB_RMI_PORT` | 必填 | 用户自定义 RMI 回调 TCP 端口 |
| `OOB_LDAP_PORT` | 必填 | 用户自定义 LDAP 回调 TCP 端口 |
| `OOB_HTTP_CALLBACK_PORT` | 必填 | 用户自定义 HTTP 回调 TCP 端口 |
| `OOB_COOKIE_SECURE` | `1` | HTTPS 下签发 Secure Cookie |
| `TRUST_PROXY_HEADERS` | `0` | 仅在可信反代环境按需开启 |
| `OOB_SESSION_TTL_HOURS` | `24` | 用户 OOB 凭证有效期 |

主机示例：`OOB_HOST=oob.example.com docker compose up -d`。端口仍从项目根目录 `.env` 读取。

## 本地开发

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export OOB_RMI_PORT=<你的端口>
export OOB_LDAP_PORT=<你的端口>
export OOB_HTTP_CALLBACK_PORT=<你的端口>
python app.py
```

本地首次启动同样会在 `runtime/secrets.json` 创建签名密钥和密码哈希。若需要设定登录密码，运行 `python manage.py reset-oob-password`。

测试：

```bash
python -m unittest discover -s tests -q
for test_file in tests/*.js; do node "$test_file"; done
```

## 公网部署安全建议

- 使用 HTTPS 反向代理/WAF，并以防火墙限制 5001 管理页面的来源。
- 仅在确需回调时开放你在 `.env` 中设置的三个 OOB 端口；其余时间关闭。
- 保持单个 Gunicorn worker；OOB 凭证和记录当前存储于进程内存。
- 定期更新镜像和依赖，不要把 `runtime` 卷、日志或真实测试数据提交到 Git。
- 不要在互联网公开实例中移除 OOB 后端鉴权与失败限流。

更完整的披露流程见 [SECURITY.md](SECURITY.md)。

## 项目来源、版权与许可证

本项目在多个公开安全工具和网页工具基础上进行二次开发。完整来源、用途映射和已确认的许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。感谢所有原作者与社区维护者。

本仓库作者新增代码以 [MIT License](LICENSE) 发布。第三方代码、数据、图标、字体和其他素材仍遵循各自原始许可证或权利声明；MIT 许可证不覆盖无权再许可的第三方内容。若来源或署名有遗漏，请提交 Issue 更正。

## 免责声明

本软件按“原样”提供，不承诺适销性、特定用途适用性或无漏洞。作者和贡献者不对使用、误用、服务暴露、攻击流量、数据损失、业务中断或任何直接与间接损害负责。下载、部署或使用即表示你理解并同意仅在合法授权范围内操作。

## 贡献

提交代码前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。安全漏洞请不要公开提交利用细节，按 [SECURITY.md](SECURITY.md) 私下报告。
