<div align="center">
  <img src="assets/logo.svg" width="100" alt="pyguard logo"/>
  <h1>pyguard</h1>
  <p><strong>扫描你的 Python 环境，检测被投毒的包。</strong></p>

  <p>
    <a href="https://github.com/pinkbubblebubble/pyguard/actions"><img src="https://github.com/pinkbubblebubble/pyguard/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
    <img src="https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue" alt="Python 版本"/>
    <img src="https://img.shields.io/badge/license-MIT-green" alt="License"/>
  </p>

  <p>
    <a href="README.md">English</a> · <a href="README.zh.md">中文</a>
  </p>
</div>

---

2025 年 3 月 24 日，litellm 1.82.7 和 1.82.8 被悄悄投毒。恶意版本加入了一个 `.pth` 文件，在每次 Python 启动时自动执行——静默读取 API key、SSH 凭证、云服务 token，然后发送到外部服务器。

没有 CVE 被提交。pip-audit 什么都没看到。这个包来自真实的 PyPI 官方项目。

**pyguard 就是为了发现这类攻击而生的。**

---

## 检测内容

| 检测项 | 能发现什么 |
|---|---|
| **CVE 查询** | 通过 [OSV 数据库](https://osv.dev) 查询已知漏洞 |
| **已知恶意版本** | 经确认的恶意发布版本（如 litellm 1.82.7 / 1.82.8） |
| **`.pth` 启动后门** | 在 Python 启动时自动执行的代码 |
| **`sitecustomize` 注入** | site-packages 中存在 `sitecustomize.py` / `usercustomize.py` |
| **凭证窃取 + 外联组合** | 同一文件既读取凭证又发起网络请求 |
| **敏感信息访问** | 引用了环境变量、`~/.ssh`、`~/.aws`、kubeconfig、API key 名称 |

---

## 安装

```bash
pip install git+https://github.com/pinkbubblebubble/pyguard.git
```

---

## 使用

```bash
# 扫描当前整个 Python 环境
pyguard scan

# 只扫描某个包
pyguard scan litellm

# 跳过 CVE 网络查询（更快，离线可用）
pyguard scan --no-cve

# 展示每条发现的完整详情
pyguard scan --verbose
```

### 输出示例

```
Scanning: /Users/you/.venv/bin/python

[HIGH]  litellm 1.82.8
         • known malicious version (supply chain incident 2025-03-24)
           通过被入侵的 CI/CD 流水线实施供应链攻击。恶意 .pth 文件在
           Python 启动时窃取 secrets 并外传。
         • startup .pth file with executable code: litellm_init.pth
           该文件在 Python 每次启动时自动执行。

[HIGH]  requests 2.32.3
         • known vulnerability: CVE-2024-47081
           Authorization header 可能被泄露至第三方服务器
         • secret access + outbound network in requests/sessions.py
           同一文件中同时存在凭证读取和网络请求。

[MEDIUM] boto3 1.34.0
         • references sensitive paths or credential names (2 file(s))

共扫描 47 个包  2 HIGH  1 MEDIUM  44 clean
```

---

## 和现有工具的区别

大多数 Python 安全工具只查 CVE。pyguard 关注的是**发布级投毒**——一个合法包在发布层面被篡改，通常没有 CVE 被提交。

| 能力 | pip-audit | safety | bandit | semgrep | **pyguard** |
|---|:---:|:---:|:---:|:---:|:---:|
| CVE 检测 | ✅ | ✅ | ❌ | ❌ | ✅ |
| 静态代码分析 | ❌ | ❌ | ✅ | ✅ | ✅ |
| 扫描本地 site-packages | ❌ | ❌ | ❌ | ❌ | ✅ |
| `.pth` 启动后门检测 | ❌ | ❌ | ❌ | ❌ | ✅ |
| 供应链投毒检测 | ❌ | ❌ | ❌ | ❌ | ✅ |
| 将发现归因到具体包 | ❌ | ❌ | ❌ | ❌ | ✅ |
| 凭证窃取 + 外联组合检测 | ❌ | ❌ | 部分 | 部分 | ✅ |

**pip-audit / safety**：对已知 CVE 效果很好，但对没有 CVE 的投毒版本完全无效——litellm 事件发生时就没有 CVE。

**bandit / semgrep**：适合扫描你自己的代码，不是为了检查已安装的第三方包并将风险归因到具体包而设计的。

---

## 在 CI 中使用

存在 HIGH 级别发现时，`pyguard` 退出码为 `1`，可以直接用于 pipeline 拦截：

```yaml
- name: 检查是否存在投毒包
  run: pyguard scan --no-cve
```

---

## 贡献

当新的供应链事件被确认时，欢迎向 [`data/known_bad.json`](src/pyguard/data/known_bad.json) 提交 PR：

```json
{
  "package-name": {
    "versions": ["x.y.z"],
    "reason": "事件的简要说明。",
    "reference": "https://相关-issue-或-报告链接"
  }
}
```

---

## License

MIT
