# PYAS Security Cyanmod

<div align="center">

**[PYAS](https://github.com/87owo/PYAS) 的个人分支——同一套检测引擎，重做了交互与 AI 辅助。开发过程由 AI 深度参与；如果你只想要原版 PYAS，请直接用[上游原版](https://github.com/87owo/PYAS)。**

[![Upstream](https://img.shields.io/badge/upstream-87owo%2FPYAS-0078D4?style=flat-square)](https://github.com/87owo/PYAS)
[![Version](https://img.shields.io/badge/version-3.7.1--3-0969DA?style=flat-square)](../../releases)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4?style=flat-square&logo=windows)](https://github.com/87owo/PYAS)
[![Python](https://img.shields.io/badge/language-Python-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)

</div>

## 关于这个分支

这是 [87owo/PYAS](https://github.com/87owo/PYAS) 的个人分支，由 AI 辅助开发。**检测引擎与核心防护代码不动**，改的是交互层和 AI 辅助能力。版本号跟随上游，格式为 `上游版本-本地修订`（如 `3.7.1-3` = 上游 3.7.1 的第 3 轮改动）。

主要改动点：

- **AI 辅助拦截决策**：拦截弹窗接入本地大模型（Ollama 一键接入，或任意 OpenAI 兼容接口），AI 分析可疑文件并给出「采纳建议」第四按钮；AI 未就绪或超时把决定交回用户，绝不替你放行。AI 的判断理由在弹窗里可见。
- **误报抑制**：弹窗一键标记误报，支持按 SHA-256 内容锚定、路径范围、签名级等多档抑制规则，90 天过期、命中留审计；带独立的抑制规则管理页。
- **智能体加固**：识别 aider / Claude Code / Cline / Cursor / Copilot 等编程智能体的敏感操作，提权与权限跳变审计、拦截事件智能体标注，可整体开关。
- **交互告警重做**：检测证据分行展示、来源区分（驱动/实时/云）、免打扰模式、告警防洪（默认不超时自动拦截，详见 [docs/alert-policy.md](docs/alert-policy.md)）。
- **界面重绘**：52 枚重绘图标整套实装、AI 模型接入引导、窗口与输入框细节修正、11 种语言同步。
- **可靠性修复**：告警弹窗崩溃导致的静默拦截、拦截日志漏记、云端熔断冷却期跳过等一批底层问题修复。

行为防御与检测证据的设计细节见 [docs/behavior-defense.md](docs/behavior-defense.md)、[docs/threat-evidence-and-ai.md](docs/threat-evidence-and-ai.md)。

> 原版 PYAS 的完整介绍（防护能力、系统架构、内核驱动、规则编辑器、机器学习引擎等）直接看上游，不在本页重复：
> **[github.com/87owo/PYAS](https://github.com/87owo/PYAS)** · [上游 Releases](https://github.com/87owo/PYAS/releases) · [官网](https://pyas-security.com/antivirus)

<div align="center">

### 特别感谢 DeepSeek、GLM、GPT 三位对本项目开发的大力支持 (¬‿¬)✧

<table>
  <tr>
    <td align="center"><img src="docs/thanks/deepseek.webp" height="170" alt="DeepSeek 娘化形象（AI 生成）"><br><sub><b>DeepSeek</b></sub></td>
    <td align="center"><img src="docs/thanks/glm.webp" height="170" alt="GLM 娘化形象（AI 生成）"><br><sub><b>GLM</b></sub></td>
    <td align="center"><img src="docs/thanks/gpt.webp" height="170" alt="GPT 娘化形象（AI 生成）"><br><sub><b>GPT</b></sub></td>
  </tr>
</table>

<sub>形象为 AI 生成的同人 Q 版设定，仅用于致谢展示，不代表各官方品牌。</sub>

</div>

---

## 获取与安装

从 [本仓库 Releases](../../releases) 下载 `PYAS_Setup_v<版本>.exe`，安装要求与上游一致（Windows 10/11 x64、VC++ 运行库、WebView2 Runtime），请以管理员身份运行。

从源码运行、命令行参数、配置文件位置、驱动构建等，均与上游相同，见[上游 README](https://github.com/87owo/PYAS#readme)。

## 构建渠道

本分支的打包分两种渠道（`build.py`）：

| 命令 | 渠道 | 行为 |
|---|---|---|
| `python build.py local` | 开发者模式 | 「检查更新」会附带比对上游 [87owo/PYAS](https://github.com/87owo/PYAS) 的最新发布，发现上游更新即在更新弹窗提示跟进 |
| `python build.py release` | 普通模式 | 发布用，不含上游跟进等开发特性；GitHub Actions 构建显式使用此渠道 |

发布护栏会阻止把开发者模式的安装包发布出去。构建前置条件（PyInstaller、Inno Setup 等）与上游构建方式一致，`python build.py check` 可验证工具链。

## 版本规则

- `上游版本-本地修订`：前半段跟随上游 `87owo/PYAS` 的 release（如 `3.7.1`），后半段是本地改动轮次。
- 跟进新的上游版本时升前半段（`3.7.0-x` → `3.7.1-1`）；同一上游基础上的每轮本地改动递增修订号。
- 构建脚本强制校验该格式，并把点分数字形式（`3.7.1.3`）写入 Inno Setup 元数据。

## 已知问题与说明

- Windows 11 上启用内核驱动可能被 Smart App Control / WDAC 拦截（错误码 577 / 1275 / 4551），应用会检测并给出针对性指引，完整说明见[上游文档](https://github.com/87owo/PYAS#readme)。
- 本分支可能滞后于上游；开发者模式安装包的「检查更新」会提示上游进展。
- AI 辅助决策默认关闭，需要在设置里自行接入模型；不上传任何文件到第三方，分析请求仅发往你自己配置的模型端点。

## 许可

请自行确认上游及其第三方组件的许可条款后再分发。本分支的改动遵循上游的许可约束。
