# PYAS Security Cyanmod

<div align="center">

**[PYAS](https://github.com/87owo/PYAS) 的个人分支**：检测引擎沿用上游，重做的是交互、AI 辅助与一批可靠性问题。只要原版请直接用[上游](https://github.com/87owo/PYAS)。

[![Upstream](https://img.shields.io/badge/upstream-87owo%2FPYAS-0078D4?style=flat-square)](https://github.com/87owo/PYAS)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4?style=flat-square&logo=windows)](https://github.com/87owo/PYAS)
[![Python](https://img.shields.io/badge/language-Python-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)

</div>

## 改动点

- **AI 辅助拦截决策**：拦截弹窗接入本地模型（Ollama 或任意 OpenAI 兼容端点），AI 分析后给出「采纳建议」；未就绪或超时一律把决定交回用户，不替你放行，理由在弹窗内可见。
- **误报抑制**：一键标记误报，支持 SHA-256 内容锚定、路径范围、签名级等档位，90 天过期、命中留审计，附独立规则管理页。
- **智能体加固**：识别 aider / Claude Code / Cline / Cursor / Copilot 等编程智能体的敏感操作，提权与权限跳变审计、事件智能体标注，可整体开关。
- **交互告警重做**：证据分行展示、来源区分（驱动 / 实时 / 云）、免打扰模式、告警防洪（详见 [docs/alert-policy.md](docs/alert-policy.md)）。
- **界面重绘**：图标整套重绘、改为统一 sprite 引用，AI 模型接入引导、窗口与输入框细节修正，11 种语言同步。
- **可靠性修复**：告警弹窗崩溃导致的静默拦截、拦截日志漏记、云端熔断冷却期跳过等底层问题。

设计细节见 [docs/behavior-defense.md](docs/behavior-defense.md)、[docs/threat-evidence-and-ai.md](docs/threat-evidence-and-ai.md)。

原版 PYAS 的介绍（防护能力、架构、内核驱动、规则编辑器、机器学习引擎等）不在本页重复，直接看 **[上游 README](https://github.com/87owo/PYAS#readme)**。

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

从 [Releases](../../releases) 下载 `PYAS_Setup_v<版本>.exe`，以管理员身份运行。环境要求（Windows 10/11 x64、VC++ 运行库、WebView2 Runtime）、命令行参数与配置位置均与上游一致。

## 构建

打包分两种渠道：`python build.py local` 出**开发者模式**包（「检查更新」附带比对上游最新发布，发现上游更新即在弹窗提示跟进）；`python build.py release` 出**普通模式**包（发布用，不含该特性，GitHub Actions 显式使用）。发布护栏会阻止把开发者模式包发布出去；工具链自检 `python build.py check`。

## 已知问题

- Windows 11 启用内核驱动可能被 Smart App Control / WDAC 拦截（577 / 1275 / 4551），应用会检测并给出对应指引。
- 本分支可能滞后上游；开发者模式包的「检查更新」会提示上游进展。
- AI 辅助决策默认关闭，需在设置中自行接入模型，分析请求只发往你自己配置的端点。

## 许可

改动遵循上游许可约束，分发前请自行确认上游及其第三方组件的条款。
