# 工作移交 —— 告警窗口 UI 两项问题（PYAS_Cyanmod）

> 移交日期：2026-10-15　|　调查已完成、**未做任何代码改动**，本文档含根因证据与修复方向。
> 接手人读完本文档即可直接动手，无需重新排查。

---

## 0. 项目速览

| 项 | 内容 |
|---|---|
| 路径 | `E:\Project Files\PYAS_Cyanmod` |
| 技术栈 | Python + **pywebview**（WebView2 渲染 HTML/CSS/JS），主程序 `PYAS.py` |
| 告警窗口逻辑 | `PYAS_Dialog.py`（107KB，窗口创建/本地化/决策提交） |
| 告警窗口前端 | `Interface/templates/`（HTML）+ `Interface/static/css/threat.css`（告警样式）+ `Interface/static/js/threat.js`（前端状态机） |
| AI 相关 | `PYAS_AI.py` / `PYAS_Decisions.py`（AI 分析状态机，供前端 `ai.state` 查询） |
| 构建 | `PYAS_Build.py` / `PYAS.spec`；产物 `dist/PYAS.exe`；MSIX 包在 `Output/` |

## 1. 问题一：内容密度太小，AI辅助决策/事件详情/文件身份要滚动才能看到

### 根因（已定位）
- 窗口尺寸定义在 `PYAS_Dialog.py:1151-1153`：**`width=720, height=520, min_size=(560, 420)`**；
- 告警页各区块（检测证据 grid → AI辅助决策 → 事件详情 → 文件身份 → 底部操作区）为**单列纵向堆叠**，520px 高度装不下，必然出现滚动。

### 修复方向（任选或组合，按工作量从小到大）
1. **调窗口高度**：`height=520 → 680~720`（主要屏幕 1080p 下无压力），同步调 `min_size`；
2. **压缩纵向空间**：threat.css 中区块 padding/标题行高/证据 grid 行距收紧一档；
3. **证据区改双列**：`.detection-grid` 已是 grid，把"事件详情/文件身份"类短字段并入同网格（两列）；
4. **AI辅助决策改为可折叠面板（accordion）或 Tab**：与"检测证据"并列切换，默认展开 AI 决策；
5. 布局已有一档响应式（`threat.css` 底部 `@media (max-width: 620px)`），可参照再加一档"高度不足"压缩档。

### 验证清单
- [ ] 720×520 与 560×420 两个尺寸下，AI辅助决策与操作按钮同屏可见；
- [ ] 进程防护告警（无文件身份区块，见 `PYAS_Dialog.py:925` 的说明）布局不错位；
- [ ] 误报表单入口仍可用。

## 2. 问题二：AI分析边框流光是静态的——窗口不支持动画吗？

**结论先行：窗口（WebView2）完全支持 CSS 动画**（项目里另有两处 keyframes 动画正常）。流光静态是下面两个原因之一，均有明确代码证据：

### 机制（证据）
`Interface/static/css/threat.css:221-236`：
```css
.ai-window-glow::before {
    background: conic-gradient(#ff3b30, …, #ff3b30);   /* 彩虹光谱 */
    animation: ai-window-spectrum 6s linear infinite;
    animation-play-state: paused;                      /* ← 默认暂停！ */
}
.ai-window-glow.is-analyzing::before { animation-play-state: running; }  /* 仅 AI 分析中流转 */
@media (prefers-reduced-motion: reduce) {
    .ai-window-glow::before { animation: none; }       /* ← 系统关动画则完全静止 */
}
```
`Interface/static/js/threat.js:26`：
```js
glow.classList.toggle('is-analyzing',
    visible && ai.state === 'analyzing' && !busy && !resolving);
```

### 两个候选根因（按概率排序）
1. **系统"动画效果"被关闭**：Windows 设置 → 辅助功能 → 视觉效果 → 动画效果 关闭时，WebView2 上报
   `prefers-reduced-motion: reduce`，命中 `threat.css:234` → `animation: none`，流光彻底静止。
   政务/办公机器常关闭动画，**最可能就是这个**。
2. **`.is-analyzing` 未激活**：该类只在 `ai.state === 'analyzing'` 且非 busy/resolving 时挂上
   （`threat.js:26`）。AI 分析结束或未开始时流光**设计上就是暂停的**——若截图时 AI 已分析完毕，
   静态属正常行为。

### 排查步骤（5 分钟）
1. 系统开启动画效果后重开告警窗，触发一次 AI 分析：流转 → 根因 1 确认；
2. 或 WebView2 DevTools（右键→检查）选中 `.ai-window-glow::before`，看 computed 的
   `animation-play-state` 与 `animation` 是否被 reduced-motion 媒体查询清掉。

### 修复方向（按需选择）
- 若根因 1 且希望忽略系统设置：删除 `@media (prefers-reduced-motion:…)` 中针对
  `.ai-window-glow::before` 的 `animation: none`（保留其余过渡的克制即可）——注意这对晕动症用户不友好，可改为提供设置开关；
- 若希望"非分析中也有反馈"：把默认 `animation-play-state: paused` 改为低速常转（如 24s），
  `is-analyzing` 时提速到 6s；
- 若静态属预期：仅做视觉上的区分（如分析中加"AI分析中…"呼吸点，已有 `aiGuidePulse` 动画可复用，
  `style.css:2042`）。

## 3. 相关文件索引

| 文件 | 作用 |
|---|---|
| `PYAS_Dialog.py:1151` | 告警窗口创建（尺寸/最小尺寸） |
| `PYAS_Dialog.py:925` | "文件身份"区块的显隐逻辑（内存告警无文件身份） |
| `Interface/static/css/threat.css:212-236` | 流光效果全部样式（含媒体查询） |
| `Interface/static/js/threat.js:15,26` | `is-analyzing` 类的挂载/摘除 |
| `Interface/static/css/style.css:2042` | 可复用的呼吸点动画 `aiGuidePulse` |
| `PYAS_AI.py` / `PYAS_Decisions.py` | `ai.state` 的来源（前端判定依赖） |

## 4. 注意事项
- 改 CSS/JS 后无需重新 pip 安装，重启 `PYAS.py` 即生效；打包验证走 `PYAS_Build.py`；
- 告警窗还有第二处 `webview.create_window`（`PYAS_Dialog.py:1770`，360px 小窗），改尺寸时注意区分；
- 本文档只覆盖这两项 UI 问题；PYAS 引擎/规则/AI 决策逻辑不在本次移交范围。
