"""构建渠道：本地构建 = 开发者模式，发布构建 = 普通模式。

渠道由 build.py 在打包前写入生成文件 PYAS_Build.py（不进版本库）：

    CHANNEL = "dev"     # 本地构建：附带上游跟进检查等开发用能力
    CHANNEL = "normal"  # 发布构建：不含这些能力

生成文件缺失（例如直接跑 PyInstaller、或在开发机上以源码运行）时按
普通模式处理，也就是发布包的默认行为——不会因为漏了构建步骤而把开发
能力带进发布包。
"""

try:
    from PYAS_Build import CHANNEL as _CHANNEL
except Exception:  # 生成文件缺失或损坏，一律降级为普通模式
    _CHANNEL = "normal"

CHANNEL = _CHANNEL if _CHANNEL in ("dev", "normal") else "normal"
IS_DEV = CHANNEL == "dev"
# 渠道中文名，供界面/日志显示
LABEL = {"dev": "开发者模式", "normal": "普通模式"}[CHANNEL]
