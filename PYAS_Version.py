# 版本号格式:PYAS 上游版本号 + Cyanmod 修订号，显示为 3.7.1-1。
# 连字符前与上游 87owo/PYAS 版本保持一致，连字符后为本项目的修订序号：
# 跟进上游新版本时连字符前随之升级(3.7.0-24 -> 3.7.1-1)，同一上游基础上的
# 每轮 Cyanmod 修改递增连字符后的数字(3.7.1-1 -> 3.7.1-2)。
VERSION = "3.7.1-15"
# 数值形态（- 替换为 .）：Inno Setup / PE 版本资源只接受纯数字段
NUMERIC_VERSION = VERSION.replace("-", ".")
FILE_VERSION = NUMERIC_VERSION
# 上游项目：版本号跟随它，开发者模式的「检查更新」会比对它的最新发布
UPSTREAM_REPO = "87owo/PYAS"
# 本项目当前跟进的上游版本：上游更新日志只展示到该版本为止
UPSTREAM_TRACKED = "3.7.1"


def create_version_file(output_file="versionfile.txt"):
    import pyinstaller_versionfile

    pyinstaller_versionfile.create_versionfile(
        output_file=output_file,
        version=FILE_VERSION,
        company_name="PYAS Security Cyanmod",
        file_description="PYAS Security Cyanmod Antivirus",
        internal_name="PYAS",
        legal_copyright="PYAS Security",
        original_filename="PYAS.exe",
        product_name="PYAS Security Cyanmod",
    )


if __name__ == "__main__":
    create_version_file()
