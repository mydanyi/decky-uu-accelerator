# UU加速器（Decky 插件）

UU加速器是为 ArmadaOS 设计的第三方 Decky 插件，负责下载、校验网易 UU 官方安装包，以及管理独立的加速服务。

preview.7 仅保留“Steam Deck 核心（FEX 使用）”：在 ARM64 掌机上通过系统已有 FEX 运行官方 x86_64 核心。ARM 路由器核心和 x86 直接运行方式已移除。

## 使用

1. 确认系统已提供可用的 FEXInterpreter，再通过 Decky 开发者设置安装插件 ZIP。插件不负责安装 FEX。
2. 点击“安装核心”或“安装 / 更新核心”。首次安装会启动核心；升级前若已停止，升级后保持停止，可再点击“启动服务”。
3. 手机与掌机位于同一局域网，使用“UU主机加速器”App 扫描“手机绑定”二维码，再选择游戏和节点。

二维码支持放大、刷新；刷新仅重新读取，不重置身份。普通卸载、换装 FEX 核心均保留绑定 UUID，只有重置绑定才更换身份。默认关闭开机启动。

旧版插件安装的其他核心不再支持启动、重置绑定或开启自启动，仍可停止、卸载、关闭自启动，并换装 FEX 核心。换装失败会恢复旧安装数据，保持旧核心停止并关闭自启动。检测到插件之外的旧官方安装时，会提示先处理冲突。

## 兼容性

- 复用系统已有 FEX，不修改全局 rootfs；使用插件自有数据目录。
- 原生 Python 监督程序和独立 systemd 服务负责进程管理。服务运行状态不等于实际加速效果。
- 官方包下载后核对 MD5，并检查可执行文件 ELF 架构；HTTPS 验证系统 CA。
- 系统模块优先。确需随包兼容模块时，按清单精确匹配内核 release/version/machine/config 四字段，并校验模块 SHA-256；未知构建报错，不强制加载。
- 随包 xt_cgroup、xt_nat 是支持 FEX 网络规则的 ARM64 Linux 内核模块，与已移除的 UU 路由器核心无关。插件按实际内核自动选择模块，适用于使用受支持内核的 ARM64 掌机，不绑定机型或 IP。保留原有 10 月 11 日、10 月 16 日内核支持，并新增 10 月 26 日与 10 月 29 日（#12 SMP PREEMPT Thu Oct 29 04:36:08 UTC 2026）构建的独立模块；每组分别校验内核配置与模块摘要。

## 构建

使用 npm ci、npm run typecheck、npm run build 构建前端。运行 python3 tools/package_plugin.py --output output 打包，再用 python3 tools/verify_package.py <zip> 校验。tools/verify_official_payloads.py --output <dir> 只下载并静态检查 Steam Deck 官方包，不执行核心。

## 许可

本插件与网易 UU 无隶属关系。官方 UU 核心不包含在插件 ZIP 中，安装时从官方渠道下载，适用供应商许可；本项目没有对应核心源码，无法据此重新编译为 ARM64。

原创管理和前端代码适用根目录 MIT LICENSE。compat 目录的 Linux 网络模块适用随附 GPL-2.0-only，附源码、Makefile、许可证与精确匹配清单。这些源码是插件和 Linux 模块的源码，不是 UU 核心源码；三组共六个兼容模块是插件包中仅有的 ELF。
