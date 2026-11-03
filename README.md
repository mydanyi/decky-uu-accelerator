<h1 align="center">UU加速器</h1>

<p align="center"><strong>简体中文</strong> · <a href="README.en.md">English</a></p>

<p align="center"><strong>在 ArmadaOS 上安装、绑定和管理 UU 加速服务</strong></p>

<p align="center">
  面向 ARM64 掌机和平板的 Decky 插件。<br>
  在游戏模式中安装官方核心，手机扫码绑定后即可选择游戏或 Steam 商店加速。
</p>

<p align="center">
  <a href="https://github.com/mydanyi/decky-uu-accelerator/releases/latest"><img alt="最新版本" src="https://img.shields.io/github/v/release/mydanyi/decky-uu-accelerator?style=flat&amp;color=285580"></a>
  <a href="https://armadaos.dev/"><img alt="适用于 ArmadaOS" src="https://img.shields.io/badge/ArmadaOS-ARM64-18181a?style=flat"></a>
  <a href="#相关项目与许可"><img alt="插件代码采用 MIT 许可证" src="https://img.shields.io/badge/plugin_code-MIT-18181a?style=flat"></a>
</p>

<p align="center">
  <a href="https://github.com/mydanyi/decky-uu-accelerator/releases/latest"><strong>下载安装包</strong></a>
  · <a href="#安装与首次使用">安装与首次使用</a>
  · <a href="#常见问题">常见问题</a>
  · <a href="https://github.com/mydanyi/decky-uu-accelerator/issues">反馈问题</a>
</p>

## 关于插件

UU加速器将核心安装、手机绑定和服务管理整合到 ArmadaOS 的 Decky 面板中。插件通过系统已有的 **FEX** 运行网易 UU 官方 **Steam Deck 核心**，并按系统实际网络能力处理运行所需的配置。

掌机负责运行加速服务；登录账号、选择游戏或 Steam 商店、选择节点和开始加速在手机 **UU主机加速器** App 中完成。

- **核心管理**：下载并校验官方核心，检查更新、安装、启动、停止和卸载。
- **手机绑定**：显示、放大和刷新二维码；绑定后可收起二维码与相关选项，并记住显示偏好。
- **状态查看**：分别显示加速状态、服务状态、插件版本和核心版本；运行中与加速中使用绿色显示。
- **开机启动**：按需开启，让加速服务随系统启动。

## 使用要求

- 运行 ArmadaOS 或 ArmadaOS Freedom 的 **ARM64 设备**，已配置可用的 Decky Loader 和 FEX。
- 插件启动时自动检查网络功能；系统缺少的 cgroup 与 DNS 转发组件由插件随包提供并在兼容检查通过后加载。
- 手机安装 **UU主机加速器** App，绑定时与掌机连接同一局域网。

当前仅支持 **Steam Deck 核心（FEX 使用）**。FEX 由系统提供，插件不负责安装 FEX。游戏、节点和账号权益以手机 UU App 提供的内容为准。

## 安装与首次使用

### 1. 安装插件

1. 前往 [最新发布页](https://github.com/mydanyi/decky-uu-accelerator/releases/latest)，下载附件中的 `uu-accelerator-v*.zip` 插件安装包，保留 ZIP 格式。
2. 在掌机打开 **Decky 设置**，启用开发者模式，进入开发者页面的 **从 ZIP 文件安装插件 / Install Plugin from ZIP File**，选择下载的安装包。
3. 安装完成后，在 Decky 插件列表打开 **UU加速器**。

发布页的 **Source code** 是源码压缩包，不能作为插件安装包使用。

### 2. 安装核心并绑定手机

1. 在插件中点击 **安装核心**，等待下载、校验和安装完成。首次安装会自动启动服务。
2. 等待 **手机绑定** 区域显示二维码；如果服务已停止，先点击 **启动服务**。
3. 打开手机 **UU主机加速器** App，使用扫码绑定入口扫描二维码，按手机提示完成绑定。
4. 在手机中选择需要加速的游戏或 **Steam 商店**，选择节点并开始加速。掌机插件会随网络状态更新显示 **加速中**。
5. 绑定完成后，可点击 **隐藏绑定选项** 收起二维码、刷新和重置绑定入口。需要时点击 **显示绑定选项** 即可恢复。

## 日常使用

- **开始或停止加速**：在手机 UU App 中操作。掌机上的“启动服务”用于启动核心，具体加速目标仍在手机上选择。
- **开机启动**：默认关闭，可在插件中开启。它控制核心服务随系统启动，重启后的具体加速状态请查看手机 App 和插件状态。
- **更新核心**：点击“检查更新”，再按需点击“安装 / 更新核心”。更新前已停止的服务在更新后仍保持停止。
- **更新插件**：从 Releases 下载新版插件 ZIP，通过 Decky 安装。插件更新与官方核心更新相互独立。
- **卸载核心**：停止服务并移除本插件下载的核心，保留手机绑定身份；需要更换绑定身份时再使用“重置绑定”。

## 状态说明

| 界面显示 | 含义 |
|---|---|
| 加速中 | 已检测到核心持有的加速隧道及所需网络规则。 |
| 待加速 | 服务和核心正在运行，尚未检测到完整的加速通道。 |
| 未运行 | 服务或核心未运行，可先点击“启动服务”。 |
| 状态未知 | 暂时无法读取足够的网络状态，无法确认是否正在加速。 |
| 服务 / 核心进程：运行中 | 本机服务或核心进程已启动。 |
| 后台操作：空闲 | 当前没有安装、更新等管理任务；正在加速时也可以显示“空闲”。 |
| 插件版本 / 核心版本 | 分别是本插件的版本和网易官方核心的版本。 |

“加速中”反映本机加速通道的状态，具体连接质量和延迟仍以手机 App 与实际游戏体验为准。

## 常见问题

### 绑定后还要一直显示二维码吗？

不需要。点击 **隐藏绑定选项** 即可收起，插件会记住该选择。隐藏或刷新二维码不会重置绑定，也不会影响正在运行的服务；只有 **重置绑定** 才会生成新的设备身份，并需要重新扫码。

### 不同设备和内核能否使用？

插件按 ArmadaOS 的系统接口适配，不按机型设置白名单。优先使用系统已有的网络功能；缺少时自动加载随包的 `xt_cgroup`、`xt_nat` 组件，重启后再次启动服务也会自动处理，无需用户手动安装。

0.3 新增实际接口检查：即使整份内核配置与已有记录不同，只要所需接口兼容，也可以使用随包组件。当前组件面向 ArmadaOS 的 ARM64 Linux 7.2.6；若后续系统升级改变了这些接口，需要更新插件组件。启动失败时会保留具体的规则检查、模块加载和兼容检查错误，便于定位。

### 安装或启动失败时如何反馈？

先记录插件与手机 App 的具体错误，再到 [Issues](https://github.com/mydanyi/decky-uu-accelerator/issues) 提交设备型号、系统与内核版本、插件与核心版本，以及失败的操作步骤。截图和日志请遮挡账号信息、绑定二维码及其他个人信息。

## 开发

前端位于 [`src/`](src/)，核心安装与服务管理位于 [`py_modules/uu_accelerator/`](py_modules/uu_accelerator/)，网络兼容模块的来源与构建说明见 [`compat/armada-7.2.6/`](compat/armada-7.2.6/README.md)。

<details>
<summary>构建与打包命令</summary>

在具备 Node.js / npm 和 Python 3 的构建环境中执行：

```sh
npm ci
npm run typecheck
npm run build
python3 tools/package_plugin.py --output output
python3 tools/verify_package.py output/uu-accelerator-v*.zip
```

`tools/verify_official_payloads.py --output <dir>` 可下载并静态检查官方 Steam Deck 安装包，不运行官方核心。

</details>

## 相关项目与许可

- [ArmadaOS](https://github.com/armada-os/armada) · [ArmadaOS Freedom](https://github.com/mydanyi/armadaos-freedom)：系统与设备适配。
- [Decky Loader](https://github.com/SteamDeckHomebrew/decky-loader)：游戏模式中的插件框架。
- [FEX](https://github.com/FEX-Emu/FEX)：在 ARM64 上运行官方 x86_64 核心。

本项目是第三方插件，与网易 UU 无隶属关系。原创插件代码采用 [MIT 许可证](LICENSE)；随包 Linux 网络模块及其源码采用 [GPL-2.0-only](compat/armada-7.2.6/GPL-2.0.txt)。

网易 UU 官方核心为闭源软件，在安装时从官方渠道下载，适用其自身许可和服务条款。仓库与插件安装包均不包含官方核心。
