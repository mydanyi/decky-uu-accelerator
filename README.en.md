<h1 align="center">UU加速器 · UU Accelerator</h1>

<p align="center"><a href="README.md">简体中文</a> · <strong>English</strong></p>

<p align="center"><strong>Install, pair, and manage UU acceleration on ArmadaOS</strong></p>

<p align="center">
  A Decky plugin for ARM64 handhelds and tablets.<br>
  Install the official core in Gaming Mode, pair your phone, and select a game or the Steam Store to accelerate.
</p>

<p align="center">
  <a href="https://github.com/mydanyi/decky-uu-accelerator/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/mydanyi/decky-uu-accelerator?style=flat&amp;color=285580"></a>
  <a href="https://armadaos.dev/"><img alt="For ArmadaOS" src="https://img.shields.io/badge/ArmadaOS-ARM64-18181a?style=flat"></a>
  <a href="#related-projects-and-license"><img alt="Plugin code licensed under MIT" src="https://img.shields.io/badge/plugin_code-MIT-18181a?style=flat"></a>
</p>

<p align="center">
  <a href="https://github.com/mydanyi/decky-uu-accelerator/releases/latest"><strong>Download</strong></a>
  · <a href="#installation-and-first-use">Get started</a>
  · <a href="#frequently-asked-questions">FAQ</a>
  · <a href="https://github.com/mydanyi/decky-uu-accelerator/issues">Report an issue</a>
</p>

## About

UU Accelerator brings core installation, phone pairing, and service management into the ArmadaOS Decky panel. It runs NetEase UU's official **Steam Deck core** through the system's existing **FEX** installation and configures networking according to the capabilities available on the device.

The handheld runs the acceleration service. Sign in, choose a game or the Steam Store, select a node, and start acceleration in the **UU主机加速器** mobile app.

- **Core management**: download and verify the official core, check for updates, install, start, stop, and uninstall it.
- **Phone pairing**: display, enlarge, or refresh the QR code; hide pairing controls after setup and remember the preference.
- **Status display**: separate acceleration and service states, plus plugin and core versions; active states appear in green.
- **Start on boot**: optionally start the core service with the system.

## Requirements

- An **ARM64 device** running ArmadaOS or ArmadaOS Freedom, with working Decky Loader and FEX installations.
- The plugin checks networking at startup and supplies bundled cgroup and DNS forwarding components when they are missing, loading them after compatibility checks pass.
- The **UU主机加速器** mobile app, with the phone and handheld on the same local network when pairing.

Only the **Steam Deck core through FEX** is supported. FEX is supplied by the operating system and is not installed by this plugin. Available games, nodes, and account entitlements are determined by the UU mobile app.

## Installation and first use

### 1. Install the plugin

1. Open the [latest release](https://github.com/mydanyi/decky-uu-accelerator/releases/latest) and download the `uu-accelerator-v*.zip` plugin asset. Keep it as a ZIP file.
2. On the handheld, open **Decky Settings**, enable Developer Mode, and use **Install Plugin from ZIP File** on the Developer page to select the downloaded package.
3. Open **UU加速器** in the Decky plugin list.

The **Source code** archives on the release page are not installable plugin packages. The plugin interface is currently in Chinese; the labels below match that interface.

### 2. Install the core and pair your phone

1. Select **安装核心** (Install core) and wait for download, verification, and installation to finish. The first installation starts the service automatically.
2. Wait for a QR code under **手机绑定** (Phone pairing). If the service is stopped, select **启动服务** (Start service) first.
3. Open **UU主机加速器** on your phone, scan the code using its pairing option, and follow the app's instructions.
4. Choose a game or the **Steam Store**, select a node, and start acceleration on your phone. The plugin updates to **加速中** (Accelerating) when it detects the acceleration channel.
5. Select **隐藏绑定选项** (Hide pairing options) to collapse the QR code, refresh, and reset controls. Use **显示绑定选项** (Show pairing options) to restore them later.

## Everyday use

- **Start or stop acceleration** in the mobile app. **启动服务** starts the local core; choose the acceleration target on your phone.
- **Start on boot** is off by default. Enable **开机启动** to start the core with the system. Check the mobile app and plugin for acceleration status after a reboot.
- **Update the core** with **检查更新** (Check for updates), followed by **安装 / 更新核心** (Install / update core) when needed. A service that was stopped before the update remains stopped afterward.
- **Update the plugin** by installing a newer release ZIP through Decky. Plugin updates and official core updates are separate.
- **Uninstall the core** with **卸载核心**. This stops the service and removes the downloaded core while retaining the pairing identity. Use **重置绑定** only when you want a new identity and intend to pair again.

## Understanding the status

| Display | Meaning |
|---|---|
| 加速中 — Accelerating | The core owns an acceleration tunnel and the required network rules are present. |
| 待加速 — Ready | The service and core are running, but a complete acceleration channel has not been detected. |
| 未运行 — Not running | The service or core is not running. Start the service first. |
| 状态未知 — Unknown | The plugin cannot read enough network state to confirm acceleration. |
| 服务 / 核心进程：运行中 — Service / core running | The local service or core process has started. |
| 后台操作：空闲 — Background task: idle | No management task, such as installation or an update, is in progress. Acceleration can still be active. |
| 插件版本 / 核心版本 — Plugin / core version | The version of this plugin and the version of NetEase's official core, respectively. |

“Accelerating” describes the local acceleration channel. Connection quality and latency should be assessed in the mobile app and the game itself.

## Frequently asked questions

### Does the QR code need to stay visible after pairing?

No. Use **隐藏绑定选项** to hide it; the plugin remembers your choice. Hiding or refreshing the code does not reset pairing or stop the service. Only **重置绑定** generates a new device identity and requires pairing again.

### What about different devices and kernels?

The plugin targets ArmadaOS system interfaces without a device-model allowlist. It prefers existing network capabilities and automatically loads bundled `xt_cgroup` and `xt_nat` components when needed. Starting the service after a reboot repeats this process; no manual module installation is required.

Version 0.3 adds checks against the running kernel's actual interfaces. A different overall kernel configuration no longer prevents loading if the required interfaces remain compatible. The bundled components currently target ArmadaOS ARM64 Linux 7.2.6; future system updates that change those interfaces require updated plugin components. Startup errors retain the specific rule-probe, module-loading, and compatibility-check failures for diagnosis.

### How do I report an installation or startup problem?

Record the exact errors shown by the plugin and mobile app. [Open an issue](https://github.com/mydanyi/decky-uu-accelerator/issues) with your device model, OS and kernel versions, plugin and core versions, and the steps that failed. Redact account details, pairing QR codes, and other personal information from screenshots and logs.

## Development

The frontend is in [`src/`](src/), core installation and service management are in [`py_modules/uu_accelerator/`](py_modules/uu_accelerator/), and network module sources and build notes are in [`compat/armada-7.2.6/`](compat/armada-7.2.6/README.md).

<details>
<summary>Build and package commands</summary>

Run in a build environment with Node.js / npm and Python 3:

```sh
npm ci
npm run typecheck
npm run build
python3 tools/package_plugin.py --output output
python3 tools/verify_package.py output/uu-accelerator-v*.zip
```

`tools/verify_official_payloads.py --output <dir>` downloads and statically checks the official Steam Deck package without executing its core.

</details>

## Related projects and license

- [ArmadaOS](https://github.com/armada-os/armada) · [ArmadaOS Freedom](https://github.com/mydanyi/armadaos-freedom): operating system and device support.
- [Decky Loader](https://github.com/SteamDeckHomebrew/decky-loader): the Gaming Mode plugin framework.
- [FEX](https://github.com/FEX-Emu/FEX): runs the official x86_64 core on ARM64.

This is a third-party plugin and is not affiliated with NetEase UU. Original plugin code is licensed under [MIT](LICENSE). Bundled Linux network modules and their sources are licensed under [GPL-2.0-only](compat/armada-7.2.6/GPL-2.0.txt).

The official NetEase UU core is closed-source software, downloaded from the official channel during installation and governed by its own license and service terms. It is not included in this repository or the plugin package.
