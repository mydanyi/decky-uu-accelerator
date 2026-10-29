# ArmadaOS 网络兼容模块

说明：本目录模块供 Steam Deck 核心经 FEX 使用；它们是 ARM64 Linux 内核模块，与 UU 路由二进制无关。

本目录提供 Linux 原版 xt_cgroup.c、xt_nat.c、对应 ARM64 内核模块、外部模块 Makefile 和 GPL-2.0-only 许可证。C 源码未修改。精确内核、架构、编译批次和摘要见 manifest.json；module_sha256 指向 xt_cgroup，nat_module_sha256 指向 xt_nat。

内核源码基线：https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.2.6.tar.xz
编译器：aarch64-linux-gnu-gcc 13.3.0（Ubuntu 24.04）。使用同批已准备内核目录及 Module.symvers 执行：

    make -C /path/to/matching/kernel M=/path/to/this/directory ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules
    aarch64-linux-gnu-strip --strip-debug xt_cgroup.ko xt_nat.ko

插件先检查内核真实网络能力并优先尝试原生系统模块（modprobe）。仅在系统确实缺少相应模块时，才由原生 Python 监督程序在随包候选中核对模块接口（内核 release、machine、归一化内核配置 SHA，需与 manifest.json 中任一条目匹配）并通过逐模块 SHA-256 校验后加载；kernel_version 仅作编译来源记录，不作为加载资格条件，也不按构建日期白名单或拒绝。找不到匹配的随包模块时明确报错，不尝试加载、不 force。根目录两个 .ko 仍为 Oct11 同一批次编译产物，字节与摘要未变，Oct16 profile 继续使用这一组。oct26 子目录为独立编译的新模块，按该 profile 自己的 module_sha256 / nat_module_sha256 校验，不回退使用根目录模块。cgroup 依赖 x_tables；NAT 依赖 x_tables 和 nf_nat。重启后由插件启动流程再次处理；不替换内核镜像或启动项。

xt_cgroup 补齐 UU 进程流量标记，xt_nat 补齐 DNS DNAT 规则。已通过实际规则检查，用户确认手机加速成功，Steam 商店联网自测通过；其他游戏效果仍需实际验证。UU 官方核心依旧在安装时下载，没有包含在插件 ZIP 中。


## Oct26 模块

oct26 对应 Linux 7.2.6、构建时间 Mon Oct 26 11:51:41 UTC 2026、aarch64，以及 manifest.json 中的精确配置摘要。配置取自该 Armada 内核，模块不依赖具体掌机型号或网络地址。系统已提供模块时仍优先使用系统模块。

源码为 Linux 7.2.6，加 Armada eebdf06f610c132076eccaec307a68a5bf7da16c 的全部 263 个内核补丁：
https://github.com/armada-os/armada/tree/eebdf06f610c132076eccaec307a68a5bf7da16c/packages/kernel

编译器为 aarch64-linux-gnu-gcc 16.2.1 20260819 (Red Hat Cross 16.2.1-1)，链接器 2.46.1-1.fc44。xt_cgroup.c、xt_nat.c 与根目录随附源码相同。模块在与目标内核配置一致的构建树中按上述外部模块方式构建；保留目标禁用 GCC plugins 的设置。交叉编译时只对编译器名称、构建工具版本及链接/签名工具能力探测作区分，所有实际启用的内核功能保持一致。

运行时按模块接口（内核 release、machine、归一化配置 SHA）匹配并校验对应模块摘要；构建时间仅为来源记录。不会使用不匹配内核的兼容模块或强制加载。

## Oct29 模块

oct29 对应 Linux 7.2.6、构建时间 #12 SMP PREEMPT Thu Oct 29 04:36:08 UTC 2026、aarch64，以及 manifest.json 中的精确配置摘要。模块在实际编译所用的已准备内核源码、配置和 Module.symvers 构建树中按上述外部模块方式构建，使用 aarch64-linux-gnu-gcc 13.3.0（Ubuntu 24.04）、链接器 2.42。xt_cgroup.c、xt_nat.c 与根目录随附源码相同，不依赖具体掌机型号或网络地址。系统已提供模块时仍优先使用系统模块。运行时按模块接口（内核 release、machine、归一化配置 SHA）匹配，再校验该 profile 自己的 module_sha256 / nat_module_sha256；不回退使用根目录或其他子目录模块，无匹配模块时明确报错。
