# ArmadaOS 网络兼容模块

说明：本目录模块供 Steam Deck 核心经 FEX 使用；它们是 ARM64 Linux 内核模块，与 UU 路由二进制无关。

本目录提供 Linux 原版 xt_cgroup.c、xt_nat.c、对应 ARM64 内核模块、外部模块 Makefile 和 GPL-2.0-only 许可证。C 源码未修改。精确内核、架构、编译批次和摘要见 manifest.json；module_sha256 指向 xt_cgroup，nat_module_sha256 指向 xt_nat。

内核源码基线：https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.2.6.tar.xz
编译器：aarch64-linux-gnu-gcc 13.3.0（Ubuntu 24.04）。使用同批已准备内核目录及 Module.symvers 执行：

    make -C /path/to/matching/kernel M=/path/to/this/directory ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules
    aarch64-linux-gnu-strip --strip-debug xt_cgroup.ko xt_nat.ko

插件先检查实际网络能力，再尝试系统模块（modprobe）；系统确实缺少相应能力时，自动使用随包组件。根目录、oct26、oct29 保留已有精确配置的模块和摘要。没有匹配配置时，0.3 会继续检查 portable 中的模块与当前内核实际接口是否兼容，而不是仅因整份配置 SHA 不同就拒绝启动。已有候选的文件损坏不会被当作配置不匹配跳过。所有模块均使用普通 insmod 加载，不强制加载。

cgroup 依赖 x_tables；NAT 依赖 x_tables 和 nf_nat。重启后由插件启动流程再次处理；不替换内核镜像或启动项。模块加载、规则探测及兼容检查的具体错误会保留在启动失败信息中。

xt_cgroup 补齐 UU 进程流量标记，xt_nat 补齐 DNS DNAT 规则。已通过实际规则检查，用户确认手机加速成功，Steam 商店联网自测通过；其他游戏效果仍需实际验证。UU 官方核心依旧在安装时下载，没有包含在插件 ZIP 中。


## Oct26 模块

oct26 对应 Linux 7.2.6、构建时间 Mon Oct 26 11:51:41 UTC 2026、aarch64，以及 manifest.json 中的精确配置摘要。配置取自该 Armada 内核，模块不依赖具体掌机型号或网络地址。系统已提供模块时仍优先使用系统模块。

源码为 Linux 7.2.6，加 Armada eebdf06f610c132076eccaec307a68a5bf7da16c 的全部 263 个内核补丁：
https://github.com/armada-os/armada/tree/eebdf06f610c132076eccaec307a68a5bf7da16c/packages/kernel

编译器为 aarch64-linux-gnu-gcc 16.2.1 20260819 (Red Hat Cross 16.2.1-1)，链接器 2.46.1-1.fc44。xt_cgroup.c、xt_nat.c 与根目录随附源码相同。模块在与目标内核配置一致的构建树中按上述外部模块方式构建；保留目标禁用 GCC plugins 的设置。交叉编译时只对编译器名称、构建工具版本及链接/签名工具能力探测作区分，所有实际启用的内核功能保持一致。

运行时按内核 release、machine、归一化配置 SHA 匹配此组模块并校验摘要；构建时间仅为来源记录。没有匹配条目时，继续检查下述 portable 组件。

## Oct29 模块

oct29 对应 Linux 7.2.6、构建时间 #12 SMP PREEMPT Thu Oct 29 04:36:08 UTC 2026、aarch64，以及 manifest.json 中的精确配置摘要。模块在实际编译所用的已准备内核源码、配置和 Module.symvers 构建树中按上述外部模块方式构建，使用 aarch64-linux-gnu-gcc 13.3.0（Ubuntu 24.04）、链接器 2.42。xt_cgroup.c、xt_nat.c 与根目录随附源码相同，不依赖具体掌机型号或网络地址。系统已提供模块时仍优先使用系统模块。运行时按内核 release、machine、归一化配置 SHA 匹配，再校验该 profile 自己的 module_sha256 / nat_module_sha256。没有匹配条目时，继续检查下述 portable 组件。

## Portable 组件（0.3）

`portable/` 提供 ARM64 Linux 7.2.6 的 xt_cgroup、xt_nat 及各自的 ABI 描述。源码仍是本目录未修改的 Linux C 源文件，使用 aarch64-linux-gnu-gcc 13.3.0 和已准备的 7.2.6 构建树编译。

构建时从模块的 DWARF 调试信息生成独立 BTF，并通过 `tools/build_kernel_abi.py build` 记录实际使用的公开结构及按值嵌套结构。xt_cgroup 描述包含 61 个结构或枚举，xt_nat 包含 32 个。模块去除调试信息和 `.BTF` / `.BTF.base` 段，避免将构建时的内核类型编号带入另一批内核；加载前的类型检查由随包 `kernel_abi.py` 完成。模块与描述文件各自的 SHA-256 记录在 `manifest.json` 的 `portable_modules` 中。

检查依据是宿主 `/sys/kernel/btf/vmlinux` 和已加载依赖模块的 BTF。每份依赖 BTF 都以同一份 vmlinux 为基准解析。指针指向的内部实现结构不递归展开；模块实际解引用的结构必须明确列为公开根：

- xt_cgroup：`sk_buff`、`sock`、`cgroup`、`module`、`xt_action_param`、`xt_match`、`xt_mtchk_param`、`xt_mtdtor_param`、`nf_hook_state`、`percpu_ref_data`。
- xt_nat：`sk_buff`、`module`、`xt_action_param`、`xt_target`、`xt_tgchk_param`、`xt_tgdtor_param`、`nf_nat_range2`、`ip_conntrack_info`。

除了结构布局，加载前还检查架构、内核 release、文件摘要，以及 xt_cgroup 实际使用的配置分支：`CONFIG_CGROUPS=y`、`CONFIG_SOCK_CGROUP_DATA=y`、`CONFIG_CGROUP_NET_CLASSID=n`。无关配置变化不再影响资格；所需接口变化、BTF 不可读或文件损坏会明确报错。更换内核版本时应重新构建并验证组件，不能仅修改版本字符串。

原始内核 Image 的 BTF 可用 `tools/build_kernel_abi.py extract` 提取；生成描述后，用 `check` 对目标内核及其依赖 BTF 校验。`tools/kernel_vm_init.sh` 是离线 ARM64 虚拟机的加载与规则验证入口，不包含在插件 ZIP 中。
