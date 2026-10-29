import { callable } from "@decky/api";

/** 核心引擎标识（仅支持 FEX）。 */
export type Engine = "fex";

/** 平台探测信息。 */
export interface PlatformInfo {
  arch?: string;
  is_armada?: boolean;
  legacy_install?: boolean;
  recommended_engine?: Engine | null;
  fex_path?: string | null;
}

/** 手机端绑定信息（由核心生成）。 */
export interface BindingInfo {
  qr_text: string;
  /** 后端生成的纯 SVG 二维码文本（可选，旧后端可能缺省）。 */
  qr_svg?: string;
  available: boolean;
}

/** get_status 返回的完整状态。 */
export interface Status {
  installed: boolean;
  running: boolean;
  core_running: boolean;
  busy: boolean;
  phase: string;
  progress: number;
  error: string | null;
  version: string | null;
  /** 持久化安装方式，旧版 native/x86 安装可能为其他字符串。 */
  engine: string | null;
  engines: Engine[];
  autostart: boolean;
  platform: PlatformInfo;
  binding: BindingInfo;
}

/** 所有变更类 RPC 的统一应答；accepted 仅表示已入队。 */
export interface JobReply {
  accepted: boolean;
  error?: string;
}

/** check_updates 返回的更新检查结果。 */
export interface UpdateInfo {
  update_available: boolean;
  version: string | null;
  md5: string;
  engine: Engine;
}

export const getStatus = callable<[], Status>("get_status");
export const checkUpdates = callable<[], UpdateInfo>("check_updates");
export const installCore = callable<[engine: Engine | "auto"], JobReply>("install_core");
export const startCore = callable<[], JobReply>("start_core");
export const stopCore = callable<[], JobReply>("stop_core");
export const setAutostart = callable<[enabled: boolean], JobReply>("set_autostart");
export const uninstallCore = callable<[reset_binding?: boolean], JobReply>("uninstall_core");
export const resetBinding = callable<[], JobReply>("reset_binding");
