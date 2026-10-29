import { useCallback, useEffect, useRef, useState, type CSSProperties } from "react";
import {
  PanelSection,
  PanelSectionRow,
  ButtonItem,
  ToggleField,
  ConfirmModal,
  showModal,
  staticClasses,
} from "@decky/ui";
import { definePlugin, toaster } from "@decky/api";
import { FaBolt } from "react-icons/fa";
import {
  getStatus,
  checkUpdates,
  installCore,
  startCore,
  stopCore,
  setAutostart,
  uninstallCore,
  resetBinding,
  type Status,
  type UpdateInfo,
} from "./api";

const PLUGIN_TITLE = "UU加速器";

/** 唯一核心的固定标签。 */
const CORE_LABEL = "Steam Deck 核心（FEX 使用）";

/** 旧版插件核心的展示标签。 */
const LEGACY_CORE_LABEL = "旧版核心（不再支持）";

/** 后端 phase 的中文展示。 */
const PHASE_TEXT: Record<string, string> = {
  detecting: "检测中",
  metadata: "获取元数据",
  downloading: "下载中",
  verifying: "校验中",
  installing: "安装中",
  starting: "启动中",
  complete: "完成",
  error: "错误",
  running: "运行中",
  idle: "空闲",
};

function phaseText(phase: string): string {
  return PHASE_TEXT[phase] || "未知";
}

function clampProgress(value: number | undefined): number {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.floor(n)));
}

function errText(e: unknown): string {
  if (typeof e === "string" && e) return e;
  if (e && typeof e === "object" && "message" in e) {
    const m = (e as { message?: unknown }).message;
    if (typeof m === "string" && m) return m;
  }
  return "未知错误";
}

const rowTextStyle = (opacity = 1) => ({ opacity, fontSize: 12, lineHeight: 1.5 });
const noteStyle = { opacity: 0.7, fontSize: 11, lineHeight: 1.5 };
const errorStyle = { color: "#ff6b6b", fontSize: 12, lineHeight: 1.5 };

const progressTrack: CSSProperties = {
  background: "#3a3f46",
  borderRadius: 4,
  height: 8,
  overflow: "hidden",
  width: "100%",
  marginTop: 4,
};
const progressFill: CSSProperties = {
  background: "#1a9fff",
  height: "100%",
  transition: "width 0.3s ease",
};

/** 将后端纯 SVG 转为内联图片地址（data URI）。 */
function svgToDataUri(svg: string): string {
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}

const qrImgStyle: CSSProperties = {
  display: "block",
  width: "100%",
  maxWidth: 260,
  height: "auto",
  marginTop: 4,
  background: "#fff",
  imageRendering: "pixelated",
  objectFit: "contain",
};

const qrLargeImgStyle: CSSProperties = {
  display: "block",
  width: "100%",
  maxWidth: 420,
  maxHeight: "60vh",
  height: "auto",
  margin: "0 auto",
  background: "#fff",
  imageRendering: "pixelated",
  objectFit: "contain",
};

function UuPanel() {
  const [status, setStatus] = useState<Status | null>(null);
  const [loading, setLoading] = useState(true);
  const [pollError, setPollError] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [updateResult, setUpdateResult] = useState<UpdateInfo | null>(null);
  const [updateBusy, setUpdateBusy] = useState(false);
  const [confirm, setConfirm] = useState<"uninstall" | "reset" | null>(null);

  const mounted = useRef(true);
  const inFlight = useRef(false);
  const busyRef = useRef(false);
  const pendingRef = useRef<{ idle: number; accepted: boolean } | null>(null);

  // 本地 pending 释放：RPC 被接受后，观察到后端 busy，或连续两次轮询仍未 busy（视为很快完成）。
  const settle = useCallback((jobBusy: boolean | null) => {
    const p = pendingRef.current;
    if (!p) return;
    if (!p.accepted) return;
    if (jobBusy === null) return;
    if (jobBusy === true) {
      pendingRef.current = null;
      setPending(null);
      busyRef.current = false;
    } else if (++p.idle >= 2) {
      pendingRef.current = null;
      setPending(null);
      busyRef.current = false;
    }
  }, []);

  // 串行轮询：慢响应期间跳过，卸载后不写状态。
  const poll = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const s = await getStatus();
      if (!mounted.current) return;
      setStatus(s);
      setPollError(null);
      setLoading(false);
      settle(s.busy);
    } catch (e) {
      if (!mounted.current) return;
      setPollError(errText(e));
      setLoading(false);
      settle(null);
    } finally {
      inFlight.current = false;
    }
  }, [settle]);

  useEffect(() => {
    mounted.current = true;
    void poll();
    const id = window.setInterval(() => {
      void poll();
    }, 2000);
    return () => {
      mounted.current = false;
      window.clearInterval(id);
    };
  }, [poll]);

  // 变更类操作：ref 闩锁防止重渲染/后端 busy 生效前的连点。
  const runJob = useCallback(
    async (label: string, fn: () => Promise<{ accepted: boolean; error?: string }>, clearUpdate = false) => {
      if (busyRef.current || updateBusy || pollError || !!status?.busy) return;
      busyRef.current = true;
      pendingRef.current = { idle: 0, accepted: false };
      setPending(label);
      if (clearUpdate) setUpdateResult(null);
      try {
        const res = await fn();
        if (!mounted.current) return;
        if (!res || !res.accepted) {
          toaster.toast({ title: PLUGIN_TITLE, body: res?.error || "请求被拒绝" });
          pendingRef.current = null;
          busyRef.current = false;
          setPending(null);
          return;
        }
        if (pendingRef.current) pendingRef.current.accepted = true;
        void poll();
      } catch (e) {
        if (!mounted.current) return;
        toaster.toast({ title: PLUGIN_TITLE, body: `请求失败：${errText(e)}` });
        pendingRef.current = null;
        busyRef.current = false;
        setPending(null);
      }
    },
    [poll, updateBusy, pollError, status?.busy],
  );

  const onCheckUpdates = useCallback(async () => {
    if (busyRef.current || updateBusy || pollError) return;
    busyRef.current = true;
    setUpdateBusy(true);
    try {
      const r = await checkUpdates();
      if (!mounted.current) return;
      setUpdateResult(r);
    } catch (e) {
      if (!mounted.current) return;
      toaster.toast({ title: PLUGIN_TITLE, body: `检查更新失败：${errText(e)}` });
    } finally {
      busyRef.current = false;
      if (mounted.current) setUpdateBusy(false);
    }
  }, [updateBusy, pollError]);

  // ---- 派生状态 ----
  const engines = status?.engines ?? [];
  const installed = !!status?.installed;
  const currentEngine = status?.engine ?? null;
  const legacyInstall = !!status?.platform?.legacy_install;
  const busy = !!status?.busy;
  const disabled = !status || pending !== null || busy || updateBusy || !!pollError;

  const canUseFex = engines.includes("fex");
  const legacyCore = installed && currentEngine !== "fex";
  const canInstall = !disabled && !legacyInstall && canUseFex;

  const primaryLabel = installed ? "安装 / 更新核心" : "安装核心";

  const pct = clampProgress(status?.progress);
  const running = !!status?.running;
  const coreRunning = !!status?.core_running;

  // 二维码：仅当后端标记 available 且返回非空 SVG 时可用。
  const qrSvg = status?.binding?.qr_svg;
  const hasQrSvg = typeof qrSvg === "string" && qrSvg.trim().length > 0;
  const qrSvgDataUri = hasQrSvg && status?.binding?.available ? svgToDataUri(qrSvg as string) : null;

  const openEnlargedQr = (src: string) => {
    showModal(
      <ConfirmModal
        strTitle="手机扫码绑定"
        strDescription={<img src={src} alt="手机绑定二维码（放大）" style={qrLargeImgStyle} />}
        strOKButtonText="关闭"
        bAlertDialog
      />,
    );
  };

  const onPrimary = () => {
    if (!canInstall) return;
    runJob(primaryLabel, () => installCore("fex"), true);
  };
  const onStart = () => runJob("启动服务", () => startCore());
  const onStop = () => runJob("停止服务", () => stopCore());
  const onToggleAutostart = (v: boolean) => runJob("设置开机启动", () => setAutostart(v));

  const onConfirmUninstall = () => {
    setConfirm(null);
    if (busyRef.current) return;
    runJob("卸载核心", () => uninstallCore(false));
  };
  const onConfirmReset = () => {
    setConfirm(null);
    if (busyRef.current) return;
    runJob("重置绑定", () => resetBinding());
  };

  // ---- 首屏 / 连接失败 ----
  if (loading && !status) {
    return (
      <PanelSection>
        <PanelSectionRow>
          <div style={noteStyle}>正在读取状态…</div>
        </PanelSectionRow>
      </PanelSection>
    );
  }

  if (!status) {
    return (
      <PanelSection>
        <PanelSectionRow>
          <div style={errorStyle}>无法连接加速服务：{pollError ?? "未知错误"}</div>
        </PanelSectionRow>
        <PanelSectionRow>
          <ButtonItem layout="below" onClick={() => void poll()}>
            重试
          </ButtonItem>
        </PanelSectionRow>
      </PanelSection>
    );
  }

  return (
    <>
      {pollError && (
        <PanelSection>
          <PanelSectionRow>
            <div style={errorStyle}>连接异常：{pollError}</div>
          </PanelSectionRow>
          <PanelSectionRow>
            <ButtonItem layout="below" onClick={() => void poll()}>
              手动刷新
            </ButtonItem>
          </PanelSectionRow>
        </PanelSection>
      )}

      <PanelSection title="状态">
        <PanelSectionRow>
          <div style={rowTextStyle()}>服务状态：{running ? "运行中" : installed ? "已停止" : "未安装"}</div>
        </PanelSectionRow>
        <PanelSectionRow>
          <div style={rowTextStyle()}>核心进程：{coreRunning ? "运行中" : "未运行"}</div>
        </PanelSectionRow>
        <PanelSectionRow>
          <div style={rowTextStyle()}>已安装版本：{status.version ?? "未知"}</div>
        </PanelSectionRow>
        <PanelSectionRow>
          <div style={rowTextStyle()}>
            当前运行方式：{!installed ? "未安装" : currentEngine === "fex" ? CORE_LABEL : LEGACY_CORE_LABEL}
          </div>
        </PanelSectionRow>
        <PanelSectionRow>
          <div style={rowTextStyle()}>
            状态：{phaseText(status.phase)}
            {busy || pending ? `（进行中 ${pct}%）` : ""}
          </div>
          {(busy || pending) && (
            <div style={progressTrack}>
              <div style={{ ...progressFill, width: `${pct}%` }} />
            </div>
          )}
        </PanelSectionRow>
        {status.error && (
          <PanelSectionRow>
            <div style={errorStyle}>错误：{status.error}</div>
          </PanelSectionRow>
        )}
      </PanelSection>

      <PanelSection title="运行方式">
        <PanelSectionRow>
          <div style={rowTextStyle()}>{CORE_LABEL}</div>
        </PanelSectionRow>
        <PanelSectionRow>
          <div style={noteStyle}>
            需系统已提供 FEX 解释器（FEXInterpreter），插件不负责安装 FEX。
          </div>
        </PanelSectionRow>
        {!canUseFex && (
          <PanelSectionRow>
            <div style={errorStyle}>当前不支持 FEX：需要 ARM64 平台且系统已提供可用的 FEXInterpreter。</div>
          </PanelSectionRow>
        )}
        {legacyCore && (
          <PanelSectionRow>
            <div style={errorStyle}>
              检测到旧版插件核心，已不再支持；安装 FEX 核心即可替换，绑定身份会保留。停止或卸载核心仍可使用。
            </div>
          </PanelSectionRow>
        )}
        {legacyInstall && (
          <PanelSectionRow>
            <div style={errorStyle}>检测到旧的官方安装方式，为避免冲突已禁用安装，请先手动清理旧安装。</div>
          </PanelSectionRow>
        )}
      </PanelSection>

      <PanelSection title="操作">
        <PanelSectionRow>
          <ButtonItem layout="below" onClick={onPrimary} disabled={!canInstall}>
            {primaryLabel}
          </ButtonItem>
        </PanelSectionRow>
        <PanelSectionRow>
          <ButtonItem
            layout="below"
            onClick={onStart}
            disabled={disabled || running || !installed || legacyCore || !canUseFex}
          >
            启动服务
          </ButtonItem>
        </PanelSectionRow>
        <PanelSectionRow>
          <ButtonItem layout="below" onClick={onStop} disabled={disabled || !(running || coreRunning)}>
            停止服务
          </ButtonItem>
        </PanelSectionRow>
        <PanelSectionRow>
          <ButtonItem
            layout="below"
            onClick={() => void onCheckUpdates()}
            disabled={disabled || !installed || !canUseFex}
          >
            {updateBusy ? "正在检查…" : "检查更新"}
          </ButtonItem>
        </PanelSectionRow>
        {updateResult && (
          <PanelSectionRow>
            <div style={rowTextStyle()}>
              {updateResult.update_available
                ? `有新包${updateResult.version ? `（${updateResult.version}）` : ""}`
                : "已是最新"}
            </div>
          </PanelSectionRow>
        )}
        <PanelSectionRow>
          <ToggleField
            label="开机启动"
            checked={!!status.autostart}
            onChange={onToggleAutostart}
            disabled={
              disabled ||
              !installed ||
              ((legacyCore || !canUseFex) && !status.autostart)
            }
          />
        </PanelSectionRow>
      </PanelSection>

      <PanelSection title="手机绑定">
        <PanelSectionRow>
          <div style={rowTextStyle()}>
            使用手机“UU主机加速器”App 的扫码绑定入口扫描下方二维码，按手机提示绑定，再在手机选择游戏和节点；请确保手机与掌机处于同一局域网。
          </div>
        </PanelSectionRow>
        {legacyCore ? (
          <PanelSectionRow>
            <div style={errorStyle}>当前为旧版核心，不支持扫码绑定；请安装 FEX 核心替换。</div>
          </PanelSectionRow>
        ) : !installed ? (
          <PanelSectionRow>
            <div style={noteStyle}>尚未安装核心，请先在“操作”中安装核心。</div>
          </PanelSectionRow>
        ) : !coreRunning ? (
          <PanelSectionRow>
            <div style={noteStyle}>核心未运行，请在“操作”中启动服务后等待二维码生成。</div>
          </PanelSectionRow>
        ) : qrSvgDataUri ? (
          <>
            <PanelSectionRow>
              <img src={qrSvgDataUri} alt="手机绑定二维码" style={qrImgStyle} />
            </PanelSectionRow>
            <PanelSectionRow>
              <ButtonItem layout="below" onClick={() => openEnlargedQr(qrSvgDataUri)}>
                放大二维码
              </ButtonItem>
            </PanelSectionRow>
            <PanelSectionRow>
              <div style={noteStyle}>二维码由核心生成，是否可用请以手机 UU App 扫码结果为准。</div>
            </PanelSectionRow>
          </>
        ) : (
          <PanelSectionRow>
            <div style={noteStyle}>
              正在等待核心生成二维码，可点击“刷新二维码”重试；无二维码并不代表已绑定。
            </div>
          </PanelSectionRow>
        )}
        <PanelSectionRow>
          <ButtonItem layout="below" onClick={() => void poll()}>
            刷新二维码
          </ButtonItem>
        </PanelSectionRow>
      </PanelSection>

      <PanelSection title="核心管理">
        {confirm === null ? (
          <>
            <PanelSectionRow>
              <ButtonItem layout="below" onClick={() => setConfirm("uninstall")} disabled={disabled || !installed}>
                卸载核心
              </ButtonItem>
            </PanelSectionRow>
            <PanelSectionRow>
              <div style={noteStyle}>仅移除本插件下载的核心运行时，不影响 Decky 前端；绑定身份会保留。</div>
            </PanelSectionRow>
            <PanelSectionRow>
              <ButtonItem
                layout="below"
                onClick={() => setConfirm("reset")}
                disabled={disabled || !installed || legacyCore || !canUseFex}
              >
                重置绑定
              </ButtonItem>
            </PanelSectionRow>
            <PanelSectionRow>
              <div style={noteStyle}>重置将重新生成绑定身份，需要重新绑定。</div>
            </PanelSectionRow>
          </>
        ) : (
          <>
            <PanelSectionRow>
              <div style={rowTextStyle()}>
                {confirm === "uninstall"
                  ? "确认卸载核心？将停止服务并移除插件下载的运行时，绑定身份会保留。"
                  : "确认重置绑定身份？重置后需要重新绑定。"}
              </div>
            </PanelSectionRow>
            <PanelSectionRow>
              <ButtonItem
                layout="below"
                onClick={confirm === "uninstall" ? onConfirmUninstall : onConfirmReset}
                disabled={disabled || (confirm === "reset" && (legacyCore || !canUseFex))}
              >
                确认
              </ButtonItem>
            </PanelSectionRow>
            <PanelSectionRow>
              <ButtonItem layout="below" onClick={() => setConfirm(null)} disabled={disabled}>
                取消
              </ButtonItem>
            </PanelSectionRow>
          </>
        )}
      </PanelSection>
    </>
  );
}

export default definePlugin(() => ({
  name: PLUGIN_TITLE,
  titleView: <div className={staticClasses.Title}>{PLUGIN_TITLE}</div>,
  icon: <FaBolt />,
  content: <UuPanel />,
  onDismount() {
    // 仅插件卸载生命周期：不在此停止加速守护进程。
  },
}));
