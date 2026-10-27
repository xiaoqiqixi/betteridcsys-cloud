// Shared presentation only: resource and operation states remain server-owned.
export type StatusTone = "neutral" | "info" | "good" | "warning" | "danger";
const labels: Record<string, [string, string, StatusTone]> = {
  shutoff: ["已关机", "Shut off", "neutral"],
  sending: ["正在派发", "Sending", "info"],
  dispatched: ["已派发", "Dispatched", "info"],
  transferred: ["已传输", "Transferred", "info"],
  imported: ["已导入", "Imported", "info"],
  running: ["运行中", "Running", "good"],
  stopped: ["已关机", "Stopped", "neutral"],
  active: ["可用", "Active", "good"],
  enabled: ["已启用", "Enabled", "good"],
  disabled: ["已停用", "Disabled", "neutral"],
  online: ["在线", "Online", "good"],
  offline: ["离线", "Offline", "neutral"],
  accepted: ["已受理", "Accepted", "info"],
  pending: ["待执行", "Pending", "info"],
  superseded: ["已由新版本替代", "Superseded", "neutral"],
  queued: ["等待执行", "Queued", "info"],
  dispatching: ["正在派发", "Dispatching", "info"],
  succeeded: ["已完成", "Completed", "good"],
  failed: ["失败", "Failed", "danger"],
  rejected: ["已拒绝", "Rejected", "danger"],
  uncertain: ["待核实", "Uncertain", "warning"],
  unknown: ["待核实", "Unknown", "warning"],
  ready: ["可用", "Ready", "good"],
  verified: ["已校验", "Verified", "good"],
  preparing: ["准备中", "Preparing", "info"],
  prepared: ["已准备", "Prepared", "info"],
  fenced: ["已隔离", "Fenced", "warning"],
  deleted: ["已删除", "Deleted", "neutral"],
  maintenance: ["维护中", "Maintenance", "warning"],
};

export function statusPresentation(
  state: string,
  tr: (zh: string, en: string) => string,
) {
  const entry = Object.prototype.hasOwnProperty.call(labels, state)
    ? labels[state]
    : undefined;
  return {
    label: entry ? tr(entry[0], entry[1]) : state || tr("待核实", "Unknown"),
    tone: entry?.[2] || ("neutral" as StatusTone),
  };
}
