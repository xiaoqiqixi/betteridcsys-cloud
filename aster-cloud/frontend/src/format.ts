import type { Locale } from "./composables/preferences";
export function dateText(raw: string | null | undefined, locale: Locale) {
  if (!raw) return "—";
  const value = new Date(raw);
  return Number.isFinite(value.valueOf())
    ? new Intl.DateTimeFormat(locale === "en" ? "en-GB" : "zh-CN", {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(value)
    : "—";
}
export function sizeMiB(value: number) {
  return value >= 1024
    ? `${new Intl.NumberFormat("en", { maximumFractionDigits: 2 }).format(value / 1024)} GiB`
    : `${value} MiB`;
}
export const actionNames: Record<string, [string, string]> = {
  create: ["创建实例", "Create instance"],
  public_adopt: ["接纳实例公网地址", "Adopt VM public address"],
  public_detach: ["解除实例公网地址", "Detach VM public address"],
  start: ["启动", "Start"],
  shutdown: ["关机", "Shut down"],
  reboot: ["重启", "Restart"],
  force_off: ["强制关机", "Force off"],
  delete: ["删除实例", "Delete instance"],
  snapshot_create: ["创建快照", "Create snapshot"],
  snapshot_restore: ["恢复快照", "Restore snapshot"],
  snapshot_delete: ["删除快照", "Delete snapshot"],
  backup_create: ["创建备份", "Create backup"],
  backup_verify: ["校验备份", "Verify backup"],
  backup_restore: ["恢复备份", "Restore backup"],
  backup_delete: ["删除备份", "Delete backup"],
  migrate_prepare: ["准备迁移", "Prepare migration"],
  migrate_transfer: ["安全传输", "Transfer migration data"],
  migrate_import: ["导入目标节点", "Import to target"],
  migrate_activate: ["激活目标实例", "Activate target"],
  migrate_retire_source: ["退役迁移源", "Retire migration source"],
};
export const failureNames: Record<string, [string, string]> = {
  public_ip_exhausted: [
    "此出口暂无可分配地址，请更换地址池或补充可用地址。",
    "No address is available for this egress. Choose another pool or add available addresses.",
  ],
  network: [
    "连接失败，请检查网络后重新加载。",
    "Connection failed. Check your connection and reload.",
  ],
  unknown: [
    "结果尚未确认。请查看任务状态，不要重复提交。",
    "The result is not yet confirmed. Check tasks before submitting again.",
  ],
  unauthorized: [
    "登录已过期，请重新登录。",
    "Your session has expired. Sign in again.",
  ],
  forbidden: [
    "你没有执行此操作的权限。",
    "You do not have permission to perform this action.",
  ],
  conflict: [
    "当前状态已变化，请重新加载后确认。",
    "The state has changed. Reload before continuing.",
  ],
  invalid: [
    "无法处理请求，请检查输入后重试。",
    "The request could not be processed. Check the input.",
  ],
  unavailable: [
    "服务暂时不可用，请稍后重新加载。",
    "The service is unavailable. Try reloading later.",
  ],
};
export const permissionNames: Record<string, [string, string]> = {
  "audit.read": ["查看审计记录", "View audit log"],
  "instances.dangerous": [
    "重启、强制关机与删除实例",
    "Restart, force off and delete instances",
  ],
  "instances.manage": [
    "创建、启动与关闭实例",
    "Create, start and shut down instances",
  ],
  "instances.read": ["查看实例与任务", "View instances and tasks"],
  "migration.manage": ["管理实例迁移", "Manage migrations"],
  "nodes.manage": ["管理节点与网络", "Manage nodes and networks"],
  "nodes.read": ["查看节点", "View nodes"],
  "settings.manage": ["管理系统设置", "Manage system settings"],
  "storage.manage": [
    "创建、校验与删除快照备份",
    "Create, verify and delete snapshots and backups",
  ],
  "storage.read": ["查看快照与备份", "View snapshots and backups"],
  "storage.restore": ["从快照或备份恢复", "Restore snapshots or backups"],
  "users.manage": ["管理成员与权限", "Manage members and access"],
};
export const auditNames: Record<string, [string, string]> = {
  "public_ingress.updated": [
    "公网入站规则已保存",
    "Public ingress rules saved",
  ],
  "public_ip.pool.create": ["公网地址池已创建", "Public IP pool created"],
  "public_ip.pool.extend": ["公网地址池已补充", "Public IP pool extended"],
  "public_ip.pool.state": [
    "公网地址池状态已修改",
    "Public IP pool state changed",
  ],
  "public_ip.lease.allocate": ["公网 IP 已分配", "Public IP allocated"],
  "public_ip.lease.release": ["公网 IP 已回收", "Public IP reclaimed"],
  "public_ip.resource.allocate": [
    "实例公网地址已分配",
    "VM public address allocated",
  ],
  "public_ip.resource.bind": [
    "公网地址绑定已规划",
    "Public address binding planned",
  ],
  "public_ip.resource.unbind": [
    "公网地址解绑已规划",
    "Public address detachment planned",
  ],
  "public_ip.resource.release": [
    "实例公网地址已回收",
    "VM public address reclaimed",
  ],
  "overlay.vpc.created": ["VPC 已创建", "VPC created"],
  "overlay.epoch.planned": ["网络变更已规划", "Network change planned"],
  "overlay.member.reserved": ["网络成员已预留", "Network member reserved"],
  "overlay.advance.requested": [
    "请求继续网络变更",
    "Network continuation requested",
  ],
  "overlay.reconcile.requested": [
    "请求核对节点回执",
    "Node receipt check requested",
  ],
  "overlay.recovery.planned": ["网络恢复已规划", "Network recovery planned"],
  "overlay.recovery.replacement": [
    "网络恢复配置已修正",
    "Recovery configuration replaced",
  ],
  "overlay.prepare.sending": [
    "网络准备正在派发",
    "Network preparation sending",
  ],
  "overlay.prepare.succeeded": [
    "网络准备已确认",
    "Network preparation confirmed",
  ],
  "overlay.prepare.uncertain": [
    "网络准备待核实",
    "Network preparation unconfirmed",
  ],
  "overlay.prepare.rejected": [
    "网络准备已拒绝",
    "Network preparation rejected",
  ],
  "overlay.program.sending": [
    "网络应用正在派发",
    "Network application sending",
  ],
  "overlay.program.succeeded": [
    "网络应用已确认",
    "Network application confirmed",
  ],
  "overlay.program.uncertain": [
    "网络应用待核实",
    "Network application unconfirmed",
  ],
  "overlay.program.rejected": [
    "网络应用已拒绝",
    "Network application rejected",
  ],
  "overlay.release.sending": ["网络放行正在派发", "Network release sending"],
  "overlay.release.succeeded": ["网络放行已确认", "Network release confirmed"],
  "overlay.release.uncertain": [
    "网络放行待核实",
    "Network release unconfirmed",
  ],
  "overlay.release.rejected": ["网络放行已拒绝", "Network release rejected"],
  "network.vpc.planned": ["私有网络已规划", "Private network planned"],
  "network.pool.created": ["IP 地址池已创建", "IP pool created"],
  "network.lease.reserved": ["IP 地址已预留", "IP address reserved"],
  "identity.bootstrap": ["创建首位管理员", "First administrator created"],
  "identity.user_created": ["创建成员", "Member created"],
  "identity.user_updated": ["更新成员资料", "Member updated"],
  "identity.sessions_revoked": ["撤销成员会话", "Member sessions revoked"],
  "identity.login_failed": ["登录失败", "Sign-in failed"],
  "identity.login": ["账户登录", "Signed in"],
  "identity.logout": ["账户退出", "Signed out"],
  "instance.create_requested": ["请求创建实例", "Instance creation requested"],
  "node.registered": ["节点已登记", "Node registered"],
  "node.heartbeat": ["记录节点心跳", "Node heartbeat recorded"],
  "node.dispatch_claimed": [
    "已锁定任务，准备派发",
    "Task claimed for node dispatch",
  ],
  "node.result_dispatched": [
    "节点已受理开通任务",
    "Node accepted provisioning task",
  ],
  "node.result_succeeded": [
    "节点开通任务已完成",
    "Node provisioning task completed",
  ],
  "node.result_rejected": [
    "节点已拒绝开通任务",
    "Node rejected provisioning task",
  ],
  "node.result_uncertain": [
    "节点开通结果待核实",
    "Node provisioning result uncertain",
  ],
  "node.maintenance_on": ["节点进入维护模式", "Node maintenance enabled"],
  "node.maintenance_off": ["节点退出维护模式", "Node maintenance disabled"],
  "operation.dispatch": ["派发操作任务", "Task dispatched"],
  "operation.dispatch_requested": ["请求派发任务", "Task dispatch requested"],
  "operation.reconcile_requested": [
    "请求核对任务",
    "Task reconciliation requested",
  ],
  "operation.dispatch_committed": ["任务派发已提交", "Task dispatch committed"],
  "operation.succeeded": ["操作已完成", "Operation completed"],
  "operation.rejected": ["操作已拒绝", "Operation rejected"],
  "operation.uncertain": ["操作结果待核实", "Operation result uncertain"],
  "operation.dispatched": ["节点已受理操作", "Node accepted operation"],
  "provisioning.accepted": ["开通任务已受理", "Provisioning accepted"],
  "provisioning.succeeded": ["开通任务已完成", "Provisioning completed"],
  "provisioning.rejected": ["开通任务已拒绝", "Provisioning rejected"],
};
