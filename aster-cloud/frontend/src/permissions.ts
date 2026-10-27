import type { Action } from "./api/types";
export function actionPermission(action: string) {
  switch (action) {
    case "create":
    case "start":
    case "shutdown":
    case "public_adopt":
    case "public_detach":
      return "instances.manage";
    case "reboot":
    case "force_off":
    case "delete":
      return "instances.dangerous";
    case "snapshot_restore":
    case "backup_restore":
      return "storage.restore";
    case "snapshot_create":
    case "snapshot_delete":
    case "backup_create":
    case "backup_verify":
    case "backup_delete":
      return "storage.manage";
    case "migrate_prepare":
    case "migrate_transfer":
    case "migrate_import":
    case "migrate_activate":
    case "migrate_retire_source":
      return "migration.manage";
    default:
      return "";
  }
}
export function actionAllowed(
  action: Action,
  state: string,
  permissions: readonly string[],
) {
  const permission = actionPermission(action);
  if (!permission || !permissions.includes(permission)) return false;
  if (
    action.startsWith("snapshot_") ||
    action.startsWith("backup_") ||
    action === "migrate_prepare"
  )
    return state === "shutoff";
  return state !== "deleted";
}
