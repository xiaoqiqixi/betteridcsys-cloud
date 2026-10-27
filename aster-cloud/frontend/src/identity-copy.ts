type Translate = (zh: string, en: string) => string;
export function identityNoticeLabels(tr: Translate) {
  return {
    noticeAriaLabel: tr("账户操作状态", "Account operation status"),
    conflictTitle: tr("资料已有更新", "This account has changed"),
    conflictBody: tr(
      "其他人已修改这位成员的资料。你的草稿仍保留，不能直接覆盖。",
      "Another operator changed this account. Your draft is preserved and cannot overwrite it.",
    ),
    conflictHint: tr(
      "重新读取会放弃当前草稿，请先记下需要保留的内容。",
      "Reloading discards this draft. Copy anything you need to keep first.",
    ),
    uncertainTitle: tr("更改结果待核对", "Change awaiting verification"),
    uncertainBody: tr(
      "暂时无法确认这次更改是否完成。请核对原操作，不要重复提交。",
      "The result of this change is not yet confirmed. Verify the original operation instead of submitting again.",
    ),
    uncertainHint: tr(
      "查不到回执也不代表未执行；未核实前会保留这项记录。",
      "A missing receipt does not prove it was not executed. This record stays until verified.",
    ),
    blockedTitle: tr("暂时不能提交更改", "Changes are temporarily blocked"),
    blockedBody: tr(
      "无法安全保留待核对记录，或存在升级前尚未核实的操作。请保留当前浏览器数据，联系管理员核查。",
      "Pending records cannot be safely stored, or an earlier operation remains unresolved. Keep this browser data and ask an administrator to investigate.",
    ),
    busyTitle: tr("正在提交更改", "Submitting change"),
    busyBody: tr(
      "请稍候，正在等待处理结果。",
      "Please wait for the operation result.",
    ),
    confirmedTitle: tr("操作已核实", "Operation verified"),
    confirmedBody: tr(
      "这次更改已由原操作回执确认。",
      "The original operation receipt confirms this change.",
    ),
    targetPrefix: tr("成员", "Member"),
    baseRevisionLabel: tr("原版本", "Original revision"),
    currentRevisionLabel: tr("当前版本", "Current revision"),
    operationIdLabel: tr("操作 ID", "Operation ID"),
    reloadAction: tr("放弃草稿并重新读取", "Discard draft and reload"),
    inspectAction: tr("核对原操作", "Verify original operation"),
  };
}
export function identityFieldLabels(
  tr: Translate,
  editing: boolean,
  custom: boolean,
) {
  return {
    formAriaLabel: tr("成员资料与权限", "Member details and access"),
    sectionIdentity: tr("登录资料", "Sign-in details"),
    nameLabel: tr("姓名", "Name"),
    namePlaceholder: tr("填写成员姓名", "Member name"),
    emailLabel: tr("邮箱", "Email"),
    emailPlaceholder: tr("填写登录邮箱", "Sign-in email"),
    passwordLabel: editing
      ? tr("新密码（留空则不更改）", "New password (leave blank to keep)")
      : tr("初始密码", "Initial password"),
    passwordPlaceholder: tr("输入密码", "Enter password"),
    passwordHint: tr(
      "12–1024 字节。密码仅用于本次提交，不保存到浏览器。",
      "12–1024 bytes. Used only for this submission, never saved in this browser.",
    ),
    sectionAccess: tr("角色与访问权限", "Role and access"),
    roleLabel: tr("选择角色", "Choose role"),
    selfLockNotice: tr(
      "不能更改自己的角色、权限或停用自己的账户。",
      "You cannot change your own role or permissions, or disable your own account.",
    ),
    enabledLabel: tr("允许登录", "Allow sign-in"),
    enabledHint: tr(
      "停用后，该成员的所有会话立即失效。",
      "Disabling the account ends all its sessions immediately.",
    ),
    enabledOn: tr("已启用", "Enabled"),
    enabledOff: tr("已停用", "Disabled"),
    permissionsLabel: tr("权限明细", "Permissions"),
    permissionsHint: custom
      ? tr(
          "逐项授予此成员所需的权限。",
          "Grant only the access this member needs.",
        )
      : tr(
          "此角色的固定权限，只读。选择自定义角色可逐项授权。",
          "These fixed role permissions are read-only. Choose Custom to assign individual permissions.",
        ),
    permissionsEmpty: tr("尚未授予权限", "No permissions granted"),
    sectionReason: tr("变更说明", "Change reason"),
    reasonLabel: tr("说明本次变更的原因", "Reason for this change"),
    reasonPlaceholder: tr(
      "例如：调整值班人员的访问权限",
      "For example: update access for the on-call operator",
    ),
    reasonHint: tr(
      "必填，单行 1–500 字，首尾不要留空格。请勿填写密码或密钥。",
      "Required: 1–500 characters on one line, without leading or trailing spaces. Do not include passwords or keys.",
    ),
    reasonCountSuffix: tr("字", "characters"),
  };
}
export function identityRevocationLabels(tr: Translate) {
  return {
    rowTitle: tr("要求重新登录", "Require re-authentication"),
    rowDescription: tr(
      "结束该成员在所有设备上的当前会话，下次访问需重新登录。",
      "Sign this member out of all active devices. They will need to sign in again.",
    ),
    rowSelfDescription: tr(
      "结束你在所有设备上的会话，包括当前设备。",
      "End your sessions on all devices, including this one.",
    ),
    openAction: tr("撤销全部会话", "Revoke all sessions"),
    modalTitle: tr("撤销全部会话", "Revoke all sessions"),
    closeLabel: tr("关闭确认窗口", "Close confirmation"),
    discardLabel: tr("放弃变更说明", "Discard reason"),
    continueLabel: tr("继续填写", "Continue editing"),
    targetAccountLabel: tr("目标成员", "Target member"),
    targetIdLabel: tr("成员 ID", "Member ID"),
    scopeNotice: tr(
      "所有已登录设备都会失效。账户启停状态不变，已启用的账户可重新登录。",
      "All active devices will be signed out. The account status is unchanged; enabled accounts can sign in again.",
    ),
    selfScopeNotice: tr(
      "包括当前设备。提交后你会回到登录页；结果待核对时，重新登录后继续核对。",
      "This includes this device. You will return to sign-in after submission. Sign in again to verify an uncertain result.",
    ),
    vmSafeNotice: tr(
      "不会取消云主机任务，也不会停止正在运行的实例。",
      "This does not cancel VM tasks or stop running instances.",
    ),
    reasonLabel: tr("撤销原因", "Reason"),
    reasonPlaceholder: tr(
      "说明为什么需要重新登录",
      "Why is a fresh sign-in needed?",
    ),
    reasonHint: tr(
      "单行 1–500 字，不要填写密码或密钥。",
      "1–500 characters on one line. Do not include passwords or keys.",
    ),
    reasonCountSuffix: tr("字", "characters"),
    cancelAction: tr("取消", "Cancel"),
    confirmAction: tr("确认撤销会话", "Confirm revocation"),
    confirmSelfAction: tr("撤销并退出登录", "Revoke and sign out"),
  };
}
