# 管理台真实 HTTPS / MySQL 浏览器补验

> **历史记录：2026-10-22。** 下文数字、构建哈希、浏览器覆盖和未执行项仅对应当时基线。最新已核对源码、Firefox / 严格 TLS / MySQL 与响应式导航结果见[验证入口](VALIDATION.md)；当前复现方法见[浏览器门禁](../deploy/ci/NETWORK_BROWSER.md)。不使用本页旧结果替代后续提交验收。

2026-10-22，开发验收，不是生产或真实 KVM 验收。基于 `ceda0bbc` 的管理台继续修复，后端控制器代码不变。

## 环境与数据边界

- Ubuntu22 amd64，独立 MySQL8.4.13 / `aster_cloud_browser_test` / Unix socket；既有财务库和三个财务服务未参与本fixture。
- Go控制器SHA256 `67f581393962d08ec39214dd4072279d74e0b7526e8fd7c5f1a6c85c9a1cfe97`。专用API仅监听远端127.0.0.1:9444，经SSH转发到本机HTTPS localhost:5444；不开放公网管理员端口。
- 浏览器使用真实Secure/HttpOnly/SameSite Cookie、CSRF与持久 staff RBAC；没有mock API、demo fallback、注入DOM成功画面或降低后端协议约束。
- 4个`fixture-*-no-vm`是合成缓存记录。两节点始终maintenance=true、heartbeat=NULL、free=0，节点TLS文件不存在；未运行libvirt、未创建VM、未调用节点写操作。
- 正式API实际验证：viewer读200/写403、operator危险动作403、缺CSRF403、操作202及同key绑定重放、离线创建409且码为`NODE_NOT_READY`。最终SQL核对2个操作均accepted、snapshot=pending、backup=uncertain、migration=preparing且manifest/fence为空、jobs/reservations/dispatch/reconcile/commit审计均0。

## 实际浏览器执行

ChatGPT in-app Chromium，CSS viewport 1440×1000、768×1024、375×812、320×740；不是物理手机验收。共享控件和代表状态覆盖如下，未声称执行静态测试矩阵的全部组合：

| 范围 | 实际观察结果 |
| --- | --- |
| 登录/加载/空态 | 实际HTTPS登录、禁用与忙碌状态、空实例列表、随后真实MySQL合成记录列表；无演示数据回退 |
| admin/operator/viewer | 三种真实账户分别登录退出；只读无成员/审计导航，直接成员路由显示无权限；操作员重启/强关/迁移/删除禁用；管理员具有完整入口 |
| 退出204 | 修前合法空204误报未知的截图保留；修后多次退出直接回登录页、未知提示消失，可重新输入并登录下一身份 |
| 手机导航/返回 | 修前点击Tasks会退回详情；修后实际Nodes→Instances→Tasks→Back Instances→Back Nodes，无重复中间页；Back首次关闭drawer并恢复触发器焦点 |
| 偏好/选择器 | 自定义下拉，中英文、深浅色；键盘Home/End/Enter选择、Escape先关下拉不关父层、完成回触发器；英文深色刷新及导航/返回后保留 |
| 抽屉/弹框 | 浅深主题统一，退出栏位于底部；Shift-Tab包回末项、Escape返回触发器；关闭drawer后立即点击偏好可打开；320px确认框/成员表单无横向页面溢出 |
| 成员/权限 | 真实三成员与角色列表，自定义权限表单、320px未保存关闭提示及放弃；没有在浏览器新增密码/提交授权 |
| 实例/存储 | 长ID折行、记录状态与当前采样分开；无真实节点时读取失败仍未确认；uncertain备份禁止恢复/删除，不显示成功manifest |
| 任务/迁移 | 两个真实accepted意图、派发确认框取消；preparing迁移四步展示并禁止越级提交；没有实际派发或伪造完成状态 |
| 审计 | 持久身份/资源事件，8项生产节点/创建动作中英翻译补齐；claimed/accepted不称VM已成功 |
| 可视检查 | 实际查看桌面、375和320截图；检查768列表，所测DOM scrollWidth不大于viewport；最终浏览器warn/error日志为空 |

## 冻结构建与证据

- 最终149 tests /6文件 /0 FAIL或SKIP，typecheck、format、build通过。财务公共合同及controller传输包另跑race，48 PASS事件、0SKIP/FAIL；首次受沙箱禁止本机监听的失败原日志保留，获准监听后重跑。
- 实测JS `index-B636eQE5.js` SHA256 `382eab3e78fdd2bdd92aff01e3bc9cb82cd90bce804710a9700320a86c8ca04b`；CSS `index-CRtaRfOu.css` SHA256 `9c60376fea35609131ac0278061325320166cb683164aec1d5086c60e6d29255`。上传后远端hash一致。
- 原始证据在ignored `aster-cloud/artifacts/cloud-browser-20261022/`，含TDD红/绿、fixture脚本、SQL计数、修前/修后截图。正式仓库不附凭据/私钥/CSRF或fixture数据。主要最终截图名：`final-desktop-instances-light-1440.jpg`、`final-mobile-instances-light-375.jpg`、`final-mobile-navigation-light-375.jpg`、`final-mobile-dispatch-confirm-320.jpg`、`final-mobile-dirty-member-320.jpg`。

## 临时环境清理

专用浏览器会话已退出；最终有效认证session=0。专用API/MySQL已停止，9444关闭，本轮`/run`配置/口令、`/tmp`私有数据库及`/opt`测试程序目录已移除；现有财务三个服务仍active。2026-10-23补核：两枚上轮临时CA均已从用户钥匙串消失，用户trust设置为空，旧localhost证书返回NOT_TRUSTED；本机明文凭据与私钥均不存在。对应脱敏清理回执另存ignored operations-20261023/，未重置其它系统信任。

## 明确未执行

未完整跑静态矩阵全部组合、ACK丢失/慢响应的浏览器故障注入、200%浏览器缩放、实际手机键盘/Safari/Firefox、减少动态效果的实际浏览器验收。未验真实VM、快照/备份/迁移、宿主故障、网络隔离或主控生产Nginx/TLS安装；相关Go/mTLS/fake executor测试不等于硬件验收。热迁移、HA、VNC、MFA、租户SSO、定时异地备份仍不在实现范围。
