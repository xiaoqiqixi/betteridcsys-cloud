# W07-A：主控成员完整分页

2026-10-25，main 开发候选；仅成员读取链，不是身份权限全部完成或正式发行。

## 功能与边界

- 支持第101位及之后的成员，固定100条/页，后端按`created_at ASC,id ASC`排序并查询101条。
- `next_cursor`以最后一条**已返回**记录生成；结束为null，保留的`truncated_possible`只在真实还有下一条时为true。
- 游标严格、有界、版本化，是不可信读取位置而非授权票据。每页仍检查当前会话、启用状态和`users.manage`。管理员全部显式权限、custom有界委派、所有写操作合同均保持。
- 不添加搜索/筛选/导出、总人数、MFA、SSO、用户revision、可配置财务权限组；这些是后续独立切片。
- 静态数据遍历无漏无重；并发创建/编辑时读取的是每页当前数据，不承诺长时间一致快照。上一页重新读取，不缓存旧身份的行。
- 前端游标栈只在当前页面内存里；成功才更新页码。失败重试原目标，401/403清旧行与游标，换账号/权限变化关旧编辑器，迟到响应丢弃。手机按钮可换行，中英文案及原明暗主题token保留。

完整接口见[identity说明](../internal/identity/README.md)，后续安全切片见仓库`docs/IDENTITY_PERMISSION_PLAN.md`。

## schema 11 与升级合同

只新增`011_console_users_pagination.sql`：精确索引`controller_console_users_created_id(created_at,id)`。旧001–010 SQL和历史receipt、账户、会话、审计数据不改。财务金额、币种、支付、历史快照及任何财务SQL完全不在本切片内。

迁移先检查保留索引名：精确的可见ASC/BTREE/非unique完整列索引才可承认；缺失执行DDL，正确DDL已成功但receipt缺失可重入，同名错列/倒序/前缀/不可见/表达式等拒绝。写receipt前再次核结构；已有receipt后结构缺失/漂移，check和migrate拒绝，不静默重建。

打包器从SQL最大连续号得出controller_mysql=11；安装器继续用独立migrator及原INDEX权限，不增加生产账户权限。旧binary严格拒绝11库，所以必须停写、备份并配套部署前后端；回滚用匹配的主控库备份/一致journals和应用，不能删receipt、换旧binary或拿财务库代替。该合同不等于已完成真实主机升级演练。

## 回归入口

- `internal/identity/users_page_test.go`：只读GET例外、其他身份/写query拒绝，canonical游标坏编码/字段/时间负例。
- `internal/identity/users_page_mysql_test.go`：0/1/99/100/101/205、同微秒时间、SQL预期顺序、205人深页EXPLAIN索引选择、无漏重、重新读取位置、匿名/只读403、有界管理者及下一页前撤权401。
- `internal/control/users_pagination_migration_mysql_test.go`：10→11、receipt未落重入、重复migrate、10类冲突、记录后缺失/漂移、旧receipt与身份历史摘要不变。
- `frontend/tests/users-pagination.test.ts`：完整分页响应、205人三页、忙碌/失败重试、401/403清理、身份切换、旧响应及循环游标。
- `deploy/scripts/test_cloud_package.py`：新requested commit的schema11，与旧合成commit的schema10分别读取，不复写旧版本。
- `deploy/ci/test_cloud_mysql_grants.py`：新索引精确定义也进入隔离native MySQL安装权限检查。

现有`deploy/ci/check.sh`在真实MySQL下运行全包race，任何SKIP使CI失败；新增测试自动纳入，不通过删除用例或放宽SKIP绕过。

## 本地结果与未验

- 先RED：旧接口对合法GET cursor返回400；旧UI缺分页且接受缺next_cursor/矛盾响应。随后GREEN；新增保存回读用例又捕获了shallowRef组合watch因同身份刷新误清页栈，改用值getter后通过。
- 前端完整format/typecheck、40文件969项JSDOM测试、production build通过；其中本包11项行为/响应检查。不把JSDOM当视觉或实库浏览器。
- identity/control两包race在允许本机loopback监听后通过，日志分别33/430个PASS事件；16/111个SKIP事件均为未配置隔离MySQL，不能把父测试PASS计为SQL通过。最初受沙箱bind阻断的TLS运行单列为环境阻断，不算业务失败或通过。
- identity/control vet、Linux/amd64静态controller构建通过。打包Python26项、安装器Python19项通过；grants脚本只有语法与相关隔离合同检查，未在本机执行真实MySQL权限验收。
- 新迁移001–010无diff，无财务版本/金额/SQL/支付/历史快照变更。以上是提交前结果；提交与同SHA CI另行记录，不借用旧CI给新代码背书。

新增浏览器接入复用现有`network-browser.sh`隔离链：Go overlay在历史baseline前准备205个同微秒成员（原admin、真实viewer和203不可登录列表账号），私有credentials仅向本轮浏览器交付排序ID与viewer登录凭据；生产身份Handler/CSRF创建viewer后撤销seed会话。浏览器阶段成员操作仅GET及登录/退出，不扩大业务写，结束必须证明账户全字段摘要完全不变。独立18项`members_checks`与6个固定成员图叠加原网络/侧栏门槛，不覆盖原163+53检查/64图。该overlay已Linux/amd64交叉编译，尚未执行本切片同SHA真实MySQL浏览器。

待独立验收：同SHA Linux真实MySQL零SKIP、schema10备份升级/回滚流程、真实浏览器成员205人桌面/手机/键盘/读屏/主题实测。真实KVM验收按用户安排后置，但该延期不豁免本切片数据库和浏览器验收。


## 明确移交 W15 的返回体验

原设计“跨路由浏览器返回恢复已看页码/滚动”仍待开发，本包没有删掉或冒充验收：当前离开成员页再返回，会用当前身份重新读第一页，并沿用全局回顶部行为，不恢复旧成员数据。成员页内上一/下一、顶部刷新回首页、保存重读当前页、创建后回首页及失败重试原目标均已纳入组件回归。W15若增加路由缓存，必须同时绑定session epoch、撤权清理并做真实浏览器前进/返回验证，不能将本包仅组件内的游标栈当作已完成。
