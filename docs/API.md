# 接口

模块GET使用仓内样例，模块POST可传csv或rows与context，直接计算当前规则。/api/runs使用完整流水线并原子保存。每个阶段返回rows、quarantine、metrics；后续阶段还返回累计隔离。/api/upload接收multipart文件file。/api/runs/<id>/archive只导出一份带清单与证据的CSV。

## 回单脱敏签证（/api/receipts）

独立子系统，角色通过 X-Role 头声明（经办/总包/财务/审计，默认经办）。原件入库不外发，对外只出脱敏件：POST /ingest 导入回单（重复跳过、坏行隔离、同号不同内容409）；POST /visa/build 脱敏预览；POST /visa/publish 财务原子发布（失败回滚保留旧版，重试命中台账返回 reused 不新增）；GET /visa/active、/visa/<no> 取脱敏签证；GET /visa/<no>/verify 公开摘要核验；GET /visa/<no>/reveal/<receipt_no> 仅财务/审计回查原件并写审计日志；GET /visa/<no>/export 导出无原值的脱敏CSV；GET /visa/versions 查看版本与发布尝试；GET /audit-log 仅审计。细节见 docs/RECEIPTS.md。

