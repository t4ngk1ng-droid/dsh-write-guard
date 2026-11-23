# Changelog

## 0.6.9

- 设置页面板：DSH 设置 → 写入防护，全部开关可视化，保存后立即生效
- 面板保存只写 diff，未改动的默认值和 profile 值不会被固化
- 修复：profile 里设的同类开关被运行时覆盖冲掉
- 运行时配置白名单：`notifyCommand`、`auditFile` 等路径/命令字段不再可改
- 无效值在落盘前拒绝，不再"保存成功但没生效"
- Shell 解析补 `sc`/`gc` 等 PowerShell 别名、`cp`/`mv`/`dd of=`/`Export-Csv`/`Copy-Item`
- 字面量 `Invoke-Expression` 递归解析，动态表达式转人工
- 三轮自审：畸形请求体、写盘失败回滚、面板字段漂移

## 0.5.1

- `write_guard_config` 工具：在对话里直接改开关，不用编辑配置文件

## 0.4.0

- `contentChecks`：14 类内容检测各自独立开关

## 0.3.0

- `shellChecks`：8 类 shell 写入检测各自独立开关

## 0.2.4

- 修复五组误拦：`cd` 后验错文件、搜索串里的 `Set-Content`、注释里的 `>`、`-WhatIf`、法语 `MZ` 被当 PE

## 0.2.1

- 首版：pre-execute 扫描、post-execute 校验、哈希链审计、自校验
