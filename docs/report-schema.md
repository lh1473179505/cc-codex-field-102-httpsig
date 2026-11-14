# 报告 schema

| 字段 | 类型 | 含义 |
|---|---|---|
| input | string | 消息路径，与命令行 `--message` 一致 |
| policy | string | `--policy` 路径 |
| decision | string | `ok` 或 `reject` |
| reason_codes | string[] | 成功时为空数组；失败时去重并保留首次出现顺序 |
| labels | string[] | 本轮涉及的签名标签 |
| bases | object | 可选，标签到签名基础串；便于自检，不作为打分字段 |

`reason_codes` 使用这些值：`missing_signature`、`unknown_keyid`、`alg_not_allowed`、`bad_signature`、`expired`、`not_yet_valid`、`missing_created`、`missing_component`、`content_digest_mismatch`、`tag_mismatch`、`forbidden_component`、`duplicate_query_param`、`bad_query`、`bad_path`、`unsupported_param`、`query_param_name`。
