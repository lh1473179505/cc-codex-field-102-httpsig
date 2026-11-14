# sign / verify 规则

本仓库实现 RFC 9421 HTTP Message Signatures 的一个请求子集，外加 RFC 9530 的 `sha-256` Content-Digest。只处理 JSON 快照，不发真实 HTTP。算法只认 `hmac-sha256`（标准库 `hmac` + `hashlib`）。密钥是 32 字节，写在 `fixtures/keys.json` 里，用十六进制。

消息字段：`method`、`scheme`、`authority`、`path`、`query`（不含前导 `?`；没有查询串时为空字符串）、`headers`（`[name, value]` 数组，保留出现顺序）、`body`、`now`（Unix 秒，整数）。不要去读系统时钟。

## Signature 与 Signature-Input

两者都是 RFC 8941 字典。`Signature-Input` 的值是内列表：被覆盖的分量按给出的顺序排列，列表参数写在 `)` 后面。`Signature` 的值是字节序列。同一标签必须在两个头里成对出现，否则视为解析失败（退出 2）。

分量标识：

- 派生分量 `@method`、`@authority`、`@scheme`、`@path`、`@query`、`@query-param`、`@target-uri` 写成带引号的字符串。
- 普通字段名若本身是合法 token（如 `content-digest`），写成 token，不必加引号。
- `@query-param` 必须带字符串参数 `name`。其它派生分量在本子集里不得再带参数。
- 禁止覆盖 `signature`、`signature-input` 或 `@signature-params`；出现则 `reason_codes` 含 `forbidden_component`。

## 签名基础串

每一行是 `分量标识: 值`，行与行之间用 `\n` 连接，最后一行之后不要再加换行。最后一行固定为：

```
"@signature-params": (...内列表与参数...)
```

`@signature-params` 的内列表必须与 `Signature-Input` 里该标签的内列表字节级一致，参数顺序也要一致。本子集签字时参数按这个顺序写出（缺省的项跳过）：`created`、`keyid`、`alg`、`expires`、`nonce`、`tag`。

分量取值：

- `@method`：大写方法名。
- `@authority`：小写的 `authority`（主机或 `host:port`）。
- `@scheme`：小写。
- `@path`：必须以 `/` 开头，否则 `bad_path`。
- `@query`：在原始查询串前加 `?`。查询串为空时值为 `?`。快照里的 `query` 若已带 `?`，视为 `bad_query`。
- `@query-param`：在 `query` 里按 `&` 切开，名称与值都做百分号解码（`+` 按 `%20` 处理）。只允许该 `name` 出现一次，出现多次则 `duplicate_query_param`；一次都没有则 `missing_component`。取解码后的值。
- `@target-uri`：`scheme://authority`（均为小写）+ `path`，若查询串非空再拼 `?` 和原始查询串。
- 普通头字段：名字不区分大小写，多个值用 `, `（逗号+空格）拼接。缺头则 `missing_component`。

`alg` 必须是 `hmac-sha256`，否则 `alg_not_allowed`。`keyid` 必须能在密钥表里找到，且落在策略 `allowed_keyids`（若给出）中，否则 `unknown_keyid`。签名是 `HMAC-SHA256(key, base)`，对不上则 `bad_signature`。比较时用固定时间比较。

## 时间与策略

- `created` 必须是整数。若 `created > now + max_clock_skew`，`not_yet_valid`。
- 若有 `expires` 且 `expires < now - max_clock_skew`，`expired`。
- 若策略给出 `required_tag`，签名的 `tag` 必须与之相同，否则 `tag_mismatch`。
- `required_components` 里列出的分量都必须出现在覆盖列表中。条目可以是字符串（只匹配分量名），或 `{"name":"@query-param","params":{"name":"id"}}` 这种带参数的对象。缺了则 `missing_component`。
- 当 `require_content_digest` 为真且 `body` 不是空字符串：必须有 `content-digest` 头，其中 `sha-256` 字节序列等于正文 UTF-8 的 SHA-256，且该头必须被覆盖。头缺失、解不出、或哈希不对，都记 `content_digest_mismatch`。`Content-Digest` 按 RFC 9530 / RFC 8941 字典写出，例如 `sha-256=:...:`。

## 命令

`verify` 读取已签名的请求快照，按策略核对**所有**出现的签名标签。任一标签失败则整体 `decision` 为 `reject`，`reason_codes` 去重后保持首次出现的顺序。全部通过则为 `ok`。不要写出改写后的消息。

`sign` 按策略里的 `sign` 对象补一个签名：`label`、`keyid`、`components`、`created`，可选 `expires`、`nonce`、`tag`。若 `ensure_content_digest` 为真，先按正文重写（或写入）`content-digest`，再算签名基础串。新的 `signature-input` 与 `signature` 覆盖同名旧头；若已有其它标签，保留并与新标签合并成同一字典（新标签写在后面）。写出的消息不要包含加载时附加的内部字段。

## 退出码

- 成功：退出 0，报告 `decision` 为 `ok`，并写出报告（`sign` 还要写出带签名的消息）。
- 验签或补签因业务规则失败：退出 1，`decision` 为 `reject`，报告仍要写（`sign` 可以不写 output）。
- 快照、密钥或策略无法解析，或 Signature 头不是合法的本子集 SFV：退出 2。此时可以不写报告。

仓库里的 `httpsig.sfv` 已经能解析和写出本子集用到的 RFC 8941 结构，请复用，不要另引第三方 Structured Field 库。
