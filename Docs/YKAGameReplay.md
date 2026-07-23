# YSLZM 登录到衣柜离线重放

`YKAReplay.py` 只做离线逻辑重放。它不会连接游戏服务器，不会发送登录
请求，不会注入数据包，也不会把认证 token、账号标识、设备上下文或密钥材料
写入重放轨迹。

## 覆盖链路

重放器验证并串联以下证据：

1. IDA 恢复的 SDK `login_with_token` 请求结构、签名刷新结构和响应字段。
2. TCP 双向流完整重组。
3. 服务端握手帧和客户端 type-3 认证帧。
4. 双向 type-2 密钥交换帧。
5. 服务端从明文紧凑帧切换到 MPPC 数据流。
6. type-34 Gamedata 包装层。
7. 服务端 `576` 标准衣柜快照和 `722` DIY 衣柜快照。
8. 客户端 `143` 终止游标确认。
9. `YKABusiness` 对衣柜 protobuf 的确定性状态重建。

HTTP 登录阶段是根据当前 EXE 的 IDA 证据做结构模拟；PCAP 中观察到的是
token 已交给 GNET type-3 认证帧后的链路。重放结果不会声称执行过真实 HTTP
登录。

## IDA 收敛结果

当前 EXE（SHA-256
`415DEFE14571EDCB874154F25E55A549DF6DFF72818F8597FACC3B91C850045F`）
确认：

- `0x140A13F10` 处理服务端 type 1，并构造客户端 type 3；
- `0x140A154A0` 处理 type 2 密钥交换，将 `session+0x70` 的入站
  security 切换为 factory 7；
- factory 1 是 `GNET::NullSecurity`，factory 7 在 `0x14027D930`
  明确注册为 `GNET::DecompressSecurity`，不是 ARCFour；
- `0x142510B10` 在解析 compact type/length 前调用该入站 security，
  与抓包中服务端 84 字节明文后切到 MPPC 完全吻合；
- `0x140741F40` 和 `0x140730090` 构造 type 34，内部格式为
  `uint16_le(command) || protobuf_payload`；
- `0x14088E0D0` 接收 type 34 并按前两个小端字节分发内部命令。

外层 type 7 的业务名称，以及触发服务端下发 `576/722` 的 Lua/资源层请求，
仍不能从当前 native EXE 中命名。`143` 已由抓包和 protobuf 共同确认是
`cursor=0` 的完成 ACK，不是衣柜拉取请求。

IDA 只观察到签名 `sig/time` 的本地过期判断和刷新；登录 token 没有
`exp/expires/ttl` 字段或本地时间比较。因此 token 的最长时效仍由服务端策略
决定，不能从客户端静态分析给出小时数或天数。

## 从 PCAP 生成脱敏轨迹并重放

```powershell
python YKAReplay.py `
  path\to\login.pcapng `
  --trace-output replay-trace.sanitized.json `
  --output wardrobe-replay.json
```

`replay-trace.sanitized.json` 只保留标准/DIY 快照、服装增量和终止 ACK
这些衣柜业务 protobuf，删除照片、抽卡等无关业务消息，以及认证正文、密钥
材料和网络地址；源文件名也会替换为 `capture-N.pcap[ng]`。它包含源文件
SHA-256 和自身规范化 SHA-256；未同步重算哈希的修改会在导入时失败。导入
还会执行严格字段白名单，重新封签也不能夹带认证正文、账号/设备字段、网络
地址或任意额外元数据。

衣柜 protobuf、源 PCAP 指纹和衣柜状态仍具有可关联性，属于私有数据；
“脱敏”只表示认证、密钥、地址、源文件名和无关业务已移除，不表示该轨迹
适合公开发布。轨迹 SHA-256 用于检测意外修改，不提供来源认证；能够重算
SHA-256 的人仍可制作另一份结构合法的轨迹。

## 重放脱敏轨迹

```powershell
python YKAReplay.py `
  --trace replay-trace.sanitized.json `
  --output wardrobe-replay.json
```

仅查看摘要：

```powershell
python YKAReplay.py `
  --trace replay-trace.sanitized.json `
  --summary-only `
  --output wardrobe-summary.json
```

`--summary-only` 只缩减结果文件，不会移除轨迹中的衣柜 protobuf；与
`--trace-output` 同时使用时，轨迹仍按私有数据处理。

成功结果必须同时满足：

- 双向 TCP 无缺口、无冲突；
- 握手、认证和双向密钥交换均被观察；
- 服务端 MPPC 切换成立；
- type-34 业务包装层成立；
- `576`、`722` 和终止 `143(cursor=0)` 都存在；
- 通过 TCP 捕获顺序和保守 MPPC block 边界确认终止 `143` 晚于对应
  `576/722`；
- 标准衣柜与 DIY 衣柜解析无错误。

缺少任一条件时，结果为 `incomplete`，不会把未观察内容解释为未拥有。

## 顺序语义

当前轨迹按每个方向内的帧偏移保持原顺序，并按协议阶段做逻辑合并。为验证
跨方向完成关系，解析器保存 TCP 载荷的捕获序号，并把 MPPC 消息保守映射到
包含其末字节的完整压缩 block；只有捕获顺序更晚的 `143(cursor=0)` 才能完成
衣柜状态。该序号只证明先后，不代表精确时间戳，也不提供任意两帧之间的无损
逐包时间线。
