# YSLZM 紧凑导入码协议规范

**版本**：v1.2-draft
**头部布局版本**：H1
**日期**：2026-07-20
**状态**：Python 参考实现已完成。v1.2 在 v1.1 的 C1 基础上增加累计抽数 codec、J1 压缩原始 JSON 和本地二维码输出。

本文档使用规范性关键词：**必须**（MUST）、**禁止**（MUST NOT）、**应当**（SHOULD）、**可以**（MAY）。标注 *informative* 的内容不构成一致性要求。

---

## 1. 适用范围与术语

本协议定义《以闪亮之名》微信小程序卡池导入数据的紧凑二进制表示、传输编码与无损重建规则。

| 术语 | 含义 |
|---|---|
| catalog | 静态版本字典：一份不可变的卡池、槽位、坐标与 schema 快照 |
| catalog_id | catalog 快照的唯一 8 位十进制编号（§3.3 统一版本号方案） |
| payload | C1 编码出的压缩正文字节序列 |
| wire | 9-byte 强制头 ‖ payload |
| P | catalog 中普通卡池数量 |
| R | catalog 状态码基数（合法状态为 `0 .. R-1`） |
| B | catalog 背景条目数量 |
| n | 某池的已核验槽位数量 |
| k | 某池当前拥有的槽位数量 |
| C(n, k) | 二项式系数 |

所有多字节整数**必须**采用大端序。所有位流**必须**采用 MSB-first。

---

## 2. 分层模型

```text
+--------------------------------------------------+
| 传输层  J1 / T1 Base64 / T2 Base4096            |
+--------------------------------------------------+
| Wire 层  9-byte 强制头 + payload                 |
+--------------------------------------------------+
| Codec 层  C1（codec 0 / 1 / 2 / 3）              |
+--------------------------------------------------+
| Catalog 层  静态字典（不在 wire 中传输）         |
+--------------------------------------------------+
```

设计不变量：

1. 版本内稳定的信息（池顺序、槽位、坐标几何、schema、状态码表）全部归属 catalog，**禁止**在 wire 中重复出现。
2. wire 只承载动态熵：图片宽度覆盖、逐池状态、逐池槽位拥有集合、（可选）累计抽数与背景位图。
3. 任何 wire **必须**自带 catalog_id 与 CRC-32；**禁止**发行不带强制头的 wire。
4. C1 为精确枚举编码：对任意合法输入零失真，对任意状态分布均可编码，不依赖概率参数与跨用户数据。

---

## 3. Catalog 规范

### 3.1 内容

每个 catalog 包**必须**至少包含：

```text
catalog_id                8 位十进制编号
content_sha256            catalog 全部内容的 SHA-256
pool 列表                 固定顺序的池 key 序列（数量 = P）
每池槽位表                verified 槽位的固定顺序与中心坐标（数量 = n）
default_width             默认图片显示宽度
coordinate_rule_version   坐标整数换算规则版本
status schema             状态码基数 R 与各状态含义
background 列表           固定顺序的背景 key 序列（数量 = B，可为 0）
坐标测试向量              见 §12
```

### 3.2 catalog_id 语义

catalog_id 标识**完整静态字典快照**。以下任一内容变化都**必须**分配新的 catalog_id：

```text
pool 数量、key 或顺序
任何池的槽位数量 n（含 n 从 0 变为正数）
槽位顺序或坐标几何
默认宽度
坐标整数换算规则
状态码基数或含义
背景列表
生成器 schema
```

解码规则：catalog_id 已知时只能使用该 ID 对应的精确字典；未知时**必须**硬失败或请求下载；**禁止**回退到相近版本或最新版本；catalog_id **禁止**重复分配。

### 3.3 统一版本号方案

catalog_id 与游戏版本号统一编号，由维护者手工分配。8 位十进制**必须**按以下结构解释：

```text
GGGGGG RR
GGGGGG：6 位游戏版本段（映射规则由维护者定义并保持单调递增）
RR：    2 位修订号，00 .. 99
```

规则：

1. 每个游戏版本（新增服装字典）分配新的 GGGGGG，修订号从 00 起。
2. **同一游戏版本内的任何 catalog 内容修正**（坐标勘误、n 由 0 核验为正、key 修正等）**必须**递增 RR，**禁止**复用旧编号改内容。
3. §3.2 的快照唯一性优先于版本号语义：显示上 RR 可以对用户隐藏，但 wire 中始终是完整 8 位。
4. RR 用尽（超过 99 次修订）时**必须**分配新的 GGGGGG。

*informative*：游戏每个版本必然新增服装，因此 GGGGGG 与游戏版本一一对应；RR 的存在是因为槽位核验是渐进的，字典修正不会恰好落在游戏版本边界上。

### 3.4 发布规则

1. 注册表（维护者仓库）**必须**保存每个 catalog_id 的 content_sha256，构建流程**必须**校验编号未被使用。
2. 已发布 catalog **必须**保持只读；**禁止**覆盖旧 ID。
3. Rust 与 JS 端加载同一 catalog **必须**得到相同 content_sha256。
4. 存储预算应当优先用于保留全部历史 catalog。

---

## 4. Wire 格式

### 4.1 强制头（9 bytes，全字节对齐）

```text
+--------+----------------------------+----------------------+
| 偏移   | 字段                       | 说明                 |
+--------+----------------------------+----------------------+
| 0..3   | catalog_id（32-bit BCD）   | 8 个十进制 nibble    |
| 4      | codec_id（8-bit）          | 见 §4.3              |
| 5..8   | crc32（大端）              | 见 §5                |
| 9..    | payload                    | 见 §6–§9             |
+--------+----------------------------+----------------------+
```

### 4.2 catalog_id 编码

8 位十进制数字按高位在前依次占用 nibble：最高位数字位于 byte 0 的高 4 bits。每个 nibble **必须**在 `0x0 .. 0x9`；出现 `0xA .. 0xF` 时解码器**必须**立即失败。

### 4.3 codec_id 分配

| codec_id | 含义 |
|---:|---|
| 0 | C1（累计抽数全为 0，不含背景段） |
| 1 | C1 + 背景位图（累计抽数全为 0） |
| 2 | C1 + 累计抽数（不含背景段） |
| 3 | C1 + 累计抽数 + 背景位图 |
| 4 .. 254 | 保留，解码器**必须**拒绝 |
| 255 | 扩展逃逸：payload 前 2 bytes 为扩展 codec 编号；当前**必须**拒绝 |

输入包含至少一个正抽数时**必须**使用 codec 2 或 3，否则**必须**使用 codec 0 或 1。输入包含背景段时**必须**使用奇数 codec，否则**必须**使用偶数 codec。同一 wire **禁止**部分背景。codec 2 / 3 的非零池数量必须大于 0，借此保证唯一表示。

payload 内**禁止**出现方案选择位、schema 版本、坐标规则版本、payload 长度字段或内部 magic。payload 字节长度恒等于 wire 总长减 9。

### 4.4 语义解耦

C1 的状态编码与三态模式**必须**保持无耦合：**禁止**任何基于“某状态必然蕴含 ALL”之类游戏语义的字段省略。此类优化只能定义为新的 codec_id，且蕴含关系**必须**写入对应 catalog。

---

## 5. CRC-32 定义

采用标准 CRC-32/ISO-HDLC，参数**必须**为：

```text
polynomial : 0x04C11DB7（反射形式 0xEDB88320）
init       : 0xFFFFFFFF
refin      : true
refout     : true
xorout     : 0xFFFFFFFF
check("123456789") = 0xCBF43926
```

CRC 输入**必须**为：

```text
CRC_INPUT = ASCII("YSLZM-WIRE-H1")
         || wire bytes 0..4        （catalog_id 与 codec_id）
         || payload bytes
```

crc32 字段本身不参与计算。域分隔串中的 `H1` 指头部布局版本，仅当 §4.1 布局变化时递增。

所有实现**必须**通过 check 值与共享测试向量的双端一致性验证。

*informative*：CRC-32 对随机损坏的平均漏检概率约 2.33 × 10⁻¹⁰。CRC 只检测意外损坏，不提供抗恶意篡改能力。

---

## 6. Payload 通用位流规则

1. payload 为单一连续位流，MSB-first；结束时不足 8 bits 处在右侧补 0 至字节边界。
2. 补位**必须**全为 0；解码器**必须**校验。
3. 解码**必须**恰好消费完全部定义字段后仅剩补位；剩余非补位数据**必须**拒绝。
4. 补位长度不单独保存：全部字段宽度由 catalog 与已解码内容确定。

### 6.1 truncated binary（精确均匀码）

对取值范围 `0 <= v < N`：

```python
def write_truncated(v, N):
    if N <= 1:
        return
    b = floor_log2(N)
    threshold = (1 << (b + 1)) - N
    if v < threshold:
        write_bits(v, b)
    else:
        write_bits(v + threshold, b + 1)

def read_truncated(N):
    if N <= 1:
        return 0
    b = floor_log2(N)
    threshold = (1 << (b + 1)) - N
    prefix = read_bits(b)
    if prefix < threshold:
        return prefix
    suffix = read_bits(1)
    return ((prefix << 1) | suffix) - threshold
```

`N = 1` 时字段占 0 bits。

### 6.2 组合排名（字典序）

```python
def rank_combination(n, k, selected):
    rank = 0
    previous = -1
    for j, current in enumerate(selected):
        for candidate in range(previous + 1, current):
            rank += C(n - candidate - 1, k - j - 1)
        previous = current
    return rank

def unrank_combination(n, k, rank):
    selected = []
    previous = -1
    for j in range(k):
        for candidate in range(previous + 1, n):
            count = C(n - candidate - 1, k - j - 1)
            if rank < count:
                selected.append(candidate)
                previous = candidate
                break
            rank -= count
    return selected
```

---

## 7. C1 Payload 布局

```text
width_override      1 bit
width_offset        override = 1 时：11 bits
histogram_rank      truncated(h, C(P + R - 1, R - 1))
sequence_rank       truncated(q, Nseq)
subset 流           §9
draw 流             仅 codec 2 / 3：§10.1
background 位图     仅 codec 1 / 3：§10.2
补齐                §6
```

### 7.1 宽度

`width_override = 0` 时宽度取 catalog default_width。`= 1` 时：

```text
width_offset = target_width - 120
合法范围 0 .. 1080（即宽度 120 .. 1200）
```

offset 超出 1080 **必须**拒绝。若 override 后的宽度恰好等于 default_width，该表示非规范，**必须**拒绝（唯一表示原则）。

---

## 8. 状态编码（枚举排名）

### 8.1 直方图排名

按 catalog 池顺序取状态 `s0 .. s(P-1)`，每项**必须**在 `0 .. R-1`。统计直方图 `c = (c0, .., c(R-1))`，`Σci = P`。全部组成数量为 `C(P + R - 1, R - 1)`，按向量字典序排名：

```python
def rank_histogram(c, P, R):
    rank = 0
    remaining = P
    for i in range(R - 1):
        for v in range(c[i]):
            rank += C(remaining - v + R - i - 2, R - i - 2)
        remaining -= c[i]
    return rank
```

反排名按同序贪心恢复。

### 8.2 序列排名

给定直方图后的有效序列数：

```text
Nseq = P! / Π ci!
```

按多重集字典序排名（大整数运算）：

```python
def rank_sequence(statuses, c):
    counts = c.copy()
    total = len(statuses)
    rank = 0
    for s in statuses:
        for u in range(s):
            if counts[u] > 0:
                counts[u] -= 1
                rank += perms(counts, total - 1)   # (total-1)! / Π counts[i]!
                counts[u] += 1
        counts[s] -= 1
        total -= 1
    return rank
```

`Nseq = 1` 时字段占 0 bits。解码后**必须**验证直方图各计数恰好归零。

*informative*：该编码达到多重集熵下界（上取整），对任何分布无损；相对均匀 Base-R 假设，状态偏斜越强收益越大。

---

## 9. 槽位子集流

对每个 `n > 0` 的池（catalog 顺序），设拥有槽位索引集合 `A`（升序）、`k = len(A)`。`n = 0` 的池不产生任何位。

### 9.1 三态前缀

```text
00  NONE   k = 0
01  ALL    k = n
1   MIXED  1 <= k <= n - 1，随后接 §9.2 正文
```

读取规则：读到 `1` 即 MIXED；读到 `0` 再读一位，`0` 为 NONE，`1` 为 ALL。

### 9.2 MIXED 正文

先写 1-bit 表示法标签：

```text
0  COMB：truncated(k - 1, n - 1) ‖ truncated(rank_combination(n, k, A), C(n, k))
1  RAW： n-bit 位图（bit i = 是否拥有槽位 i，MSB 为槽位 0）
```

规则：

1. RAW 位图**禁止**为全 0 或全 1（那是 NONE / ALL 的职责）。
2. 编码器**必须**逐池选择正文更短的表示；长度相等时**必须**选 COMB。
3. 解码器通过 §13 的重编码比较拒绝违反择短与平局规则的输入。

---

## 10. 累计抽数与背景

### 10.1 累计抽数（codec 2 / 3）

设 `d[i]` 为普通池 `i` 的累计抽数，必须是 `0 .. 9007199254740991` 的整数。令非零索引升序列表为 `D`，`m = len(D)`。编码顺序为：

```text
truncated(m, P + 1)
truncated(rank_combination(P, m, D), C(P, m))
对 D 中每个索引，按顺序写入 gamma(d[i])
```

正整数 `v` 的 Elias gamma 编码为 `floor(log2(v))` 个 `0`，随后写 `v` 的完整二进制表示。解码器必须拒绝超过 JavaScript 安全整数上限的结果。codec 2 / 3 中 `m = 0` 属于非规范表示，必须通过重编码比较拒绝。codec 0 / 1 不含本段，全部累计抽数重建为 `0`。

### 10.2 背景位图（codec 1 / 3）

在抽数段之后（若有）、补齐之前追加 `B` bits：

```text
bit i = catalog 背景顺序第 i 项的状态（0 / 1）
```

---

## 11. Canonical JSON

### 11.1 无损保证的定义

协议保证为**语义无损 + canonical 重建**：解码输出唯一的规范 JSON 序列化，不承诺复读任意非规范输入字节。参考编码器只接受规范输入；其他实现可以先规范化，但写入 wire 前必须得到同一规范 JSON。

### 11.2 序列化规则

1. 顶层为单行 JSON 数组，UTF-8，无任何多余空白。
2. 普通池行按 catalog 池顺序排列，结构二选一：

```json
["poolKey",drawCount,status]
["poolKey",drawCount,status,"",[x1,y1,x2,y2,...]]
```

3. 无拥有槽位时**必须**使用三元素形式；有拥有槽位时**必须**使用五元素形式，第 4 项固定为空串。`drawCount` 必须是 `0 .. 9007199254740991` 的整数；codec 0 / 1 中必须为 0。
4. 坐标数组为拥有槽位按 catalog 槽位顺序的 (x, y) 平铺序列，长度必为偶数，值由 §12 规则从宽度计算。
5. 整数使用最短十进制表示，无前导零、无正号。
6. 背景行（codec 1 / 3）按 catalog 背景顺序追加于池行之后，结构为 `["bgKey",v]`，v ∈ {0, 1}。
7. 未知字段按当前 codec 版本规则拒绝或规范化，**禁止**静默透传。

上游 schema 增删字段时**必须**通过新 codec_id（必要时配合新 catalog_id）承载，已发布 codec 语法不变。

---

## 12. 坐标确定性

1. 坐标换算算法**必须**只使用整数运算；**禁止**浮点参与。
2. 算法、默认宽度与槽位几何全部由 catalog_id 承载，wire 成本为 0。
3. 每个 catalog **必须**附带跨平台测试向量：

```text
宽度 120、1200 及若干中间值
每个宽度下全部槽位坐标序列的 SHA-256
边界舍入样本
```

4. Rust 与 JS 实现**必须**对全部向量逐项一致后方可发布。

---

## 13. 规范解码流程

解码器**必须**严格按以下顺序执行：

```text
 1. 传输层自动识别并解码（§14），得到精确的 wire 字节序列
 2. 要求 wire 长度 >= 9
 3. 读取并校验 8 个 BCD nibble
 4. 读取 codec_id；不在 {0, 1, 2, 3} 内则失败
 5. 提取 crc32
 6. 按 §5 重算 CRC；不符立即失败
 7. 以 catalog_id 精确查找 catalog
 8. 未找到则硬失败或提示下载；禁止回退
 9. 按 §7–§10 解码 payload，执行全部规范性校验
10. 用解码结果重新编码，与输入 wire 逐字节比较；不符则拒绝
11. 输出 canonical JSON（§11）
```

CRC 先于查字典与 payload 解析，用于区分“数据损坏”与“本机缺少字典”。

### 13.1 必须拒绝清单

```text
BCD nibble 含 0xA..0xF
codec_id 不在 {0, 1, 2, 3}
CRC 不符
catalog_id 未注册
width_offset 越界，或 override 值等于 default_width
histogram_rank >= C(P + R - 1, R - 1)
sequence_rank >= Nseq
直方图计数未归零
MIXED 的 k = 0、k = n，或组合排名 >= C(n, k)
RAW 位图全 0 或全 1
违反 RAW / COMB 择短或平局规则
抽数非零索引排名越界，gamma 提前耗尽或抽数超过安全整数
codec 2 / 3 的非零抽数池数量为 0
位流提前耗尽或存在多余数据
补位非 0
重编码与输入不一致
传输层非规范输入（§14 各条）
```

---

## 14. 传输编码

定义两种 C1 文本传输形式，以及一种原始 JSON 压缩封装。当前桌面程序只负责生成、复制和保存，不负责修改小程序。

### 14.0 自动识别

对输入（UI **可以**先剥离首尾空白，之后**禁止**再容忍任何空白）：

```text
首个 Unicode 标量在 U+4E00 .. U+5DFF  -> T2
首个字符在 Base64 字母表 [A-Za-z0-9+/] -> T1
其他                                   -> 拒绝
```

### 14.1 T1：Base64

RFC 4648 §4，含 `=` 填充，**禁止**换行与内部空白。填充使字节长度精确可逆。

### 14.2 T2：Base4096-Han-v1

字表 `U+4E00 .. U+5DFF` 共 4096 码点，12 bits / 码元，MSB-first，尾部右侧补 0。

由于码元数对应的字节长度可能存在两个整数候选，T2 **必须**使用结束哨兵：

```text
编码：payload' = wire ‖ 0x80，再做 Base4096
解码：
  1. 正文每字符必须在 U+4E00..U+5DFF；禁止兼容汉字、变体选择符、内部空白
  2. 按 12-bit 恢复位流；被丢弃的尾部 bit 必须全为 0
  3. 最后一个非零字节必须是 0x80；删除之得到 wire
  4. 重新编码必须逐字符相同
  5. 必须恰好存在一个满足全部条件的长度候选
```

*informative*：T2 可见字符约为 T1 的一半，适合作为默认展示形式；T1 适合纯 ASCII 环境与调试。二者承载同一 wire，互相可无损转换。

### 14.3 J1：压缩原始 JSON

J1 不承载 C1 wire，而是封装 §11 的规范 JSON UTF-8 字节。格式为：

```text
J1:<十进制 UTF-8 字节数>:<8 位大写 CRC32>:<Base45(raw-DEFLATE(JSON))>
```

DEFLATE 必须使用 zlib level 9、无 zlib/gzip 外壳的原始数据流。Base45 使用 RFC 9285 字表。解码器必须校验声明长度、CRC32、DEFLATE 完整结束且无尾随数据，并重新编码逐字符比较。解压后的 JSON 必须是规范单行数组。

### 14.4 二维码输出

二维码数据类型只允许 J1、T1、T2，不允许原始 JSON。二维码必须为纯黑白、至少 4 模块静区、不叠加图标。参考实现优先选择不高于版本 20 的最强纠错级别；三者均超过版本 20 时，选择版本号最低的可容纳候选。高密度码应支持原尺寸保存和全屏显示。

---

## 15. 一致性要求

1. **解码器**：必须支持 codec 0 / 1 / 2 / 3、J1、T1 与 T2；必须实现 §13 全部步骤与 §13.1 全部拒绝项。
2. **编码器**：必须实现 §7–§10 全部规则，只输出 canonical 表示；同一输入在任何平台**必须**产生逐字节相同的 wire。
3. **部署门槛**：C1 在通过 §16 测试集之前**禁止**发布。

---

## 16. 测试要求

### 16.1 参考 oracle

已完成逐字节往返验证的 C0 Legacy 实现（含其 216-byte 真实样本结果）**必须**保留为内部测试 oracle：C1 与 C0 共享 catalog、坐标换算与子集语义，两者对同一输入解出的语义内容**必须**一致。C0 Legacy 不是 wire codec，不出现在 codec_id 表中。

### 16.2 测试集

每个实现发布前**必须**通过：

```text
当前真实导入码：C1 wire 往返，抽数、状态、槽位和背景逐项一致
全部 NONE / 全部 ALL / 单个 MIXED
所有状态相同 / R 个状态尽量均衡 / 每状态恰出现一次
k = 1、k = n - 1、k = n / 2
RAW 与 COMB 各自胜出的样本、二者等长的平局样本
width_override 两个分支，含 override 值 = default_width 的拒绝样本
背景位图全 0、全 1、混合（codec 1）
抽数全 0、单个非零、多个非零、最大安全整数及 codec 2 / 3
wire 每一个 bit 位置的单 bit 翻转均被拒绝
CRC check 值与跨端 CRC 向量
坐标测试向量双端一致（§12）
BCD 非法 nibble、未知 codec、未知 catalog 的拒绝路径
J1 / T1 / T2 全部非规范输入的拒绝路径
随机样本与大整数参考实现差分
Rust 与 JS 对同一输入的 wire 逐字节比对
```

---

## 附录 A（informative）：当前 catalog 参数与长度估算

当前 catalog 参数：catalog_id = `00000100`，P = 199，R = 11，B = 126，default_width = 261，已核验槽位 = 1571。

| 项 | payload | wire（+9B 头） | T1 Base64 | T2 码元（含哨兵） |
|---|---:|---:|---:|---:|
| 当前账号实测（codec 3） | 394 B | 403 B | 540 | 270 |

同一样本的规范原始 JSON 为 9488 UTF-8 bytes；J1 为 3550 个字符。以上实测只作为尺寸基线，不属于协议固定测试向量。

对语义编码后的 payload 追加通用压缩器（gzip / zstd / Brotli）无收益，实测均反而变长。

## 附录 B（informative）：v1.1 相对 v1.0 的变更

1. codec 层收敛为单一 C1：删除 wire 层的 C0 Legacy / C0 Hybrid 与编码器多方案择短；codec_id 重编号为 0（C1）与 1（C1 + 背景）。C0 Legacy 降级为内部测试 oracle（§16.1）。
2. catalog_id 采用统一版本号方案：6 位游戏版本段 + 2 位修订号；修订号承接同一游戏版本内的字典勘误与渐进核验，保住快照唯一性。
3. 传输层收敛为 T1 / T2 并新增首字符自动识别；删除 T3 JIA2 envelope（其 `0x80` 哨兵规则保留于 T2）。
4. 宽度覆盖并入 C1 payload，默认宽度由 catalog 承载；override 值等于默认宽度列为非规范。

## 附录 C（informative）：v1.2 相对 v1.1 的变更

1. 分配 codec 2 / 3，完整承载普通池累计抽数；codec 0 / 1 保持原语法。
2. 增加 J1 压缩原始 JSON，供不依赖 catalog 的本地保存和二维码输出。
3. 规定二维码只承载 J1 / T1 / T2，不保留原始 JSON 选项。
4. 记录 Python 参考实现目录 `00000100` 与当前真实样本尺寸基线。
