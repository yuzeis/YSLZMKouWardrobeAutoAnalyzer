# YSLZMKouWardrobeAutoAnalyzer

当前版本：`ver1.0-beta1`，版本代号：`Gnadenfülle`。

这是 Windows PC 版《以闪亮之名》的被动采集与微信导入码生成工具。程序只读取本机游戏流量，不抽卡、不注入或重放请求、不操作微信，也不上传数据。

界面中文统一使用宋体，英文、数字、路径和数据文本使用 Times New Roman，不使用 Emoji。

## 最小环境

- Windows 10/11
- Python 3.11 或更高版本，并包含 Tcl/Tk
- Npcap 系统驱动
- `YKARequirements.txt` 中的 Python 包

采集和协议解析都使用 Scapy。TShark、mergecap 和 Wireshark不是必需组件。正常启动 GUI 时会先显示 Windows UAC 并请求管理员权限，取消提权即退出。环境检查会检测 Npcap、Scapy、可用网卡和抓包权限；缺少 Scapy 或 Npcap 时可从界面确认后自动处理。Npcap 使用官方下载地址、验证 Windows Authenticode 签名，并显示官方安装界面和 UAC 确认，不执行静默安装。

源码运行：

```powershell
python -m pip install -r YKARequirements.txt
python YKAApp.py
```

也可以双击 `YKAStart.bat`。

正式发布的 Windows x64 单文件版本可直接运行
`YSLZMKouWardrobeAutoAnalyzer-ver1.0-beta1-windows-x64.exe`。Npcap 仍是系统级
抓包组件；如未安装，程序会在用户确认后打开官方安装流程。

管理员权限确认完成后，正常启动 GUI 会依次显示账号与法律风险、AGPL-3.0-only 开源许可、
官方永久免费与侵权处理三项声明。关闭任一窗口或点击“退出”都会在主界面和
环境检查创建前结束程序；三项全部点击“同意”后才进入主界面。发布验证使用的
`--smoke-test` 不显示这些交互窗口。

运行测试：

```powershell
python -m pytest -q -o python_files=YKATest*.py Test
```

## 使用流程

1. 在“采集与报告”页运行环境检查。
2. 点“开始采集”后再启动游戏；如果游戏已经联网运行，请保持采集并重启游戏，以便捕获完整连接和压缩边界。
3. 依次浏览卡池页面、抽卡记录、衣柜全部服装和背景页面。
4. 确认“游戏流量”变为“已抓到”。顶部四项阅览状态会在捕获数据变化后约两秒进行一次后台解析并自动更新。
5. “抽卡记录”表示服务器累计抽数快照已读取，不要求本次实际抽卡；本次采集期间的实际抽取结果会在最终报告中单独列出。
6. 点“停止并生成报告文件”，用停止后的完整解析结果覆盖实时报告。
7. 到“微信导入码”页生成完整导入数据。

每个会话位于 `%LOCALAPPDATA%\YKAAuto\sessions\<会话编号>`。抓包分段实时写入 `pcap` 子目录，`report.json` 随实时解析原子更新，停止后写入最终报告。生成微信导入码后，四种导出内容会写入 `wechat-export.json`；程序仅在最终报告和对应微信导出数据都确认落盘后清理该会话的 `.pcap`/`.pcapng` 文件，并保留报告、导出数据、日志和清理记录。

## 微信导入

生成器要求完整衣柜快照，并按冻结目录输出全部普通池和背景池，不只输出单个选项。所有已核验的小程序卡池服装槽位都会依据衣柜存在状态填写。DIY 定制服装实例不属于小程序卡池槽位，因此只参与衣柜完整性报告，不会伪造成普通池服装。可匹配的累计抽数来自服务端卡池快照；未观测或没有目录映射的池保留 `0`。备注为空，“想抽”不会自动填写。

输出包括：

- 原始 JSON
- 压缩原始 JSON（J1）
- C1 Base64
- C1 Base4096
- 可选择数据类型的二维码

“微信导入码”页右上角的“查看压缩协议”会在只读窗口中打开 `Docs/YKAProtocolSpec.md`。程序只生成数据，不执行小程序导入。

## 目录

- 根目录 `YKA*.py`：所有运行源码，平铺存放
- `YKAApp.py`：GUI 与采集子进程命令入口
- `YKACatalog.py`：游戏服装目录解析与冻结紧凑目录构建
- `YKACompactCodec.py`：C1 编解码、J1/T1/T2 文本传输与导入工件生成
- `YKAQR.py`：二维码校验和图像渲染
- `YKACore.py`：合并后的运行配置与 JSON/JSONL 基础读写
- `Test/YKATest*.py`：测试源码
- `DatAnDict/*.json`：冻结卡池目录、紧凑目录和注册表
- `Docs/*.md`：说明、通知和压缩协议
- `YKARequirements.txt`：运行依赖
- `YKARequirementsLock.txt`：本发行版实际使用的依赖版本
- `YKARequirementsBuildLock.txt`：本发行版测试和构建依赖版本
- `YKARequirementsDev.txt`：测试依赖
- `YKAStart.bat`：源码启动入口
- `Packaging/*.spec`：PyInstaller onefile 构建配置
- `RELEASE_NOTES.md`：当前版本发行说明
- `THIRD_PARTY_NOTICES.md`：第三方组件声明

## 构建

在 Windows x64 的隔离 Python 环境中安装锁定依赖，然后运行：

```powershell
python -m pip install -r YKARequirementsBuildLock.txt
python -m PyInstaller --noconfirm --clean Packaging\YSLZMKouWardrobeAutoAnalyzer.spec
```

构建产物必须执行冻结烟测；`--smoke-output` 用于在无控制台的 GUI 版本中
写出机器可读结果：

```powershell
YSLZMKouWardrobeAutoAnalyzer-ver1.0-beta1-windows-x64.exe `
  --smoke-test --smoke-output smoke.json
```

## 许可证与官方发布

本项目的自有源代码以 GNU Affero General Public License version 3 only
发布，SPDX 标识为 `AGPL-3.0-only`，完整条款见根目录 `LICENSE`。程序按
“原样”（AS IS）提供，不附带任何明示或默示担保。Scapy、qrcode、Pillow、
psutil、Npcap 等第三方组件仍适用各自许可证，不因本项目许可证而重新授权。

官方源码仓库：
`https://github.com/yuzeis/YSLZMKouWardrobeAutoAnalyzer`

本项目采用公开源代码的发布方式，官方发布版本绝对免费，不设置付费版、授权
码、会员、捐赠解锁或收费功能。正式向公众发布时，与程序版本对应的完整源代码
和 `LICENSE` 必须同步到上述官方仓库；仓库为空或缺少对应版本源码时不得发布。
AGPL-3.0-only 允许第三方依法收费传播副本或提供服务，此类行为不代表作者或
官方收费。如项目内容被确认侵犯第三方合法权利，维护者将在收到可核验的权利
通知后 12 小时内下架或删除相关内容或版本。

本 beta 版的根级 Python 模块不是稳定的外部 API。功能链合并后不保留旧模块名的转发文件；外部脚本应按上表当前模块导入。

源码包不包含真实会话、抓包或报告。
