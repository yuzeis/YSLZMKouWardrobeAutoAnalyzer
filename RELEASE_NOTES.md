# YSLZMKouWardrobeAutoAnalyzer ver1.0-beta1

版本代号：Gnadenfülle

这是首个公开 beta 版本。程序面向 Windows PC 版《以闪亮之名》，通过
Scapy 与 Npcap 被动读取本机游戏流量，生成衣柜与卡池数据报告以及微信小程序
导入内容。程序不抽卡、不注入或重放请求、不操作微信，也不上传数据。

## 本次更新

- 程序打开后会自动检查 Npcap、Scapy、可用网卡与抓包权限，并在界面中显示未通过的具体原因。
- 抓包启动失败时会直接提示缺少 Npcap、抓包权限不足、网卡不可用等实际诊断，不再只显示日志文件路径。
- 修复游戏静态目录格式变化后报告已生成、微信导入却失败的问题。
- 完整衣柜快照可依据内置冻结小程序目录保守匹配既有服装 ID。
- 原始微信导入 JSON 会先显示并落盘；后续压缩格式或二维码失败时仍可直接使用。
- 适配当前游戏 `data.png` 的新增前置表，完整衣柜将直接使用已核验的本机 Fashion v9/9530 与 FashionSuite v2/943 目录。

## 主要功能

- 自动检查 Npcap、Scapy、可用网卡和抓包权限。
- 实时提示卡池、抽卡记录、衣柜全部服装和背景页面是否已浏览。
- 读取可观测的累计抽数快照与卡池状态。
- 依据完整衣柜填写全部普通池、背景池和已核验服装槽位。
- 生成原始 JSON、J1、C1 Base64、C1 Base4096 与二维码。
- 启动即请求管理员权限，抓包与 `report.json` 实时写入会话目录。
- 最终报告与微信导出数据落盘后自动清理对应 PCAP。

## 使用要求

- Windows 10/11 x64。
- 安装并启用 Npcap；程序可在确认后打开官方安装流程。
- 开始采集后进入游戏，并依次浏览卡池、抽卡记录、衣柜全部服装和背景页面。

## 发行文件

- `YSLZMKouWardrobeAutoAnalyzer-ver1.0-beta1-windows-x64.exe`：Windows x64 单文件程序。
- `YSLZMKouWardrobeAutoAnalyzer-ver1.0-beta1-source.zip`：与标签对应的完整源码。
- `SHA256SUMS.txt`：发行文件 SHA-256 校验值。

完整说明见 `Docs/YKAReadme.md`。
