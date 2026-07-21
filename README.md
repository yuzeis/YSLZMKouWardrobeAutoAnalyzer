# YSLZMKouWardrobeAutoAnalyzer

Windows PC 版《以闪亮之名》只读流量采集、衣柜分析与微信小程序导入数据生成工具。

- 版本：`ver1.0-beta1`
- 代号：`Gnadenfülle`
- 平台：Windows 10/11 x64
- 官方发行：完全免费、公开源代码

程序通过 Scapy 与 Npcap 被动读取本机游戏流量，不抽卡、不注入或重放请求、
不操作微信，也不上传数据。采集报告只保存在程序内存中；原始 PCAP 与会话证据
保存在本机 `%LOCALAPPDATA%\YKAAuto`。

## 使用

1. 下载并运行 Windows x64 单文件程序。
2. 在“采集与报告”页完成环境检查并开始采集。
3. 进入游戏，依次浏览卡池、抽卡记录、衣柜全部服装和背景页面。
4. 确认阅览状态后停止采集并生成内存报告。
5. 在“微信导入码”页生成全部衣服对应的导入数据或二维码。

完整环境、操作、协议和源码构建说明见
[Docs/YKAReadme.md](Docs/YKAReadme.md)。

## 许可证

本项目自有源代码以 `AGPL-3.0-only` 发布，完整条款见 [LICENSE](LICENSE)。
第三方组件信息见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
