# Windows onefile 构建

在项目根目录的 Windows x64 隔离环境中执行：

```powershell
python -m pip install -r YKARequirementsBuildLock.txt
python -m pytest -q -o python_files=YKATest*.py Test
python -m PyInstaller --noconfirm --clean Packaging\YSLZMKouWardrobeAutoAnalyzer.spec
dist\YSLZMKouWardrobeAutoAnalyzer-ver1.1-windows-x64.exe `
  --smoke-test --smoke-output dist\smoke.json
```

`smoke.json` 中应确认 `frozen=true`、目录资源为 true、二维码生成成功、
Scapy PCAP 往返成功且 Npcap 已就绪。
