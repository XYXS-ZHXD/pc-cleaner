# PC清理助手 🧹

> 一个给电脑小白用的 Windows C盘垃圾清理工具。无广告、无后台、不联网，10MB 单文件即开即用。

[![Version](https://img.shields.io/badge/version-1.1.0-blue)](https://github.com)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)](https://github.com)

---

## 为什么写这个

修了十几年电脑，每天都有客户问：**"师傅，我C盘怎么又满了？"**

市面上的清理工具要么弹广告、要么推会员、要么扫不全。Windows 自带的磁盘清理倒是干净，但扫不到浏览器缓存、AppData 垃圾、软件残留。

干脆自己写一个。**给小白用的，不搞花活。**

---

## 功能

| 功能 | 说明 |
|------|------|
| 🔍 智能扫描 | 预定义20+高概率垃圾靶点，秒级出结果 |
| 🟢 安全清理 | 系统临时文件、浏览器缓存、Windows更新残留，默认全选，闭眼点就行 |
| 🟡 谨慎处理 | Windows.old、软件残留等，默认折叠隐藏，小白不用管 |
| 📊 C盘大文件夹TOP10 | 告诉你哪些文件夹占了C盘大头 |
| 🛡️ 白名单保护 | System32、WinSxS 等系统关键目录绝不触碰 |
| 🔄 重启清理 | 被占用的文件标记为开机自动删除，不硬删 |
| ♻️ 回收站机制 | 删错了能从回收站还原 |

---

## 下载

👉 [下载 PC清理助手.exe](https://github.com/REPLACE_WITH_YOUR_USERNAME/pc-cleaner/releases/latest)

或者到 [Releases](https://github.com/REPLACE_WITH_YOUR_USERNAME/pc-cleaner/releases) 页面下载最新版本。

---

## 使用

1. 下载 `PC清理助手.exe`
2. **右键 → 以管理员身份运行**（可选，提权后能清理更多系统垃圾）
3. 点「开始扫描 C 盘」
4. 绿色项目默认全选，点「清理选中项」
5. 完事。

---

## 从源码运行

```bash
# 需要 Python 3.8+
python pc_cleaner.py
```

---

## 打包

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "PC清理助手" --icon app_icon.ico --uac-admin pc_cleaner.py
```

---

## 安全说明

- ✅ 不联网、不上传任何数据
- ✅ 不开机自启、不留后台进程
- ✅ 不写注册表（除重启删除标记外）
- ✅ 文件删除到回收站，可还原
- ✅ 系统关键目录白名单保护

---

## 工作原理

### 三层删除策略

| 层级 | 策略 | 说明 |
|------|------|------|
| 第1层 | `os.remove()` | 直接删除 |
| 第2层 | `os.chmod` + 重试 | 去掉只读属性再删 |
| 第3层 | `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` | 标记开机删除 |

### 扫描靶点（部分）

- `%TEMP%` / `C:\Windows\Temp`
- `C:\Windows\Prefetch`
- `C:\Windows\SoftwareDistribution\Download`
- Chrome / Edge / Firefox 缓存目录
- Windows.old（系统回滚备份）
- 回收站

完整列表见源码中的 `SCAN_TARGETS`。

---

## 许可证

MIT License - 随便用，随便改，随便分发。

---

*Made with ❤️ by 一个修电脑的*
