# ESurfingDialer-Pro

天翼校园网自动认证 —— 双击一下，再也不用管。

## 文件说明（你就看前两个）

| 文件 | 干嘛的 |
|------|--------|
| **`setup.bat`** | 🔰 **第一次用就双击这个** — 输入学号密码，自动装依赖、存配置、可选开机自启 |
| **`start.bat`** | ▶️ 手动启动守护进程（有窗口，能看到实时状态） |
| `start_hidden.vbs` | 👻 后台静默启动，`setup.bat` 装开机自启时用的就是它 |
| `uninstall_autostart.bat` | ❌ 取消开机自启 |
| `安装Python指南.txt` | 🐍 新手装 Python 的图文教程，`setup.bat` 没检测到 Python 会自动弹出来 |
| `requirements.txt` | Python 依赖列表（`setup.bat` 会自动装，你不用管） |
| `esurfing_pro/` | 📁 代码文件夹，不用打开 |

## 前置要求

**Python 3.9 或以上**（3.9 / 3.10 / 3.11 / 3.12 / 3.13 都行）。

**没装 Python？点这里下载：👇**

> 🔗 **[https://www.python.org/downloads/](https://www.python.org/downloads/)**
>
> 用 Edge 浏览器打开 → 点黄色大按钮下载 → 安装时
> **一定要勾选 ☑ Add Python to PATH**！！！

> ⚠️ **不要用 Microsoft Store 安装 Python！！！Store 版功能残缺，跑不了这个脚本。必须用上面官网地址下载。**

> ⚠️ Python 3.8 及以下版本会报语法错误。查看版本：Win+R 输入 `cmd`，输入 `python --version`

## 怎么用

```
第一步：双击 setup.bat
        → 如果报错会提示缺什么，不会乱码了
        → 输入学号
        → 输入密码
        → 回车回车回车
        → 完事。

之后每次开机，它自动在后台帮你连校园网。
```

## 常见问题

**怎么知道它在跑？**
- 看任务栏右下角托盘，或者任务管理器里找 `python` 进程（占用 ~30MB）

**怎么停掉？**
- 任务管理器结束 python 进程，或者重启电脑后不自动启（运行 `uninstall_autostart.bat`）

**换密码了怎么办？**
- 重新双击 `setup.bat` 输一遍新密码就行

**打游戏影响吗？**
- 不影响。占用 30MB 内存、0% CPU，每 10 秒才发一个几字节的小请求

## 致谢

本项目基于 [Rsplwe/ESurfingDialer](https://github.com/Rsplwe/ESurfingDialer) 开发，感谢原作者的开源贡献。

## 联系

有问题或建议请联系：**easonmalone@hotmail.com**
