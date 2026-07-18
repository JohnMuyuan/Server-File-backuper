# Simple Backup

给 Linux 服务器使用的可视化远程文件备份工具。网页填写远程服务器、目录、备份周期和保留份数，后台通过 SSH 自动备份。

## 一键安装

在**保存备份的服务器**上用 root 执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/JohnMuyuan/Server-File-backuper/main/install.sh)
```

安装程序会询问公网 HTTPS 端口、管理用户名和管理密码，自动安装依赖、生成自签名 HTTPS 证书、配置开机启动，并为正在使用的 UFW 或 firewalld 开放端口。非交互安装可使用：

```bash
SB_NONINTERACTIVE=1 SB_PANEL_USER=admin SB_PANEL_PASSWORD='至少10位密码' SB_PANEL_PORT=8088 bash <(curl -Ls https://raw.githubusercontent.com/JohnMuyuan/Server-File-backuper/main/install.sh)
```

完成后访问 `https://服务器公网IP:端口`。自签名证书第一次会触发浏览器警告，确认继续访问即可；连接仍经过 HTTPS 加密。云服务器还需要在厂商安全组中放行相同的 TCP 端口。

## 第一次设置

1. 在保存备份的服务器执行 `ssh-keygen -t ed25519`。
2. 执行 `ssh-copy-id -p 22 root@源服务器IP` 把公钥交给源服务器。
3. 执行一次 `ssh root@源服务器IP`，确认免密码登录并接受主机指纹。
4. 打开网页填写源服务器地址、目录、周期、保留份数和线程数，勾选自动备份并保存。
5. 点击“立即备份”测试。

默认使用 4 线程：多个文件并行下载，单个大文件也会分段下载；中断后会保留续传状态。远端 SFTP 不兼容时，把线程数改为 `1`，程序会使用 rsync 兼容模式。

每份完整备份位于 `/var/backups/simple-backup/时间_服务器/`，`.partial` 是断点续传暂存目录。磁盘剩余空间低于 3 GB 时会停止当前任务并暂停新任务，空间恢复后自动继续。

## 管理菜单

安装后执行：

```bash
simple-backup
```

菜单支持查看状态、启动、停止、重启、修改管理账号/密码/端口、更新、查看日志、重建 HTTPS 证书和卸载。也可直接执行 `simple-backup update`、`simple-backup status` 或 `simple-backup logs`。

卸载默认只删除程序，不删除已有备份；面板配置和证书会再次询问是否删除。

## Telegram

向 `@BotFather` 发送 `/newbot` 创建机器人，把 Token 填进网页；给机器人发一条消息，再访问 `https://api.telegram.org/bot你的Token/getUpdates`，从结果中找到 `chat.id` 填入网页。

支持命令：`/backup`、`/stop`、`/status`、`/list`、`/delete 备份名称`。只有设置中的 Chat ID 可以控制。

## 支持范围

安装器支持 apt、dnf、yum、zypper、pacman、apk，以及 systemd、OpenRC 和常见 SysV init。需要源服务器提供 SSH/SFTP 服务。
