# Simple Backup

给 Linux 服务器使用的多任务远程备份面板。每个任务可独立设置源服务器、SSH 密钥、远程路径、本地目录、备份周期、保留份数和并行线程数；备份在后台运行。

## 一键安装

在**保存备份的服务器**上用 root 执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/JohnMuyuan/Server-File-backuper/main/install.sh)
```

安装器会要求填写公网 IPv4、面板端口、用户名和密码，自动安装依赖、配置服务和防火墙，并通过 Let’s Encrypt 申请可自动续期的短期 IP HTTPS 证书。浏览器不会再出现自签名证书警告。

申请和续期证书时，公网 IPv4 必须直接指向这台服务器，且云安全组、防火墙和本机都要允许互联网访问 **TCP 80**。面板使用另外的自定义端口。TCP 80 被占用或处于 NAT/运营商封锁环境时，IP 证书无法签发，安装器会明确报错而不会退回不受信任证书。

非交互安装：

```bash
SB_NONINTERACTIVE=1 \
SB_PUBLIC_IP='203.0.113.10' \
SB_PANEL_USER='admin' \
SB_PANEL_PASSWORD='至少10位密码' \
SB_PANEL_PORT='8088' \
bash <(curl -Ls https://raw.githubusercontent.com/JohnMuyuan/Server-File-backuper/main/install.sh)
```

完成后访问 `https://公网IP:面板端口`，使用网页内的登录界面进入。

## 创建备份任务

1. 在备份服务器生成密钥：`ssh-keygen -t ed25519`。
2. 把公钥交给源服务器：`ssh-copy-id -p 22 root@源服务器IP`。
3. 在面板点击“新建任务”，填写源服务器、路径、周期等信息。
4. 保持“首次连接自动安装依赖”勾选，然后点击“立即备份”测试。

程序首次执行任务时会用已提供的 SSH 密钥登录源服务器，检查并安装 rsync 和 OpenSSH SFTP。SSH 用户必须是 root，或拥有免密 `sudo -n` 权限；否则会在面板和 Telegram 中给出失败原因。程序使用 `StrictHostKeyChecking=accept-new` 自动记录首次主机指纹。

默认 4 线程：多个文件可并行下载，大文件可分段下载；中断内容保存在每个任务自己的 `.partial-任务ID` 目录中，下次自动续传。线程数设为 1 时使用 rsync 兼容模式。

保留份数填 0 表示全部保留。设置为 10 时，在创建第 11 份之前先删除该任务最旧的一份。任务之间互不删除对方的备份。任一目标磁盘剩余空间低于 3 GB 时，程序会停止所有正在运行的备份、暂停新备份并发送 Telegram 通知。

## Telegram

在面板“设置”中填写 Bot Token 和 Chat ID。只有这个 Chat ID 可以控制任务：

```text
/tasks
/backup 任务ID
/stop 任务ID
/stop all
/status 任务ID
/list 任务ID
/delete 任务ID 备份文件名
```

只有一个任务时，部分命令可省略任务 ID。通知包含任务开始、成功、失败、容量不足和旧备份删除；成功通知包含备份文件名、大小、时间和剩余容量。

## 管理与支持范围

安装后执行 `simple-backup` 可查看状态、启动、停止、重启、修改面板账号/端口、更新、查看日志、重新申请 IP 证书或卸载。也可直接运行 `simple-backup update`。

安装器支持 apt、dnf、yum、zypper、pacman、apk，以及 systemd、OpenRC 和常见 SysV init。旧版单任务配置在升级后会自动迁移为第一个任务。卸载默认保留已有备份文件。
