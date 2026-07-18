# Simple Backup

给 Linux 服务器使用的多任务远程备份面板。每个任务可独立设置源服务器、SSH 密钥或密码、远程路径、本地目录、备份周期、保留份数和并行线程数；备份在后台运行。

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

如果旧安装器错误地把面板设成了 80，运行 `simple-backup update` 会在 8088 空闲时自动迁移回 `https://公网IP:8088`。

## 创建备份任务

1. 推荐在备份服务器生成密钥：`ssh-keygen -t ed25519`，再用 `ssh-copy-id -p 22 root@源服务器IP` 交给源服务器。
2. 也可以在任务中选择“SSH 密码”并填写密码。
3. 填写源服务器、路径和周期，保持“首次连接自动安装依赖”勾选，然后点击“立即备份”测试。

程序首次执行任务时会用已提供的 SSH 密钥或密码登录源服务器，检查并安装 rsync 和 OpenSSH SFTP。SSH 用户必须是 root，或拥有免密 `sudo -n` 权限；否则会在面板和 Telegram 中给出失败原因。程序使用 `StrictHostKeyChecking=accept-new` 自动记录首次主机指纹。

默认 4 线程：多个文件可并行下载，大文件可分段下载；中断内容保存在每个任务自己的 `.partial-任务ID` 目录中，下次自动续传。线程数设为 1 时使用 rsync 兼容模式。

当前备份方式是把远程文件直接镜像到备份服务器，**不会先在源服务器生成压缩包，也不等同于文件系统快照**。这样不占用源服务器额外临时空间，并能保留多线程和断点续传；如果业务写入期间需要严格一致性，应先做数据库导出或文件系统快照，再让本项目备份导出目录。

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

面板只保存带随机盐的 PBKDF2 密码哈希，不保存面板明文密码；SSH 密码与普通任务配置分开保存在仅 root 可读的 `0600` 文件中，并通过环境变量而非命令行参数交给 `sshpass`。登录包含 HTTPS、安全 Cookie、CSRF 校验、每 IP 与账户级失败限速和失败日志。公网管理面板仍建议使用高强度随机密码，并在云防火墙中只允许可信 IP 访问面板端口。

安装器支持 apt、dnf、yum、zypper、pacman、apk，以及 systemd、OpenRC 和常见 SysV init。旧版单任务配置在升级后会自动迁移为第一个任务。卸载默认保留已有备份文件。
