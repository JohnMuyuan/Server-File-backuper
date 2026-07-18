# Simple Backup

给 Linux 服务器使用的可视化远程文件备份工具。通过网页填写“远程服务器、目录、每几天一次、保留几份”，后台用 SSH + rsync 自动备份。

## 安装

把本文件夹上传到**保存备份的服务器**，然后执行：

```sh
sudo sh install.sh
```

安装程序会显示随机管理密码，请保存。它支持 systemd、OpenRC 和常见 SysV init，并能通过 apt、dnf、yum、zypper、pacman 或 apk 安装依赖。

网页默认不会暴露到公网。在自己的电脑运行下面命令并保持窗口打开：

```sh
ssh -L 8088:127.0.0.1:8088 root@保存备份的服务器IP
```

浏览器打开 <http://127.0.0.1:8088>，用户名是 `admin`，密码是安装时显示的随机密码。

## 第一次设置

1. 在保存备份的服务器生成密钥：`ssh-keygen -t ed25519`。
2. 把公钥交给源服务器：`ssh-copy-id -p 22 root@源服务器IP`。
3. 先执行 `ssh root@源服务器IP`，确认能免密码登录并接受主机指纹。
4. 打开网页，填写源服务器地址、目录、周期和保留份数，勾选自动备份并保存。
5. 点“立即备份”测试。

每份完整备份在 `/var/backups/simple-backup/时间_服务器/`。`.partial` 是断点续传暂存目录，不要手动删除。磁盘剩余空间低于 3 GB 时会停止当前任务并暂停新任务，空间恢复后自动继续。

## Telegram

向 `@BotFather` 发送 `/newbot` 创建机器人，把 Token 填进网页；给机器人发一条消息，再访问 `https://api.telegram.org/bot你的Token/getUpdates`，从结果里找到 `chat.id` 填入网页。

支持命令：`/backup`、`/stop`、`/status`、`/list`、`/delete 备份名称`。只有设置中的 Chat ID 可以控制。

## 管理服务

systemd 系统：

```sh
systemctl status simple-backup
journalctl -u simple-backup -f
systemctl restart simple-backup
```

配置保存在 `/var/lib/simple-backup/config.json`。更新程序时重新执行 `sudo sh install.sh`，已有配置不会被覆盖。
