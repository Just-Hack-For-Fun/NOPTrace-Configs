## 简介

大家好，我们是 NOP Team

这段时间，我们相继推出了 **OpenForensicRules**、**NOPTrace-Configurator**、**NOPTrace-Collector** 

简单介绍一下它们的作用

- **OpenForensicRules** 是一套标准化的数字取证与应急响应信息采集规则格式规范。
- **NOPTrace-Configurator** 是 **OpenForensicRules** 的图形化配置工具，同时可以检查用户配置是否规范
- **NOPTrace-Collector**  是基于 **OpenForensicRules**  的采集器，用户可以使用它进行定制化信息采集



 **NOPTrace-Configs** 项目是符合 **OpenForensicRules** 规范的电子取证与应急响应配置集合
该项目的目的是当出现应急响应事件时，受害方能够第一时间采集重要信息，即使后续恢复系统或者排查破坏了痕迹，也能够留一份证据，供后续应急响应人员以及相关人员分析回溯


**OpenForensicRules**  项目中也会同步该项目的配置文件



## 配置文件说明

在发布 **NOPTrace-Collector**  时，我们曾发出提醒，大家一定要了解程序要加载的配置文件，因为采集器是可以执行系统命令的，所以下面展示并简述每一个配置文件的内容，其中 `SensitiveDirs.yaml` 、 `Log.yaml`、`Integrity.yaml` 要着重考虑是否加载

 **NOPTrace-Configs** 项目 Linux 版已覆盖绝对多数 《Linux 应急响应手册》 中的常规安全检查部分内容

![](http://mweb-tc.oss-cn-beijing.aliyuncs.com/2025-07-08-101718.jpg)

![](http://mweb-tc.oss-cn-beijing.aliyuncs.com/2025-07-08-101644.png)



## Account.yaml

```yaml
name: 'LinuxAccounts'
doc: 'Linux 平台用户相关内容，其中 /etc/passwd 文件可能包含恶意用户或额外配置了密码，用于权限维持'
version: '0.0.1'
sources:
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/passwd'
author: 'NOPTeam'
```

采集 Linux 账户相关信息，用于发现异常账户



## Alias.yaml

```yaml
name: LinuxAlias
doc: |-
  Linux 平台上 alias 信息收集。
  alias 是用于设置别名的命令，可被利用来进行权限维持。
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Linux
    attributes:
      cmd: alias
      args: []
urls:
  - https://mp.weixin.qq.com/s/yXY8opNctHK5d9tXhQj35w
```

采集 Linux 平台上用户的 alias 设置，主要是排查 alias 后门。



## ASLR.yaml

```yaml
name: 'LinuxASLR'
doc: "Linux 平台上ASLR 是一项 Linux 系统的保护措施，将某些地址空间进行随机化，减缓一些溢出攻击。\n\n此处文件内容含义如下：\n0 - 表示关闭进程地址空间随机化。\n1 - 表示将mmap的基址，stack和vdso页面随机化\n2 - 表示在1的基础上增加堆（heap）的随机化"
version: '0.0.1'
sources:
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/proc/sys/kernel/randomize_va_space'
        - '/etc/sysctl.conf'
author: 'NOPTeam'
```

采集 Linux 平台上 ASLR 配置。



## Bash.yaml

```yaml
name: 'LinuxBashBuiltIn'
doc: 'Linux 平台上 Bash 内置的函数以及命令信息'
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'compgen'
      args:
        - '-b'
urls:
  - 'https://www.cnblogs.com/zhiminyu/p/14388997.html'
author: 'NOPTeam'
```

采集 Linux 平台上 Bash 相关信息，目前只采集内置命令。



## Capabilities.yaml

```yaml
name: 'LinuxCapabilities'
doc: 'Linux 平台上 capabilities 是一种对 Linux 权限更严格划分和管控的规范，设置得当可以有效防止过度授权造成提权操作'
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'getcap'
      args:
        - '-r'
        - '/'
        - '2>/dev/null'
author: 'NOPTeam'
```

采集 Linux 平台上 capabilities 权限信息。



## CrontabFile.yaml

```yaml
name: 'LinuxCrontab'
doc: 'Linux 计划任务程序，包括所有可能的文件'
version: '0.0.1'
sources:
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/crontab'
        - '/etc/anacrontab'
  - type: 'PATH'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/cron.d/'
        - '/var/spool/cron/'
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/var/log/cron'
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'journalctl'
      args:
        - '-u'
        - 'crond'
urls:
  - 'https://mp.weixin.qq.com/s/snJ80-Aiy9-XfFvJw380vg'
author: 'NOPTeam'

---

name: 'LinuxAt'
doc: 'Linux 平台中 at 用于安排只执行一次的定时任务（在指定的将来某个时间点执行）。'
version: '0.0.1'
sources:
  - type: 'PATH'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/var/spool/at/'
        - '/var/spool/atjobs/'
        - '/var/spool/cron/atjobs/'
        - '/usr/spool/at/'
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/at.allow'
        - '/etc/at.deny'
  - type: 'PATH'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/at.d/'
        - '/etc/init.d/atd'
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/lib/systemd/system/atd.service'
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/var/log/atd'
urls:
  - 'https://mp.weixin.qq.com/s/snJ80-Aiy9-XfFvJw380vg'
author: 'NOPTeam'
```

采集 Linux 平台上计划任务相关的内容，包括 crontab 和 at 内容。



## Dns.yaml

```yaml
name: 'LinuxDnsConfig'
doc: 'Linux 平台上DNS配置收集，用于判断是否存在 DNS 劫持等。'
version: '0.0.1'
sources:
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/resolv.conf'
author: 'NOPTeam'
```

采集 Linux 平台上 DNS 配置相关信息，用于判断是否存在 DNS 劫持等内容。



## GPG.yaml

```yaml
name: 'LinuxGPG'
doc: 'Linux 平台上软件源会将 GPG 公钥存储在系统中，用于验证软件源中的内容是否被篡改。该 Artifact 用于收集公钥。'
version: '0.0.1'
sources:
  - type: 'PATH'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/apt/trusted.gpg.d/'
        - '/etc/pki/rpm-gpg/'
author: 'NOPTeam'
```

采集 Linux 平台上的 GPG 公钥，用于后续判断是否存在恶意公钥，确保完整性校验有效。



## HistoryFile.yaml

```yaml
name: 'LinuxHistoryFile'
doc: '所有用户的 .history 文件'
version: '0.0.1'
sources:
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '%%users_homedir%%/.bash_history'
        - '%%users_homedir%%/.zsh_history'
        - '%%users_homedir%%/.sh_history'
        - '%%users_homedir%%/.ksh_history'
        - '%%users_homedir%%/.history'
        - '%%users_homedir%%/.csh_history'
        - '%%users_homedir%%/.tcsh_history'
        - '%%users_homedir%%/.local/share/fish/fish_history'
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/shells'
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'echo'
      args:
        - '$SHELL'
author: 'NOPTeam'
```

采集 Linux 平台上所有用户的命令执行历史信息，包括各种 shell 。



## HomeTemplate.yaml

```yaml
name: 'LinuxHomeTemplate'
doc: 'Linux 平台上在新建用户需要创建家目录时，会从模板处复制一份给新用户，如果攻击者在此处投毒，新创建用户可能都会受影响。'
version: '0.0.1'
sources:
  - type: 'PATH'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/skel/'
author: 'NOPTeam'
```

采集 Linux 家目录模板目录，用于发现攻击者可能潜藏的后门。



## Integrity.yaml

```yaml
name: 'LinuxIntegrity'
doc: "Linux 平台上软件以及配置文件完整性检查。\nubuntu 平台会使用 debsums ，redhat 系会使用 rpm。"
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'rpm'
      args:
        - '-Va'
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'debsums'
      args:
        - '--all'
        - '--changed'
author: 'NOPTeam'
```

Linux 平台上软件程序以及配置文件的完整性检查。

**需要注意：** 默认 `Debian` 系的系统可能默认没有安装 `debsums` 程序，只有安装后配置才有效；`redhat` 系一般会带有 `rpm` ，但还是建议先检查一下



## Iptables.yaml

```yaml
name: 'LinuxIptables'
doc: 'Linux 平台上 iptables 可能被用于端口复用等权限维持'
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'iptables'
      args:
        - '-L'
author: 'NOPTeam'
```

采集 Linux 平台上 Iptables 规则信息，主要用于检查是否存在恶意的端口复用情况。



## KernalModule.yaml

```yaml
name: LinuxKernalMod
doc: Linux 平台上内核平台配置、已加载内核模块、报错日志收集。
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Linux
    attributes:
      cmd: zgrep
      args:
        - CONFIG_MODULE_SIG
        - /boot/config-$(uname -r)
        - '|'
        - grep
        - '-v'
        - '"^#"'
  - type: COMMAND
    supported_os: Linux
    attributes:
      cmd: lsmod
      args: []
  - type: COMMAND
    supported_os: Linux
    attributes:
      cmd: dmesg
      args:
        - '|'
        - grep
        - '-i'
        - '"taint"'
  - type: FILE
    supported_os: Linux
    attributes:
      paths:
        - /var/log/kern.log
        - /var/log/syslog
```

采集 Linux 平台上关于内核模块相关的信息，检查内核模块加载规则配置以及相关日志。



## Log.yaml

```yaml
name: 'LinuxLog'
doc: 'Linux 平台上日志文件收集'
version: '0.0.1'
sources:
  - type: 'PATH'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/var/log/'
author: 'NOPTeam'
```

采集 Linux 平台上的日志信息。

**需要注意：** Linux 平台上的日志信息可能很大，可以使用 `sudo du -sh /var/log` 等方法先判断一下大小，之后选择是否加载该配置文件。



## Login.yaml

```yaml
name: LinuxLogin
doc: Linux 登录相关信息
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Linux
    attributes:
      cmd: w
      args: []
  - type: COMMAND
    supported_os: Linux
    attributes:
      cmd: who
      args: []
  - type: COMMAND
    supported_os: Linux
    attributes:
      cmd: last
      args:
        - '-awF'
  - type: COMMAND
    supported_os: Linux
    attributes:
      cmd: users
      args: []
  - type: COMMAND
    supported_os: Linux
    attributes:
      cmd: lastlog
      args: []
  - type: COMMAND
    supported_os: Linux
    attributes:
      cmd: lslogins
      args: []
urls:
  - https://www.jianshu.com/p/05926453654c

```

采集 Linux 平台登录相关信息。



## Motd.yaml

```yaml
name: 'LinuxMotd'
doc: 'Linux 平台上 motd 是欢迎信息，该部分内容可能被用作权限维持'
version: '0.0.1'
sources:
  - type: 'PATH'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/update-motd.d/'
urls:
  - 'https://mp.weixin.qq.com/s/AvnCXkdGqo8uBBRYH61ihA'
author: 'NOPTeam'
```

采集 Linux 平台上的 motd 信息，排查是否存在后门。



## PAM.yaml

```yaml
name: 'LinuxPAM'
doc: "Linux 平台上 PAM 是一套身份认证框架，用于统一和灵活地管理系统的各种认证方式。\nPAM 常被用于权限维持。"
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'debsums'
      args:
        - 'libpam0g'
        - '-a'
        - '-c'
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'debsums'
      args:
        - '-a'
        - '-c'
        - '2>/dev/null'
urls:
  - 'https://mp.weixin.qq.com/s/W4RX5WRzUp-hK1_Pr3rp7w'
author: 'NOPTeam'
```

采集 Linux 平台上 PAM 相关信息，用于判断是否存在被用于权限维持的情况。



## Preload.yaml

```yaml
name: 'LinuxPreload'
doc: 'Linux 平台上常见的动态链接库劫持排查'
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'echo'
      args:
        - '$LD_PRELOAD'
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/ld.so.conf'
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'echo'
      args:
        - '$LD_LIBRARY_PATH'
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/ld.so.preload'
urls:
  - 'https://mp.weixin.qq.com/s/7mOeZ6DkSAFqzibN82qcMg'
  - 'https://mp.weixin.qq.com/s/InMQaKOwns2mEIp5yF8dDw'
author: 'NOPTeam'

```

采集 Linux 平台上 preload 相关信息，用于判断是否存在这种类型的动态链接库劫持。



## Proc.yaml

```yaml
name: 'LinuxProc'
doc: "Linux 平台上 proc 是 Linux 系统中的一个虚拟文件系统，不是存储真实文件的地方，而是内核提供给用户空间的一种内存映射接口。\n本 Artifact 是用于比对 ps -aux 与实际 proc 的差异，寻找是否存在隐藏进程。"
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'ps'
      args:
        - '-aux'
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'ls'
      args:
        - '-al'
        - '/proc'
author: 'NOPTeam'
```

采集对比 Linux 平台上 `ps -aux` 和 `/proc/` 目录下目录的差异，寻找是否存在隐藏进程。



## ProcessFileDeleted.yaml

```yaml
name: 'LinuxProcessFileDeleted'
doc: 'Linux 平台上进程启动文件被删除的情况排查，部分恶意文件会删除进程启动文件来避免被分析，常规程序通常不会删除进程启动文件。'
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'ls'
      args:
        - '-al'
        - '/proc/*/exe'
        - '2>/dev/null'
        - '|'
        - 'grep'
        - 'deleted'
author: 'NOPTeam'
```

发现 Linux 平台上是否存在进程启动文件被删除的情况，有些恶意程序为防止本身被分析会采取这样的操作。



## PtraceScope.yaml

```yaml
name: 'LinuxPtraceScope'
doc: "Linux 平台上 /proc/sys/kernel/yama/ptrace_scope 这个文件是 Linux 内核安全模块 YAMA 提供的一个“开关”，用于限制 ptrace 系统调用的使用范围，从而增强系统的安全性。\n\n内容含义如下：\n- 0\t没有限制，任何进程都可以 ptrace 其它进程（只要有权限，如相同的用户）。不推荐，除非有特别需求。\n- 1\t（默认） 只有父进程可以 ptrace 其直接的子进程，或者进程彼此有明确的 ptrace 关系。更安全，推荐。\n- 2\t只有 root 用户可以使用 ptrace。\n- 3\t完全禁止 ptrace，即使是 root 也不行。"
version: '0.0.1'
sources:
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/proc/sys/kernel/yama/ptrace_scope'
author: 'NOPTeam'
```

采集 Linux 平台上 ptrace 相关配置，部分恶意程序可能会对此进行配置。



## Python.pth.yaml

```yaml
name: 'LinuxPythonPthBackdoor'
doc: "Linux 平台上 Python 中 .pth 后缀的文件用于扩展模块搜索路径。\n当此类文件位于 site-packages 或 dist-packages 等目录时，Python会在启动时自动处理文件内容但是它有一个问题，如果文件以 import 开头，那么在执行任意 Python 代码时就会执行 *.pth 文件的代码"
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'echo'
      args:
        - '$PYTHONPATH'
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'locate'
      args:
        - '.pth'
urls:
  - 'https://dfir.ch/posts/publish_python_pth_extension/'
  - 'https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/'
author: 'NOPTeam'

```

排查 Linux 平台上 .pth  后门的情况
**需要注意：** 需要系统上的 `locate` 配合，一般系统没有默认安装，安装后执行 `updatedb` 可以为其生成数据库，之后就可以像 `Windows` 上的 `everything` 一样快速搜索了。



## SensitiveDirs.yaml

```yaml
name: 'SensitiveDirs'
doc: 'Linux 平台上存在一些经常被攻击者使用的目录，例如 /tmp、/dev/shm ，本 Artifact 用于收集这些内容， /tmp 内容可能较多，需要根据实际情况谨慎收集。'
version: '0.0.1'
sources:
  - type: 'PATH'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/tmp/'
        - '/dev/shm'
        - '/var/tmp'
author: 'NOPTeam'
```

采集 Linux 平台上一些敏感目录。
**需要注意：** 这些目录中可能存在较多文件，还是建议先使用 `sudo du -sh /tmp/` 来查看每个目录的大小后决定是否采集。



## Services.yaml

```yaml
name: 'LinuxServices'
doc: 'Linux 平台上运行的服务相关收集'
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'systemctl'
      args:
        - 'list-units'
        - '--type=service'
        - '--state=running'
author: 'NOPTeam'
```

采集 Linux 平台上服务相关的内容，目前仅收集正在运行的服务。



## SpecialPermissionFile.yaml

```yaml
name: 'LinuxSpecialPermission'
doc: 'Linux 平台上具有 SUID、GUID 等权限的目录及文件'
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'find'
      args:
        - '/'
        - '-perm'
        - '/4000'
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'find'
      args:
        - '/'
        - '-perm'
        - '/2000'
author: 'NOPTeam'

```

采集 Linux 平台上具有特殊权限的文件信息，例如 SUID 。

该配置文件采集过程中可能会耗费一段时间。



## SSH.yaml

```yaml
name: 'LinuxSSHAccess'
doc: 'Linux 平台上SSH保存的公钥以及访问其他SSH服务器的目标地址记录'
version: '0.0.1'
sources:
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '%%users_homedir%%/.ssh/authorized_keys'
        - '%%users_homedir%%/.ssh/authorized_keys2'
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '%%users_homedir%%/.ssh/known_hosts'
urls:
  - 'https://mp.weixin.qq.com/s/R_CUPqa2WQUgOJu__5MFzg'
author: 'NOPTeam'

---

name: 'LinuxSSHConfig'
doc: 'Linux 平台上 SSH 客户端配置文件收集，其中可能会被利用来权限维持'
version: '0.0.1'
sources:
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/ssh/ssh_config'
        - '%%users_homedir%%/.ssh/config'
urls:
  - 'https://mp.weixin.qq.com/s/7WDWjMOI7GdUM5e4vDVAoA'
author: 'NOPTeam'

```

采集 Linux 平台上 SSH 相关信息，包括保存的公钥、连接过的 SSH 服务器、SSH 客户端配置信息等。



## Startup.yaml

```yaml
name: 'LinuxStartupService'
doc: 'Linux 平台上开机自启的服务项'
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'systemctl'
      args:
        - 'list-unit-files'
        - '--type=service'
        - '|'
        - 'grep'
        - 'enabled'
author: 'NOPTeam'

---

name: 'LinuxStartConfig'
doc: 'Linux 平台上开机或登录自启的配置文件'
version: '0.0.1'
sources:
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/rc.local'
        - '/etc/rc.d/rc.local'
        - '/etc/profile'
  - type: 'PATH'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/rc.d/init.d/'
        - '/etc/profile.d/'
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'chkconfig'
      args:
        - '--list'
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/bashrc'
        - '%%users_homedir%%/.bashrc'
        - '%%users_homedir%%/.bash_profile'
        - '%%users_homedir%%/.profile'
        - '%%users_homedir%%/.bash_logout'
author: 'NOPTeam'
```

采集 Linux 平台上启动项相关信息，包括各种配置文件以及服务。



## Sudo.yaml

```yaml
name: 'LinuxSudo'
doc: 'Linux 平台上 sudo 用于赋予用户特定的权限，可能被利用来进行权限维持。'
version: '0.0.1'
sources:
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/sudo.conf'
        - '/etc/sudoers'
  - type: 'PATH'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/sudoers.d/'
author: 'NOPTeam'
```

采集 Linux 平台上 `sudo` 相关的配置信息。



## TCPWrappers.yaml

```yaml
name: 'LinuxTcpWrappers'
doc: "Linux 平台上 TCP Wrappers 是一种用于控制对网络服务访问的安全工具。它可以限制和记录通过 inetd超级服务器启动的服务的访问。\n其配置文件中的 spawn 和 twist 可能会被用来执行命令。"
version: '0.0.1'
sources:
  - type: 'FILE'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/hosts.allow'
        - '/etc/hosts.deny'
author: 'NOPTeam'

```

采集 Linux 平台上 `TcpWrappers` 相关信息。



## Trap.yaml

```yaml
name: 'LinuxTrap'
doc: 'Linux 平台上 trap 是一个内建命令，用于捕获和处理信号，或者在脚本退出时（包括正常退出、异常中断）执行特定的命令。'
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Linux'
    attributes:
      cmd: 'trap'
      args:
        - '-p'
author: 'NOPTeam'
```

采集 Linux 平台上的 `Trap` 信息。



## Udev.yaml

```yaml
name: 'LinuxUdev'
doc: "Linux 平台上 udev 是Linux kernel的设备管理器，主要管理 /dev 目录底下的设备节点。它同时也是用来接替devfs 及 hotplug 的功能，这意味着它要在添加/删除硬件时处理 /dev 目录以及所有用户空间的行为，包括加载固件时。\n\n我们需要着重关注每个规则文件中以下三个关键字(赋值键)：\n- RUN\n- PROGRAM\n- IMPORT"
version: '0.0.1'
sources:
  - type: 'PATH'
    supported_os: 'Linux'
    attributes:
      paths:
        - '/etc/udev/rules.d/'
        - '/run/udev/rules.d/'
        - '/lib/udev/rules.d/'
urls:
  - 'https://mp.weixin.qq.com/s/t9pOy5MzZ6hxH0gdgprI7g'
author: 'NOPTeam'
```

采集 Linux 平台上 `udev` 相关信息，主要用于排查 `udev` 后门。



----

目前 Linux 版本配置如上，如果大家有好的建议，可以提 pr 或者微信联系 `just_hack_for_fun` 反馈。




