## 简介

大家好，我们是 NOP Team

这段时间，我们相继推出了 **OpenForensicRules**、**NOPTrace-Configurator**、**NOPTrace-Collector** 

简单介绍一下它们的作用

- **OpenForensicRules** 是一套标准化的数字取证与应急响应信息采集规则格式规范。
- **NOPTrace-Configurator** 是 **OpenForensicRules** 的图形化配置工具，同时可以检查用户配置是否规范
- **NOPTrace-Collector**  是基于 **OpenForensicRules**  的采集器，用户可以使用它进行定制化信息采集
- **NOPTrace-Configs**  是符合 **OpenForensicRules** 规范的电子取证与应急响应配置集合



 **NOPTrace-Configs** 项目是符合 **OpenForensicRules** 规范的电子取证与应急响应配置集合
该项目的目的是当出现应急响应事件时，受害方能够第一时间采集重要信息，即使后续恢复系统或者排查破坏了痕迹，也能够留一份证据，供后续应急响应人员以及相关人员分析回溯


**OpenForensicRules**  项目中也会同步该项目的配置文件



## 配置文件说明

在发布 **NOPTrace-Collector**  时，我们曾发出提醒，大家一定要了解程序要加载的配置文件，因为采集器是可以执行系统命令的，所以下面展示并简述每一个配置文件的内容，其中部分配置文件要着重考虑是否加载

 **NOPTrace-Configs** 项目 Linux 版已覆盖绝大多数 《Linux 应急响应手册》 中的常规安全检查部分内容； Windows 版已覆盖绝大多数 《Windows 应急响应手册》 中的常规安全检查部分内容

![](http://mweb-tc.oss-cn-beijing.aliyuncs.com/2025-07-08-101718.jpg)

![](http://mweb-tc.oss-cn-beijing.aliyuncs.com/2025-07-08-101644.png)



![](http://mweb-tc.oss-cn-beijing.aliyuncs.com/2025-07-09-061255.jpg)

![](http://mweb-tc.oss-cn-beijing.aliyuncs.com/2025-07-09-061339.png)

<br />

## Linux 版本配置文件说明

### Account.yaml

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



### Alias.yaml

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



### ASLR.yaml

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



### Bash.yaml

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



### Capabilities.yaml

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



### CrontabFile.yaml

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



### Dns.yaml

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



### GPG.yaml

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



### HistoryFile.yaml

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



### HomeTemplate.yaml

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



### Integrity.yaml

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



### Iptables.yaml

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



### KernalModule.yaml

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



### Log.yaml

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



### Login.yaml

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



### Motd.yaml

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



### PAM.yaml

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



### Preload.yaml

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



### Proc.yaml

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



### ProcessFileDeleted.yaml

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



### PtraceScope.yaml

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



### Python.pth.yaml

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



### SensitiveDirs.yaml

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



### Services.yaml

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



### SpecialPermissionFile.yaml

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



### SSH.yaml

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



### Startup.yaml

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



### Sudo.yaml

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



### TCPWrappers.yaml

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



### Trap.yaml

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



### Udev.yaml

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


## Windows 版配置文件说明

### Accessibility.yaml

```yaml
name: 'WindowsAccessibility'
author: 'NOPTeam'
sources:
  - type: 'FILE'
    supported_os: 'Windows'
    attributes:
      paths:
        - '%%environ_systemroot%%\System32\sethc.exe'
        - '%%environ_systemroot%%\System32\utilman.exe'
        - '%%environ_systemroot%%\System32\osk.exe'
        - '%%environ_systemroot%%\System32\Magnify.exe'
        - '%%environ_systemroot%%\System32\Narrator.exe'
        - '%%environ_systemroot%%\System32\DisplaySwitch.exe'
        - '%%environ_systemroot%%\System32\AtBroker.exe'
version: '0.0.1'
doc: 'Windows 平台辅助程序信息收集。'
```

采集 Windows 平台的辅助程序，例如常见的粘滞键。



### Accounts.yaml

```yaml
name: 'WindowsAccounts'
doc: 'Windows 平台上用户以及用户组的相关信息收集。'
author: 'NOPTeam'
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'net'
      args:
        - 'user'
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'net'
      args:
        - 'localgroup'
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'net'
      args:
        - 'localgroup'
        - 'Users'
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'net'
      args:
        - 'localgroup'
        - 'Administrators'
  - type: 'WMI'
    supported_os: 'Windows'
    attributes:
      base_object: ''
      query: 'SELECT * FROM Win32_UserAccount'
  - type: 'WMI'
    supported_os: 'Windows'
    attributes:
      base_object: ''
      query: 'SELECT * FROM Win32_Group'

```

采集 Windows 平台上账户相关信息。



### Activity.yaml

```yaml
name: WindowsGroupPolicy
doc: |-
  Windows 平台上组策略中关于进程创建是否设置了记录。

  计算机配置 -> Windows设置 -> 安全设置 -> ⾼级审核策略配置 -> 详细跟踪 -> 审核进程创建
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: auditpol
      args:
        - /get
        - /subcategory:"Process Creation"
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: auditpol
      args:
        - /get
        - /subcategory:"进程创建"

---

name: WindowsAmcache
doc: |-
  Windows 平台上 Amcache 是一个用于记录系统上执行过的程序及其信息的数据库。
  它主要用于取证调查和安全分析，因为它会在后台自动收集和保存可执行文件的元数据，包括程序路径、首次运行时间、文件哈希值等信息。
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: .\tools\AmcacheParser.exe
      args:
        - '-f'
        - C:\Windows\appcompat\Programs\Amcache.hve
        - '--csv'
        - '%temp%'
  - type: FILE
    supported_os: Windows
    attributes:
      paths:
        - '%%current_user_temp%%/*_Amcache_*.csv'
urls:
  - https://github.com/EricZimmerman/AmcacheParser

---

name: WindowsShimCache
doc: >-
  Windows 平台上的ShimCache（全名 Application Compatibility Cache，应用兼容性缓存）是 Windows
  操作系统用于程序兼容性支持的一个内部机制。它最常被数字取证、安全分析和溯源调查用来判断某个可执行文件曾经是否在系统上运行过，即使这个文件和日志都已经被删除，ShimCache
  也可能有残留记录。
author: NOPTeam
version: 0.0.1
sources:
  - type: REGISTRY_KEY
    supported_os: Windows
    attributes:
      keys:
        - >-
          HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session
          Manager\AppCompatCache

---

name: WindowsUserAssist
doc: >-
  Windows 平台上 UserAssist 是 Windows
  注册表中的一个特殊分支，用于记录用户通过图形界面（如开始菜单、桌面、资源管理器等）运行过的程序的信息。它最初的目的是帮助 Windows
  统计和优化“常用程序”列表，但在数字取证和行为审计中非常有价值，因为它能反映出用户实际交互打开过哪些程序及其次数和最后时间。
author: NOPTeam
version: 0.0.1
sources:
  - type: REGISTRY_KEY
    supported_os: Windows
    attributes:
      keys:
        - >-
          HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*

---

name: WindowsMUICache
doc: >-
  Windows 平台上 MUICache 是 Windows
  操作系统中的⼀个功能，⽤于记录和缓存多语⾔⽤户界⾯（MUI）⽂件的信息。它主要⽤于加快多语⾔应⽤程序的启动速度，并提供对多语⾔资源的访问⽀持。
author: NOPTeam
version: 0.0.1
sources:
  - type: REGISTRY_KEY
    supported_os: Windows
    attributes:
      keys:
        - >-
          HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\ShellNoRoam\MUICache
        - >-
          HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Explorer\MUICache
        - >-
          HKEY_USERS\%%users_sid%%\Software\Classes\Local
          Settings\Software\Microsoft\Windows\Shell\MuiCache

---

name: WindowsRunMRU
doc: |-
  Windows 平台上 RunMRU 是注册表中的一个条目，用于记录“运行”对话框（Win+R 或开始菜单 > 运行）历史输入的命令。
  它能反映出用户近期通过“运行”窗口手动输入过哪些路径、命令、网址等，对于用户操作溯源和数字取证非常有用。
author: NOPTeam
version: 0.0.1
sources:
  - type: REGISTRY_KEY
    supported_os: Windows
    attributes:
      keys:
        - >-
          HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

---

name: WindowsAppCompatFlags
doc: >-
  AppCompatFlags 注册表键（AppCompatFlags Registry Keys）是 Windows
  操作系统应用程序兼容性机制（Application Compatibility, Shim
  Engine）的一部分。它用于记录和配置针对特定可执行文件的兼容性设置、强制沙箱、强制以管理员权限运行等信息。这些信息既可能是系统自动生成，也可以是用户手动配置（比如在程序右键属性里“兼容性”选项卡里的设置）。
author: NOPTeam
version: 0.0.1
sources:
  - type: REGISTRY_KEY
    supported_os: Windows
    attributes:
      keys:
        - >-
          HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows
          NT\CurrentVersion\AppCompatFlags\
        - >-
          HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows
          NT\CurrentVersion\AppCompatFlags\*\
        - >-
          HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows
          NT\CurrentVersion\AppCompatFlags\*\*\
        - >-
          HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows
          NT\CurrentVersion\AppCompatFlags\*\*\*\
        - >-
          HKEY_LOCAL_MACHINE\Software\Microsoft\Windows
          NT\CurrentVersion\AppCompatFlags\
        - >-
          HKEY_LOCAL_MACHINE\Software\Microsoft\Windows
          NT\CurrentVersion\AppCompatFlags\*\
        - >-
          HKEY_LOCAL_MACHINE\Software\Microsoft\Windows
          NT\CurrentVersion\AppCompatFlags\*\*\
        - >-
          HKEY_LOCAL_MACHINE\Software\Microsoft\Windows
          NT\CurrentVersion\AppCompatFlags\*\*\*\

---

name: WindowsPrefetch
doc: |-
  Prefetch 是 Windows 操作系统为加快程序启动速度而设计的程序预读机制，也是一类特殊的磁盘文件（不是注册表项！）和相关分析术语。
  在数字取证领域，Prefetch 文件可以用来判断某个程序是否被运行过、运行过多少次、最后一次运行时间等信息。
author: NOPTeam
version: 0.0.1
sources:
  - type: REGISTRY_VALUE
    supported_os: Windows
    attributes:
      key_value_pairs:
        - key: >-
            HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session
            Manager\Memory Management\PrefetchParameters
          value: EnablePrefetcher
  - type: PATH
    supported_os: Windows
    attributes:
      paths:
        - C:\Windows\Prefetch\

---

name: WindowsApplicationExperience
doc: >-
  Application-Experience（应用体验，常缩写为 AE 或 AppCompat）是 Windows
  操作系统的一个系统服务和相关组件，主要用于应用兼容性和用户体验改进。

  它包括一系列后台服务、注册表项和日志，用于：

  - 检测和记录应用兼容性问题

  - 支持“兼容性助手”弹窗和建议（如“此程序可能没有正确安装”之类提示）

  - 辅助 Windows 安装、升级和程序运行的平滑化

  - 记录部分程序的安装、卸载、运行等操作的相关信息

  这些机制有助于微软收集兼容性数据，改进后续系统和补丁，同时也为数字取证分析提供了一些痕迹。
author: NOPTeam
version: 0.0.1
sources:
  - type: FILE
    supported_os: Windows
    attributes:
      paths:
        - >-
          C:\Windows\System32\winevt\Logs\Microsoft-Windows-Application-Experience*.evtx

---

name: WindowsJumpLists
doc: >-
  Jump Lists（跳转列表）是 Windows 7
  及以后引入的一项功能，用于记录和展示用户最近或常用打开的文件、文件夹、网址等操作历史，并通过任务栏和开始菜单为用户提供快速访问入口。它不仅提升了用户体验，也为取证分析提供了重要的用户操作轨迹。
author: NOPTeam
version: 0.0.1
sources:
  - type: PATH
    supported_os: Windows
    attributes:
      paths:
        - '%%users_appdata%%\Microsoft\Windows\Recent\AutomaticDestinations\'
        - '%%users_appdata%%\Microsoft\Windows\Recent\CustomDestinations\'

---

name: WindowsSRUM
doc: >-
  SRUM（System Resource Usage Monitor，系统资源使用监控器）是自 Windows 8
  起引入的一个系统组件，用于记录和监控系统资源的详细使用情况。SRUM 会持续采集并保存如下数据：

  - 各个进程/应用的CPU、内存、网络、能耗等资源消耗

  - 网络连接的应用、IP、流量统计

  - 用户活动（如程序启动、前台/后台运行情况）

  这些数据会被系统用于电池优化、能耗分析、网络流量统计等内部用途，但对于数字取证来说，SRUM 是一个极其宝贵的用户行为和系统活动历史分析源。
author: NOPTeam
version: 0.0.1
sources:
  - type: PATH
    supported_os: Windows
    attributes:
      paths:
        - C:\Windows\System32\sru\

---

name: WindowsLastVisitedMRU
doc: >-
  LastVisitedMRU 是 Windows
  注册表中用于记录资源管理器（Explorer）或常见文件对话框中“最近访问过的文件夹/路径”历史的一个项目。

  在数字取证中，LastVisitedMRU 可还原用户最近通过“打开/保存”对话框访问过哪些文件夹，属于用户操作轨迹的重要部分。
author: NOPTeam
version: 0.0.1
sources:
  - type: REGISTRY_KEY
    supported_os: Windows
    attributes:
      keys:
        - >-
          HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
        - >-
          HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy
        - >-
          HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*\
urls:
  - https://www.cybertriage.com/artifact/windows-opensave-mru-artifact/

---

name: WindowsRecentDocs
doc: Windows 平台上用于记录该用户最近打开过的文件列表，也就是 Windows “最近文档”功能的核心数据源。
author: NOPTeam
version: 0.0.1
sources:
  - type: REGISTRY_KEY
    supported_os: Windows
    attributes:
      keys:
        - >-
          HKEY_USERS\%%users_sid%%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

```

采集 Windows 平台上的近期活动，这里包括了多个 Artifact 
**需要注意：** Amcache 文件无法直接采集，需要外部工具协助，上面使用的是 `AmcacheParser` 来辅助先在用户目录生成解析后的 csv 文件，之后在使用文件采集的方法进行采集。收集器支持 source 的串行执行。 所以需要大家自行下载 AmcacheParser 放入到 `.\tools` 目录或直接使用项目附带的 。

> 官方下载地址
> https://ericzimmerman.github.io/#!index.md
> https://github.com/EricZimmerman/AmcacheParser?tab=readme-ov-file



### AppCertDLLs.yaml

```yaml
name: 'WindowsAppCertDLLs'
doc: "AppCert DLLs 是 Windows 的一个高级进程拦截与注入机制，广泛用于安全产品、调试器、取证工具。\n当程序使用 CreateProcess、CreateProcessAsUser、CreateProcessWithLoginW、CreateProcessWithTokenW 或 WinExec 等函数时，这些进程会获取HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SessionManager\\AppCertDlls注册表项，此项下的dll都会加载到此进程。"
author: 'NOPTeam'
version: '0.0.1'
sources:
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\AppCertDlls'
```

采集 Windows 平台上的 `AppCert DLLs` 信息，该内容常被用来进程拦截与注入



### AppInitDLL.yaml

```yaml
name: 'WindowsAppInitDLL'
author: 'NOPTeam'
sources:
  - type: 'REGISTRY_VALUE'
    supported_os: 'Windows'
    attributes:
      key_value_pairs:
        - key: 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows'
          value: 'AppInit_DLLs'
        - key: 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
          value: 'AppInit_DLLs'
version: '0.0.1'
doc: 'AppInit DLLs 是 Windows 系统提供的一种全局 DLL 注入机制，用于让指定的 DLL 自动加载到所有使用 User32.dll 的进程（几乎所有带 GUI 的应用程序）中。'

```

采集 Windows 平台上的 `AppInit DLLs` 信息，其可以被用来全局 DLL 注入



### ApplicationShimming.yaml

```yaml
name: 'WindowsApplicationShimming'
author: 'NOPTeam'
sources:
  - type: 'PATH'
    supported_os: 'Windows'
    attributes:
      paths:
        - '%%environ_windir%%\AppPatch\'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom'
version: '0.0.1'
doc: "Application Shimming（应用程序垫片/兼容性垫片）\n是 Windows 系统内置的一种兼容性子系统机制，允许为指定程序注入“垫片”代码，以“修正”或“修改”程序的运行行为。"

```

采集 Windows 平台上 `Application Shimming` 信息，这也是与程序注入相关的内容



### AutoRun.yaml

```yaml
name: 'WindowsAutoRun'
author: 'NOPTeam'
sources:
  - type: 'PATH'
    supported_os: 'Windows'
    attributes:
      paths:
        - '%%users_appdata%%\Microsoft\Windows\Start'
        - '%%environ_programdata%%\Microsoft\Windows\Start Menu\Programs\Startup'
  - type: 'PATH'
    supported_os: 'Windows'
    attributes:
      paths:
        - '%%environ_systemdrive%%\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_USERS\%%users_sid%%\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        - 'HKEY_USERS\%%users_sid%%\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_USERS\%%users_sid%%\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Load'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Run'
  - type: 'REGISTRY_VALUE'
    supported_os: 'Windows'
    attributes:
      key_value_pairs:
        - key: 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
          value: 'Userinit'
        - key: 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
          value: 'Shell'
        - key: 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
          value: 'Userinit'
        - key: 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
          value: 'Shell'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
        - 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\RunServices'
  - type: 'REGISTRY_VALUE'
    supported_os: 'Windows'
    attributes:
      key_value_pairs:
        - key: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
          value: 'Authentication Packages'
        - key: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
          value: 'Security Packages'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors'
        - 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Environments\*\Drivers\*\*\'
  - type: 'REGISTRY_VALUE'
    supported_os: 'Windows'
    attributes:
      key_value_pairs:
        - key: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors\*'
          value: 'Driver'
  - type: 'REGISTRY_VALUE'
    supported_os: 'Windows'
    attributes:
      key_value_pairs:
        - key: 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\*'
          value: 'StubPath'
  - type: 'REGISTRY_VALUE'
    supported_os: 'Windows'
    attributes:
      key_value_pairs:
        - key: 'HKEY_CURRENT_USER\Environment'
          value: 'UserInitMprLogonScript'
  - type: 'REGISTRY_VALUE'
    supported_os: 'Windows'
    attributes:
      key_value_pairs:
        - key: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\'
          value: 'BootExecute'
        - key: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager'
          value: 'PendingFileRenameOperations'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
version: '0.0.1'
doc: 'Windows 平台上自启动相关信息收集。'

---

name: 'WindowsPolicyScripts'
author: 'NOPTeam'
sources:
  - type: 'PATH'
    supported_os: 'Windows'
    attributes:
      paths:
        - 'C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup'
        - 'C:\Windows\System32\GroupPolicy\Machine\Scripts\Shutdown'
        - 'C:\Windows\System32\GroupPolicy\User\Scripts\Logon'
        - 'C:\Windows\System32\GroupPolicy\User\Scripts\Logoff\'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\*\'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\*\*\'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\*\'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\*\*\'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\*\'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\*\*\'
version: '0.0.1'
doc: 'Windows 平台上组策略相关脚本。'

```

采集 Windows 平台上自启动相关内容



### BitsJob.yaml

```yaml
name: WindowsBitsJob
doc: >-
  BITS Job（Background Intelligent Transfer Service 任务）是微软 Windows
  系统中的一个后台智能传输服务任务单位。
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: bitsadmin
      args:
        - /list
        - /allusers
        - /verbose
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: powershell
      args:
        - '-c'
        - '"Get-BitsTransfer -AllUsers"'
```

采集 Windows 平台上的 BITS Job 相关信息



### COM.yaml

```yaml
name: 'WindowsCOMHijacking'
author: 'NOPTeam'
sources:
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_CLASSES_ROOT\CLSID\*\InprocServer32'
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\*\InprocServer32'
        - 'HKEY_USERS\%%users_sid%%\Software\Classes\CLSID\*\InprocServer32'
version: '0.0.1'
doc: "COM（Component Object Model）是微软提出的一种软件组件对象模型，用于 Windows 各种程序和系统组件之间的通信和功能复用。\n程序通过CLSID/ProgID 等方式调用系统或第三方注册的 COM 组件。\n\nWindows 程序调用 COM 组件时，会从注册表查找对应 CLSID/ProgID 的实现 DLL 路径并加载。\n攻击者通过修改注册表，把某个常用或系统自动调用的 COM 组件的路径指向自己的恶意 DLL。\n这样，当系统或软件调用该 COM 组件时，就会自动加载攻击者的恶意代码，实现代码注入、权限维持、持久化等。"
urls:
  - 'https://paper.seebug.org/2030/'
```

采集 Windows 平台上 COM劫持相关的注册表内容 。



### Defender.yaml

```yaml
name: WindowsDefender
doc: Windows Defender 检测到的信息收集。
author: NOPTeam
version: 0.0.1
sources:
  - type: FILE
    supported_os: Windows
    attributes:
      paths:
        - >-
          %%environ_systemroot%%\System32\Winevt\Logs\Microsoft-Windows-Windows
          Defender*.evtx
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: powershell
      args:
        - '-c'
        - '"Get-MpThreatDetection | Format-List"'
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: powershell
      args:
        - '-c'
        - '"Get-MpThreat"'
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: powershell
      args:
        - '-c'
        - '"Get-MpPreference | Format-List"'
  - type: PATH
    supported_os: Windows
    attributes:
      paths:
        - '%%environ_programdata%%\Microsoft\Windows Defender\Quarantine\'
  - type: REGISTRY_KEY
    supported_os: Windows
    attributes:
      keys:
        - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender
        - HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender
        - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend

```

采集 Windows 平台上自带的 Defender 相关内容，例如检测到恶意行为、隔离区等。



### DLL.yaml

```yaml
name: 'WindowsDLLCheck'
author: 'NOPTeam'
sources:
  - type: 'REGISTRY_VALUE'
    supported_os: 'Windows'
    attributes:
      key_value_pairs:
        - key: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager'
          value: 'SafeDllSearchMode'
  - type: 'REGISTRY_VALUE'
    supported_os: 'Windows'
    attributes:
      key_value_pairs:
        - key: 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
          value: 'AppInit_DLLs'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'
version: '0.0.1'
doc: 'Windows DLL 劫持、注入等相关信息收集。'
```

采集 Windows 平台上 DLL 劫持、注入相关信息



### Env.yaml

```yaml
name: WindowsEnv
doc: Windows 中环境变量信息。
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: set
      args: []
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: powershell
      args:
        - '-c'
        - '"ls env: | Format-Table -Wrap"'

```

采集 Windows 平台上环境变量信息



### Firewall.yaml

```yaml
name: WindowsFirewall
doc: Windows 平台上防火墙的状态以及规则。
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: powershell
      args:
        - '-c'
        - '"Get-NetFirewallProfile"'
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: netsh
      args:
        - advfirewall
        - show
        - allprofiles
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: powershell
      args:
        - '-c'
        - '"Get-NetFirewallRule | Where-Object { $_.Enabled -eq ''True'' }"'
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: netsh
      args:
        - advfirewall
        - firewall
        - show
        - rule
        - name=all

```

采集 Windows 平台上关于防火墙状态以及规则相关信息



### History.yaml

```yaml
name: WindowsCmdHistory
doc: |-
  Windows 平台上 cmd 历史信息。
  cmd命令历史只能在未关闭的 cmd命令窗中进⾏查询，如果 cmd 窗⼝关闭，或未通过 cmd 命令窗进⾏的命令操作，是不会记录的。
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: doskey
      args:
        - /history

---

name: WindowsPSHistory
doc: Windows 平台上 Powershell 的历史记录。
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: powershell
      args:
        - '-c'
        - '"Get-History"'
  - type: FILE
    supported_os: Windows
    attributes:
      paths:
        - >-
          %%users_userprofile%%\AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt
        - >-
          %%users_userprofile%%\\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

```

采集 Windows 平台上的 cmd、 powershell 的历史记录，主要是 powershell 的历史记录



### IFEOInject.yaml

```yaml
name: WindowsIFEOInjection
doc: >-
  Image File Execution Options (IFEO) 是一个 Windows 调试功能，而不是一个后门。IFEO
  的主要目的是允许开发人员调试和跟踪特定的可执行文件。


  IFEO 提供了一种机制，使开发人员能够将一个调试器程序关联到特定的可执行文件，并在执行该可执行文件时启动调试器。这对于开发、调试和分析应用程序非常有用。

  当给定的可执行文件被启动时，操作系统会检查注册表中的 IFEO
  设置。如果找到了对应的注册表项，系统会自动启动所配置的调试器程序，并将目标可执行文件作为参数传递给调试器。这样，开发人员就可以使用调试器来监视和分析目标应用程序的运行过程，以便调试和解决问题。
author: NOPTeam
version: 0.0.1
sources:
  - type: REGISTRY_VALUE
    supported_os: Windows
    attributes:
      key_value_pairs:
        - key: >-
            HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows
            NT\CurrentVersion\Image File Execution Options\*
          value: debugger
```

采集 Windows 平台 IFEO 相关信息



### IPC.yaml

```yaml
name: 'WindowsIPCShare'
author: 'NOPTeam'
sources:
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'net'
      args:
        - 'share'
version: '0.0.1'
doc: 'Windows 平台上 IPC 共享信息收集。'
```

采集 Windows 平台上的 IPC 共享信息



### Log.yaml

```yaml
name: 'WindowsLogs'
author: 'NOPTeam'
sources:
  - type: 'PATH'
    supported_os: 'Windows'
    attributes:
      paths:
        - 'C:\Windows\System32\winevt\Logs\'
version: '0.0.1'
doc: 'Windows 平台上日志信息。'
```

采集 Windows 平台上日志文件



### Login.yaml

```yaml
name: 'WindowsLogin'
author: 'NOPTeam'
sources:
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'query'
      args:
        - 'user'
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'query'
      args:
        - 'session'
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'powershell'
      args:
        - '-c'
        - '"Get-SmbSession"'
version: '0.0.1'
doc: 'Windows 平台上与登录信息相关内容收集。'

```

采集 Windows 平台上登录相关信息



### NetSh.yaml

```yaml
name: 'WindowsNetSh'
author: 'NOPTeam'
sources:
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh'
version: '0.0.1'
doc: "NetSh（Network Shell） 是 Windows 自带的一个强大的命令行网络配置工具。\n攻击者可能注册帮助程序来进行权限维持。"
urls:
  - 'https://pentestlab.blog/2019/10/29/persistence-netsh-helper-dll/'
```

采集 Windows 平台上 NetSh 帮助程序信息



### Network.yaml

```yaml
name: WindowsNetwork
doc: Windows 上网络连接信息。
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: netstat
      args:
        - '-a'
        - '-n'
        - '-o'
        - '-b'
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: nbtstat
      args:
        - '-c'
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: powershell
      args:
        - '-c'
        - '"Get-NetTCPConnection"'
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: powershell
      args:
        - '-c'
        - '"Get-NetUDPEndpoint"'
```

发现 Windows 平台上的网络连接信息



### NetworkProvider.yaml

```yaml
name: 'WindowsNetworkProvider'
author: 'NOPTeam'
sources:
  - type: 'REGISTRY_VALUE'
    supported_os: 'Windows'
    attributes:
      key_value_pairs:
        - key: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order'
          value: 'ProviderOrder'
        - key: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\NetworkProvider\HwOrder'
          value: 'ProviderOrder'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\NetworkProvider\ProviderOrder'
        - 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\NetworkProvider'
version: '0.0.1'
doc: "Network Provider（网络提供者）是 Windows 网络子系统的一个扩展机制，用于实现对网络资源（如共享文件夹、打印机、云盘等）的访问和认证。\n可以在 HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\ 寻找相关服务。"
```

采集 Windows 上 `Network Provider` 相关信息



### PasswordFilter.yaml

```yaml
name: 'WindowsPasswordFilter'
author: 'NOPTeam'
sources:
  - type: 'REGISTRY_VALUE'
    supported_os: 'Windows'
    attributes:
      key_value_pairs:
        - key: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
          value: 'Notification Packages'
version: '0.0.1'
doc: "Password Filter（密码筛选器） 是 Windows 系统支持的一种可插拔认证扩展机制。\n它允许管理员自定义 DLL，在用户修改/设置密码时对新密码进行审核和处理。"
```

采集 Windows 上 `Password Filter` 相关信息



### Powershell.yaml

```yaml
name: WindowsPSConfig
doc: Windows 平台上 Powershell 的配置文件信息收集。
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: powershell
      args:
        - '-c'
        - '"$PROFILE | Select-Object *"'
urls:
  - >-
    https://learn.microsoft.com/zh-cn/Powershell/module/microsoft.Powershell.core/about/about_profiles?view=Powershell-7.4

---

name: WindowsPSAlias
doc: Windows 平台上 Powershell 的 Alias 信息。
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: powershell
      args:
        - '-c'
        - '"alias"'

---

name: PowershellLog
author: NOPTeam
sources:
  - type: FILE
    supported_os: Windows
    attributes:
      paths:
        - >-
          %%environ_systemroot%%\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Admin.evtx
        - >-
          %%environ_systemroot%%\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx
        - >-
          %%environ_systemroot%%\System32\Winevt\Logs\Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager%4Operational.evtx
version: 0.0.1
doc: Powershell 相关日志收集。

```

采集 Windows 平台上 Powershell 的配置信息



### Process.yaml

```yaml
name: 'WindowsProcess'
author: 'NOPTeam'
sources:
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'tasklist'
      args:
        - '/v'
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'tasklist'
      args:
        - '/m'
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'tasklist'
      args:
        - '/svc'
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'powershell'
      args:
        - '-c'
        - '"gps"'
  - type: 'WMI'
    supported_os: 'Windows'
    attributes:
      base_object: ''
      query: 'SELECT * FROM Win32_Process'
version: '0.0.1'
doc: 'Windows 平台上进程信息。'
```

采集 Windows 平台上进程相关信息



### RDP.yaml

```yaml
name: 'WindowsRDP'
author: 'NOPTeam'
sources:
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Terminal Server Client\Default'
        - 'HKEY_USERS\%%users_sid%%\Software\Microsoft\Terminal Server Client\Servers'
  - type: 'FILE'
    supported_os: 'Windows'
    attributes:
      paths:
        - '%%users_userprofile%%\Documents\Default.rdp'
version: '0.0.1'
doc: 'Windows 平台上 RDP 相关信息收集。'
```

采集 Windows 平台上 RDP 相关信息



### Screen.yaml

```yaml
name: 'WindowsScreen'
author: 'NOPTeam'
sources:
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_USERS\%%users_sid%%\Control Panel\Desktop'
version: '0.0.1'
doc: 'Windows 平台上屏幕保护排查。'
```

采集 Windows 平台上屏幕保护相关信息



### SensitiveDir.yaml

```yaml
name: 'WindowsSensitiveDir'
author: 'NOPTeam'
sources:
  - type: 'PATH'
    supported_os: 'Windows'
    attributes:
      paths:
        - '%%users_temp%%'
        - 'C:\Windows\Temp'
  - type: 'PATH'
    supported_os: 'Windows'
    attributes:
      paths:
        - 'C:\$Recycle.Bin'
  - type: 'PATH'
    supported_os: 'Windows'
    attributes:
      paths:
        - '%%environ_systemdrive%%\Users\Public'
version: '0.0.1'
doc: 'Windows 平台上敏感目录收集。'
```

采集 Windows 平台上敏感目录排查，例如各个用户的 temp 目录
**需要注意：** 这些目录可能内容很多，需要根据实际情况选择是否收集



### Service.yaml

```yaml
name: WindowsServices
doc: Windows 平台上服务信息。
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: sc
      args:
        - queryex
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: powershell
      args:
        - '-c'
        - '"Get-Service | Select *"'
  - type: WMI
    supported_os: Windows
    attributes:
      base_object: ''
      query: SELECT * FROM Win32_Service
  - type: REGISTRY_KEY
    supported_os: Windows
    attributes:
      keys:
        - >-
          HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
        - >-
          HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
        - >-
          HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
        - >-
          HKEY_USERS\%%users_sid%%\Software\Microsoft\Windows\CurrentVersion\RunServices

```

采集 Windows 平台上服务相关信息



### Systeminfo.yaml

```yaml
name: WindowsSysteminfo
doc: Windows 平台上系统基本信息以及补丁信息。
author: NOPTeam
version: 0.0.1
sources:
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: systeminfo
      args: []
  - type: COMMAND
    supported_os: Windows
    attributes:
      cmd: wmic
      args:
        - qfe
        - list
```

采集 Windows 平台上系统基本信息以及补丁信息



### TaskScheduler.yaml

```yaml
name: 'WindowsTaskScheduler'
doc: 'Windows 计划任务（Task Scheduler）信息收集。'
author: 'NOPTeam'
version: '0.0.1'
sources:
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'schtasks'
      args:
        - '/query'
        - '/fo'
        - 'LIST'
        - '/v'
  - type: 'PATH'
    supported_os: 'Windows'
    attributes:
      paths:
        - 'C:\Windows\System32\Tasks'
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\*'
  - type: 'FILE'
    supported_os: 'Windows'
    attributes:
      paths:
        - 'C:\Windows\Tasks\SchedLgU.txt'
        - 'C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler*.evtx'
```

采集 Windows 平台上的计划任务信息。



### WinsockNSP.yaml

```yaml
name: 'WindowsWinsockNSP'
author: 'NOPTeam'
sources:
  - type: 'REGISTRY_KEY'
    supported_os: 'Windows'
    attributes:
      keys:
        - 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries\*'
        - 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64\*'
        - 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64\*'
        - 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\*'
version: '0.0.1'
doc: "WinSock NSP（WinSock Namespace Provider）是指在 Windows 操作系统中实现⽹络套接字编程接⼝（Socket API）的组件之⼀。它负责提供⽹络通信的底层功能，使应⽤程序能\n够通过⽹络进⾏数据传输。\nWinSock NSP 通过⼀组动态链接库（DLL）来实现，这些 DLL 包含了实现⽹络协议栈和通信协议的代码。它们提供了⼀种标准化的编程接⼝，使开发⼈员能够使⽤常⻅的⽹络协议（如TCP/IP、UDP）进⾏⽹络通信。\n通过 WinSock NSP，开发⼈员可以创建套接字、建⽴连接、发送和接收数据等⽹络操作。\n它提供了⼀系列函数和数据结构，使应⽤程序能够⽅便地进⾏⽹络编程，实现⽹络通信功能"

```

采集 Windows 平台上 WinSock Namespace Provider 信息



### WMI.yaml

```yaml
name: 'WindowsWmi'
author: 'NOPTeam'
sources:
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'wmic'
      args:
        - '/namespace:"\\root\subscription"'
        - 'path'
        - '__EventFilter'
        - 'get'
        - '*'
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'wmic'
      args:
        - '/namespace:"\\root\DEFAULT"'
        - 'path'
        - '__EventFilter'
        - 'get'
        - '*'
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'wmic'
      args:
        - '/namespace:"\\root\subscription"'
        - 'path'
        - '__EventConsumer'
        - 'get'
        - '*'
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'wmic'
      args:
        - '/namespace:"\\root\DEFAULT"'
        - 'path'
        - '__EventConsumer'
        - 'get'
        - '*'
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'wmic'
      args:
        - '/namespace:"\\root\subscription"'
        - 'path'
        - '__FilterToConsumerBinding'
        - 'get'
        - '*'
  - type: 'COMMAND'
    supported_os: 'Windows'
    attributes:
      cmd: 'wmic'
      args:
        - '/namespace:"\\root\DEFAULT"'
        - 'path'
        - '__FilterToConsumerBinding'
        - 'get'
        - '*'
  - type: 'WMI'
    supported_os: 'Windows'
    attributes:
      base_object: 'root\subscription'
      query: 'SELECT * FROM __EventFilter'
  - type: 'WMI'
    supported_os: 'Windows'
    attributes:
      base_object: 'root\DEFAULT'
      query: 'SELECT * FROM __EventFilter'
  - type: 'WMI'
    supported_os: 'Windows'
    attributes:
      base_object: 'root\subscription'
      query: 'SELECT * FROM __EventConsumer'
  - type: 'WMI'
    supported_os: 'Windows'
    attributes:
      base_object: 'root\DEFAULT'
      query: 'SELECT * FROM __EventConsumer'
  - type: 'WMI'
    supported_os: 'Windows'
    attributes:
      base_object: 'root\DEFAULT'
      query: 'SELECT * FROM __EventConsumer'
  - type: 'WMI'
    supported_os: 'Windows'
    attributes:
      base_object: 'root\subscription'
      query: 'SELECT * FROM __FilterToConsumerBinding'
version: '0.0.1'
doc: 'Windows 平台上 WMI 后门信息收集。'

```

采集 Windows 平台上 WMI 相关信息，用于判断是否存在 WMI 后门

----

目前 Linux 版本和 Windows 版本配置如上，如果大家有好的建议，可以提 PR 或者微信联系 `just_hack_for_fun` 反馈。




