managervm

managervm 是什么：

    维护一个运行在lich中的虚拟机(虚拟机的系统盘直接放在存储中)。虚拟机里面安装管理系统。
    managervm 会检测到如果虚拟机在节点A上挂了，就会在节点B上启动起来。
    这样做为了使管理系统高可用。

managervm 的工作方式：

    managervm_admin
    这个命令要被安装到集群内每一个节点，会被cron定时任务服务周期唤醒。
    只有在 Lich 的 admin 所在的物理机上，才会继续执行该命令。
    唤醒后，会检查当前集群内虚拟机是否正常，如果虚拟机不正常就把虚拟机重启。
    直接执行managervm_admin　会打印出帮助

    managervm_ctl:
    这个命令行是帮助设置环境，和手动控制虚拟机的启动、关闭。
    直接执行managervm_ctl 会打印出帮助

    managervm_guest:
    这个命令安装在虚拟机内部。有时候managervm_admin 会向虚拟机发送信息，managervm_gutest
    会接收信息，进行处理。


快速入门:

    1) 
    下载安装包并解压后，然后进入解压后的目录，执行 python setup.py install 之后就安装成功了。
    需要在Lich集群每个节点上都执行安装。也要在虚拟机镜像中安装。

    2）
    配置，在任何一台上执行即可:
    如下，方括号里面的是默认值，如果直接确认按 Enter 键就会使用默认值。

    root@service25:~# managervm_ctl --conf
    cpu num [2]:
    mem MB [512]:
    bridge name [br_eth1]:
    Ethernet name [eth1]:
    mac [DE:AD:BE:EF:E1:3C]:
    ip [192.168.1.26]:
    netmask [255.255.255.0]:
    gateway [0.0.0.0]:
    vnc [87]:
    root@service25:~# 

    说明如下：
    cpu 是虚拟机的cpu个数
    mem 虚拟机内存
    bridge 是网桥名称
    Ethernet name 是和网桥绑定的物理网卡名称
    mac 虚拟机网卡的物理地址
    ip 虚拟机网卡的地址
    netmask 虚拟机网卡的掩码
    gateway 虚拟机的网关
    vnc 可以通过物理机哪个vnc端口访问虚拟机

    3)
    上传虚拟机模板
    在放有虚拟机镜像的机器上执行
    managervm_ctl --upload_systemdisk xxxxx

    4)
    然后启动虚拟机
    managervm_admin --start_vm

    5)
    配置定时任务
    为了让managervm周期维护虚拟机正常运行，需要在每个节点上配置cron。
    在每个节点上使用下面命令配置：
    managervm_ctl --add_admin_cron

    并在虚拟机里面执行: 
    managervm_ctl --add_guest_cron
