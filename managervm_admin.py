#!/usr/bin/env python2
#-*- coding: utf-8 -*-

import datetime
import errno
import os
import fcntl
import paramiko
import sys
import subprocess
import signal
import time

from paramiko import SSHException

from managervm_utils import VM_SYSTEMDISK
from managervm_utils import DINFO, DWARN, DERROR, exec_cmd, exec_cmd_remote

def _vm_is_running_host(host):
    cmd = 'ps aux|grep kvm|grep %s' % ('managervm_systemdisk')
    stdout, stderr, status = exec_cmd_remote(host, cmd)
    if status == 0:
        return True
    return False

def _vm_start_host(host):
    pass

def _vm_stop_host(host):
    pass

def is_admin():
    try:
        exec_cmd("lich.node --stat -v|grep 'status:admin$'")
    except Exp:
        return False
    return True

def is_lich_ready():
    try:
        exec_cmd("lich.cluster --stat|grep capacity")
    except Exp:
        return False
    return True

def is_managervm_ready():
    _path = "/lichbd/managervm"
    ready = get_attr('ready', 'no')
    return ready == 'yes'

def get_host_runningvm():
    for host in cluster_hosts():
        if _vm_is_running_host(host):
            return host

    return None

def vm_is_running():
    host = get_host_runningvm()
    if host:
        return True

    return False


def find_bridge_having_physical_interface(host, ifname):
    cmd = "brctl show|sed -n '2,$p'|cut -f 1,6"
    stdout, stderr, status = exec_cmd_remote(host, cmd, exception=True)
    for l in stdout.split('\n'):
        l = l.strip(' \n\t\r')
        if l == '':
            continue

        try:
            (br_name, iface_name) = l.split()
        except:
            # bridge has no physical interface added
            continue

        if ifname == iface_name:
            return br_name
    
    return None

def is_network_device_existing(host, dev):
    cmd = 'ip link show %s' % dev
    stdout, stderr, status = exec_cmd_remote(host, cmd)
    return status == 0

def deploy_file(host, src, dst):
    exec_cmd("scp -r %s %s:%s" % (host, src, dst))

def ifup_script_prep(host):
    script = """#!/bin/sh
set -x

switch=lichvirbr0

if [ -n "$1" ];then
    /usr/bin/sudo /usr/sbin/tunctl -u `whoami` -t $1
    /usr/bin/sudo /sbin/ip link set $1 up
    sleep 0.5s
    /usr/bin/sudo /usr/sbin/brctl addif $switch $1
    exit 0
else
    echo "Error: no interface specified"
    exit 1
fi
    """

    src = "/tmp/qemu-ifup"
    dst = "/root/zhangjf_vm/qemu-ifup-public"
    open(tmp_local, 'w') as f:
        f.write(script)

    deploy_file(host, src, dst)

def network_prep(host, bridge, eth, ifup, move_route=True):
    _bridge = find_bridge_having_physical_interface(host, interface)
    if _bridge and _bridge != bridge:
        raise Exp(1, 'failed to create bridge[{0}], physical interface[{1}] has been occupied by bridge[{2}]'.format(bridge, eth, _bridge))

    if _bridge == bridge:
        return

    if not is_network_device_existing(host, bridge):
        exec_cmd_remote(host, "brctl addbr %s" % bridge, exception=True)
        exec_cmd_remote(host, "brctl setfd %s 0" % bridge, exception=True)
        exec_cmd_remote(host, "brctl stp %s off" % bridge, exception=True)
        exec_cmd_remote(host, "ip link set %s up" % bridge, exception=True)

    if not is_network_device_existing(host, eth):
        raise Exp(2, "network device[%s] is not existing" % eth)

    exec_cmd_remote(host, "brctl addif %s %s" % (bridge, eth), exception=True)
    
    if not move_route:
        return
    
    cmd = 'ip addr show dev %s | grep "inet "' % (eth, exception=False)
    stdout, stderr, status = exec_cmd_remote(host, cmd, exception=True)
    if not stdout:
    	DINFO("Interface %s doesn't set ip address yet. No need to move route. " % eth)
        return

    #record old routes
    routes = []
    stdout, stderr, status = exec_cmd_remote(host, 'ip route show dev %s' % eth, exception=True)
    for line in stdout.split('\n'):
        if 'via' in line:
            routes.append(line)
            exec_cmd_remote(host, 'ip route del %s' % line, exception=True)

    #mv ip on interface to bridge
    ip = out.strip().split()[1]
    exec_cmd_remote(host, 'ip addr del %s dev %s' % (ip, interface), exception=True)
    exec_cmd_remote(host, 'ip addr add %s dev %s' % (ip, bridge_name), exception=True)

    #restore routes on bridge
    for r in routes:
        exec_cmd_remote(host, 'ip addr add %s dev %s' % (ip, bridge), exception=True)

def other_prep(host, channel):
    cmd = "mkdir -p %s" % ("/opt/mds/managervm/agentSocket/applianceVm")
    stdout = exec_cmd_remote(host, cmd, execption=True)
    DINFO([cmd, stdout])

    ifup_script_prep(host)
    DINFO([host, 'qemu-ifup deploy ok'])

def vm_start(host):
    #cpu 1, mem 512, lichvirbr0, "fa:a1:99:c8:e7:25" "/opt/mds/managervm/agentSocket/applianceVm"  "vnc: 87"
    #qemu-system-x86_64 --enable-kvm -smp 1 -m 512 -drive file=lichbd:managervm/managervm_systemdisk,id=drive1,format=raw,cache=none,if=none,aio=native -device virtio-blk-pci,drive=drive1,scsi=off,x-data-plane=on  -net nic,macaddr=fa:a1:99:c8:e7:25 -net tap,script=/root/zhangjf_vm/qemu-ifup-public -chardev socket,id=charchannel0,path=/opt/mds/managervm/agentSocket/applianceVm,server,nowait -device virtio-serial -device virtserialport,nr=1,chardev=charchannel0,id=channel0,name=applianceVm.vport -vnc :87 -daemonize
    cpu = get_attr('cpu')
    mem = get_attr('mem')
    bridge = get_attr('bridge')
    eth = get_attr('eth')
    mac = get_attr('mac')
    ip = get_attr('ip')
    channel = get_attr('channel')
    vnc = get_attr('vnc')

    systemdisk = "lichbd:lichbd:managervm/managervm_systemdisk"
    ifup = "/root/zhangjf_vm/qemu-ifup-public"
    host = select_host()

    network_prep(host, bridge, eth, ifup):

    cmd = "qemu-system-x86_64 --enable-kvm -smp %s -m %s -drive file=%s,id=drive1,format=raw,cache=none,if=none,aio=native -device virtio-blk-pci,drive=drive1,scsi=off,x-data-plane=on  -net nic,macaddr=%s -net tap,script=%s -chardev socket,id=charchannel0,path=%s,server,nowait -device virtio-serial -device virtserialport,nr=1,chardev=charchannel0,id=channel0,name=applianceVm.vport -vnc :%s -daemonize" % (cpu, mem, systemdisk, mac, ifup, channel, vnc)
    DINFO([host, cmd])

    stdout, stderr, status = exec_cmd_remote(host, cmd)
    DINFO(stdout)
    if status != 0:
        raise Exp(status, stderr)

def vm_stop():
    pass

def cluster_hosts():
    stdout, stderr = exec_cmd("cat /opt/mds/etc/cluster.conf |grep -v version")
    hosts = stdout.strip().split('\n')
    return hosts

def select_host():
    stdout, stderr = exec_cmd("cat /opt/mds/data/node/config/name")
    host = stdout.strip()
    return host

def make_sure_vm_start():
    host = get_host_runningvm()
    if host:
        DINFO("manager vm already is running in %s" % (host))
        return None

    host = select_host()
    vm_start(host)
    DINFO("manager vm select host %s, and start" % (host))

"""
op_admin: '192.168.1.1';
op_vmhost: '';
op_vmhostall: '';
op_bridge: '';
op_mac: '';
op_ip: '';
op_cpu: '';
op_mem: '';
"""

if __name__ == "__main__":
    print "hello, word!"
    if not is_lich_ready():
        DINFO("lich not ready, exit.")
        exit()

    if not is_managervm_ready():
        DINFO("managervm not ready, exit.")
        exit()

    if not is_admin():
        DINFO("i am not admin, exit.")
        exit()

    if vm_is_running():
        DINFO("manager vm is running, it's ok, exit.")
        exit()

    DINFO("manager vm is stopped, start it ...")
    make_sure_vm_start()
    DINFO("manager vm start ok.")
