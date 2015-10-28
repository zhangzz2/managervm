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

#todo del DINFO, this module will not use DINFO

VM_SYSTEMDISK = "/lichbd/managervm/managervm_systemdisk"
VM_SYSTEMDISK_QEMU = "lichbd:managervm/managervm_systemdisk"
VM_CHANNEL = "/opt/mds/managervm/agentSocket/applianceVm,server"
IFUP_FILE = "/root/zhangjf_vm/qemu-ifup-public"

def DINFO(msg):
    print datetime.datetime.now(), msg

def DWARN(msg):
    print >> sys.stderr, datetime.datetime.now(), msg

def DERROR(msg):
    print >> sys.stderr, datetime.datetime.now(), msg

class Exp(Exception):
    def __init__(self, errno, err, out = None):
        self.errno = errno
        self.err = err
        self.out = out

    def __str__(self):
        exp_info = 'errno:%s, err:%s'%(self.errno, self.err)
        if self.out is not None:
            exp_info += ' stdout:' + self.out
        return repr(exp_info)

def _session_recv(session):
    try:
        data = session.recv(4096)
    except socket.timeout as err:
        data = ""

    return data

def _session_recv_stderr(session):
    try:
        data = session.recv_stderr(4096)
    except socket.timeout as err:
        data = ""

    return data

def exec_cmd_remote(host, cmd, user = "root", password=None, timeout = 1, exception=False):
    stdout = ""
    stderr = ""
    status = 0

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, 22, user, password, timeout = timeout)
        transport = client.get_transport()
        session = transport.open_channel(kind='session')
        session.settimeout(3)
        session.exec_command(cmd)

        while True:
            if session.recv_ready():
                data = _session_recv(session)
                stdout = stdout + data

            if session.recv_stderr_ready():
                data = _session_recv_stderr(session)
                stderr = stderr + data

            if session.exit_status_ready():
                while True:
                    data = _session_recv(session)
                    if data == "":
                        break
                    stdout = stdout + data

                while True:
                    data = _session_recv_stderr(session)
                    if data == "":
                        break
                    stderr = stderr + data

                break

        status = session.recv_exit_status()

    except socket.timeout as err:
        raise Exp(err.errno, 'Socket timeout')
    except socket.error as err:
        raise Exp(err.errno, err.strerror)
    except paramiko.AuthenticationException as err:
        raise Exp(250, 'Authentication failed')

    session.close()
    client.close()

    if exception and status != 0:
        raise Exp(status, stderr)
        
    return stdout, stderr, status


def alarm_handler(signum, frame):
    raise Exception(errno.ETIME, "command execute time out")

def exec_cmd(cmd, retry = 3, p = False, timeout = 0):
    env = {"LANG" : "en_US", "LC_ALL" : "en_US", "PATH" : os.getenv("PATH")}
    #cmd = self.lich_inspect + " --movechunk '%s' %s  --async" % (k, loc)
    _retry = 0
    if (p):
        DINFO(cmd)
    while (1):
        p = None
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, env = env)
        except Exception, e:
            raise Exp(e.errno, cmd + ": command execute failed")

        if timeout != 0:
            signal.signal(signal.SIGALRM, alarm_handler)
            signal.alarm(timeout)
        try:
            stdout, stderr = p.communicate()
            signal.alarm(0)
            ret = p.returncode
            if (ret == 0):
                return stdout, stderr
            elif (ret == errno.EAGAIN and _retry < retry):
                _retry = _retry + 1
                time.sleep(1)
                continue
            else:
                raise Exp(ret, cmd + ": " + os.strerror(ret))

        except KeyboardInterrupt as err:
            _dwarn("interupted")
            p.kill()
            exit(errno.EINTR)

def genmac():
    return 'DE:AD:BE:EF:E1:3C'

def set_attr(key, value):
    path = os.path.dirname(VM_SYSTEMDISK)
    cmd = "/opt/mds/lich/libexec/lich --attrset %s %s %s" % (path, key, value)
    exec_cmd(cmd)

def get_attr(_key, _default=None):
    path = os.path.dirname(VM_SYSTEMDISK)
    cmd = " /opt/mds/lich/libexec/lich --attrget %s %s" % (path, _key)
    try:
        stdout, stderr = exec_cmd(cmd)
        return stdout.strip()
    except Exp, e:
        pass

    if _default is None:
        raise Exp(e.errno, str(e))

    #todo no enokey
    if e.errno == 126:
        return _default
    else:
        raise Exp(e.errno, str(e))

def set_cpu():
    _cpu_num = get_attr("cpu", "1")
    cpu_num = _raw_input("cpu num [%s]:" % (_cpu_num), _cpu_num)
    set_attr("cpu", cpu_num)

def set_mem():
    _mem = get_attr("mem", "512")
    mem = _raw_input("mem MB [%s]:" % (_mem), _mem)
    set_attr("mem", mem)

def set_bridge():
    _br = get_attr("bridge", "lichvirbr0")
    br = _raw_input("bridge name [%s]:" % (_br), _br)
    set_attr("bridge", br)

def set_eth():
    _eth = get_attr("eth", "eth0")
    eth = _raw_input("Ethernet name [%s]:" % (_eth), _eth)
    set_attr("eth", eth)

def set_mac():
    _mac = get_attr('mac', genmac())
    mac = _raw_input("mac [%s]:" % (_mac), _mac)
    set_attr("mac", mac)

def set_ip():
    _ip = get_attr('ip', "0.0.0.0")
    ip = _raw_input("ip [%s]:" % (_ip), _ip)
    set_attr("ip", ip)

def set_vnc():
    _vnc = get_attr('vnc', "87")
    vnc = _raw_input("vnc [%s]:" % (_vnc), _vnc)
    set_attr("vnc", vnc)

def ping_ok(ip):
    pass

def _raw_input(info, default=None):
    value = raw_input(info)
    if value.strip() == "":
        value = default

    return value

def vm_start(host):
    #cpu 1, mem 512, lichvirbr0, "fa:a1:99:c8:e7:25" "/opt/mds/managervm/agentSocket/applianceVm"  "vnc: 87"
    #qemu-system-x86_64 --enable-kvm -smp 1 -m 512 -drive file=lichbd:managervm/managervm_systemdisk,id=drive1,format=raw,cache=none,if=none,aio=native -device virtio-blk-pci,drive=drive1,scsi=off,x-data-plane=on  -net nic,macaddr=fa:a1:99:c8:e7:25 -net tap,script=/root/zhangjf_vm/qemu-ifup-public -chardev socket,id=charchannel0,path=/opt/mds/managervm/agentSocket/applianceVm,server,nowait -device virtio-serial -device virtserialport,nr=1,chardev=charchannel0,id=channel0,name=applianceVm.vport -vnc :87 -daemonize
    cpu = get_attr('cpu')
    mem = get_attr('mem')
    bridge = get_attr('bridge')
    eth = get_attr('eth')
    mac = get_attr('mac')
    ip = get_attr('ip')
    channel = VM_CHANNEL
    vnc = get_attr('vnc')

    systemdisk = VM_SYSTEMDISK_QEMU  
    ifup_file = IFUP_FILE 
    host = select_host()

    network_prep(host, bridge, eth, ifup_file)
    other_prep(host)

    cmd = "qemu-system-x86_64 --enable-kvm -smp %s -m %s -drive file=%s,id=drive1,format=raw,cache=none,if=none,aio=native -device virtio-blk-pci,drive=drive1,scsi=off,x-data-plane=on  -net nic,macaddr=%s -net tap,script=%s -chardev socket,id=charchannel0,path=%s,server,nowait -device virtio-serial -device virtserialport,nr=1,chardev=charchannel0,id=channel0,name=applianceVm.vport -vnc :%s -daemonize" % (cpu, mem, systemdisk, mac, ifup_file, channel, vnc)
    DINFO([host, cmd])

    stdout, stderr, status = exec_cmd_remote(host, cmd)
    DINFO(stdout)
    if status != 0:
        raise Exp(status, stderr)

def vm_stop(host):
    cmd = "set -o pipefail;ps aux|grep kvm|grep %s|grep -v grep|awk '{print $2}'|xargs kill -9" % ('managervm_systemdisk')
    stdout, stderr, status = exec_cmd_remote(host, cmd)
    DINFO(stdout)
    if status != 0:
        raise Exp(status, stderr)

def cluster_hosts():
    stdout, stderr = exec_cmd("cat /opt/mds/etc/cluster.conf |grep -v version")
    hosts = stdout.strip().split('\n')
    return hosts

def select_host():
    stdout, stderr = exec_cmd("cat /opt/mds/data/node/config/name")
    host = stdout.strip()
    return host

def _vm_is_running_host(host):
    cmd = 'set -o pipefail;ps aux|grep kvm|grep %s|grep -v grep' % ('managervm_systemdisk')
    stdout, stderr, status = exec_cmd_remote(host, cmd)
    #print host, stdout, stderr, status, 'zz'
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
    path = os.path.dirname(VM_SYSTEMDISK)
    ready = get_attr('ready', 'no')
    return ready == 'yes'

def set_managervm_ready():
    path = os.path.dirname(VM_SYSTEMDISK)
    set_attr("ready", "yes")

def set_managervm_noready():
    path = os.path.dirname(VM_SYSTEMDISK)
    set_attr("ready", "no")

def set_managervm_noha():
    path = os.path.dirname(VM_SYSTEMDISK)
    set_attr("ha", "no")

def set_managervm_ha():
    path = os.path.dirname(VM_SYSTEMDISK)
    set_attr("ha", "yes")

def is_managervm_ha():
    path = os.path.dirname(VM_SYSTEMDISK)
    ha = get_attr('ha', 'no')
    return ha == 'yes'

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


def find_bridge_having_physical_eth(host, ifname):
    cmd = "brctl show|sed -n '2,$p'|cut -f 1,6"
    stdout, stderr, status = exec_cmd_remote(host, cmd, exception=True)
    for l in stdout.split('\n'):
        l = l.strip(' \n\t\r')
        if l == '':
            continue

        try:
            (br_name, iface_name) = l.split()
        except:
            # bridge has no physical eth added
            continue

        if ifname == iface_name:
            return br_name
    
    return None

def is_network_device_existing(host, dev):
    cmd = 'ip link show %s' % dev
    stdout, stderr, status = exec_cmd_remote(host, cmd)
    return status == 0

def deploy_file(host, src, dst):
    exec_cmd("scp -r %s %s:%s" % (src, host, dst))

def ifup_script_prep(host):
    bridge = get_attr("bridge")
    script = """#!/bin/sh
set -x

switch=%s

if [ -n "$1" ];then
    /usr/bin/sudo /usr/sbin/tunctl -u `whoami` -t $1
    /usr/bin/sudo /sbin/ip link set $1 up
    sleep 0.5s
    /usr/bin/sudo /usr/sbin/brctl addif $switch $1
    exit 0
else
    echo "Error: no eth specified"
    exit 1
fi
    """ % (bridge)

    src = "/tmp/qemu-ifup"
    dst = IFUP_FILE
    with open(src, 'w') as f:
        f.write(script)

    deploy_file(host, src, dst)

def network_prep(host, bridge, eth, move_route=True):
    _bridge = find_bridge_having_physical_eth(host, eth)
    if _bridge and _bridge != bridge:
        raise Exp(1, 'failed to create bridge[{0}], physical eth[{1}] has been occupied by bridge[{2}]'.format(bridge, eth, _bridge))

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
    
    cmd = 'ip addr show dev %s | grep "inet "' % (eth)
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

    #mv ip on eth to bridge
    ip = out.strip().split()[1]
    exec_cmd_remote(host, 'ip addr del %s dev %s' % (ip, eth), exception=True)
    exec_cmd_remote(host, 'ip addr add %s dev %s' % (ip, bridge_name), exception=True)

    #restore routes on bridge
    for r in routes:
        exec_cmd_remote(host, 'ip addr add %s dev %s' % (ip, bridge), exception=True)

def other_prep(host):
    channel = VM_CHANNEL
    cmd = "mkdir -p %s" % (os.path.dirname(channel))
    stdout = exec_cmd_remote(host, cmd, exception=True)
    DINFO([cmd, stdout])

    ifup_script_prep(host)
    DINFO([host, 'qemu-ifup deploy ok'])


if __name__ == "__main__":
    print "hello, word!"
    cpu_num = raw_input("cpu num [1]:")
    print type(cpu_num)
    print cpu_num
