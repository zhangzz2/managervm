#!/usr/bin/env python2
#-*- coding: utf-8 -*-

import os
import sys
import json
import time

from optparse import OptionParser

from daemon import Daemon
import managervm_utils as mutils

def get_info():
    path = mutils.VM_PORT
    with open(path, 'r') as f:
        info = f.read()
        if info.strip():
            return json.loads(info)

    return {}

def __write_tmp_info(info, tmp_conf):
    ip = info.get('ip')
    netmask = info.get('netmask')
    gateway = info.get('gateway')
    mac = info.get("mac").lower()
    cmd = """set -o pipefail;cat /etc/udev/rules.d/70-persistent-net.rules |grep 'de:ad'|awk -F'"' '{print $(NF-1)}'"""
    stdout, stderr = mutils.exec_cmd(cmd)
    eth = stdout.strip()


    txt = """
DEVICE=%s
TYPE=Ethernet
ONBOOT=yes
NM_CONTROLLED=yes
BOOTPROTO=static
IPADDR=%s
NETMASK=%s
    """ % (eth, ip, netmask)

    if gateway.strip() in ["0.0.0.0", "", None]:
        pass
    else:
        txt = txt + "GATEWAY=%s" % (gateway)

    with open(tmp_conf, 'w') as f:
        f.write(txt)

def set_network(info):
    tmp_conf = "/tmp/eth_conf"
    dst_conf = "/etc/sysconfig/network-scripts/ifcfg-%s" % (eth)

    __write_tmp_info(info, tmp_conf):
    need_overwrite = True

    if os.path.isfile(dst_conf):
        try:
            cmd = "diff %s %s" % (tmp_conf, dst_conf)
            stdout, stderr = mutils.exec_cmd(cmd)
            need_overwrite = False
            mutils.DINFO("network no chanage, skip modify %s" % (dst_conf))
        except mutils.Exp, e:
            mutils.DWARN(e)

    if need_overwrite:
        mutils.DINFO("network changed, rewrite %s" % (dst_conf))
        cmd = "mv -f %s %s" % (tmp_conf, dst_conf)
        mutils.exec_cmd(cmd)
        mutils.DINFO("restart network")
        cmd = "/etc/init.d/network restart"
        mutils.exec_cmd(cmd)

def worker():
    info = get_info()
    if len(info.keys()) == 0:
        mutils.DERROR("info was null")
        return

    mutils.DINFO("set network %s" % (str(info)))
    set_network(info)

class Guest(Daemon):
    def run(self):
        while True:
            try:
                worker()
            except Exception, e:
                mutils.DERROR("%s" % (str(e)))
            mutils.DINFO("guest worker")
            time.sleep(15)

if __name__ == "__main__":
    usage = "usage: %prog [options] arg1 arg2"  
    parser = OptionParser(usage=usage)  

    parser.add_option('', "--start",  
        action="store_true", dest="start", default=None,  
        help="")
    parser.add_option('', "--stop",  
        action="store_true", dest="stop", default=None,  
        help="")
    parser.add_option('', "--restart",  
        action="store_true", dest="restart", default=None,  
        help="")
    parser.add_option('', "--stat",  
        action="store_true", dest="stat", default=None,  
        help="")

    if (len(sys.argv) <= 1):
        parser.print_help()
        exit(1)

    (options, args) = parser.parse_args()

    pidfile = "/var/run/managervm_guest.pid"
    stdout = "/var/log/managervm_guest.log"
    stderr = stdout
    guest = Guest(pidfile, stdout=stdout, stderr=stderr, name="managervm_guest")

    if options.start:
        guest.start()
    elif options.stop:
        guest.stop()
    elif options.stat:
        if guest.stat():
            cmd = "cat %s" % guest.pidfile
            stdout, stderr = mutils.exec_cmd(cmd)
            pid = stdout.strip()
            print 'running pid: %s' % pid
        else:
            print 'stopped'
    elif options.restart:
        guest.restart()
    else:
        mutils.DERROR("not support")
        exit(1)
