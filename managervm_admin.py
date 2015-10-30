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
import json

from paramiko import SSHException
from optparse import OptionParser

from daemon import Daemon
import managervm_utils as mutils
#from managervm_utils import VM_SYSTEMDISK
#from managervm_utils import DINFO, DWARN, DERROR, exec_cmd, exec_cmd_remote, VM_CHANNEL, VM_SYSTEMDISK

def check_hosts(hosts_all, hosts_online):
    if sorted(hosts_all) == sorted(hosts_online):
        return

    expire = time.time() + 60
    while True:
        if expire < time.time():
            break

        _hosts_online = [x for x in hosts_all if mutils.ping_ok(x)]
        if sorted(_hosts_online) != sorted(hosts_online):
            raise Exp(1, "there was host reconnect or disconnect, i am not sure the network")

        diff = set(hosts_all) - set(_hosts_online)
        mutils.DINFO("host %s was stopped, i need time to make sure this" % (list(diff)))
        time.sleep(1)

def make_sure_vm_start(hosts_online):
    hosts = mutils.get_hosts_runningvm(hosts_online)
    if (len(hosts) > 1):
        error = "manager vm was double, crazy, running with %s, kill all" % (hosts)
        mutils.DERROR(error)
        for host in hosts:
            vm_stop(host)
        raise Exp(1, error)

    if hosts:
        mutils.DINFO("manager vm already is running in %s" % (host))
        return None

    host = mutils.select_host()
    mutils.DINFO("select host %s, and start" % (host))
    mutils.vm_start(host)
    mutils.DINFO("vm running...")
    mutils.DINFO("wait network...")
    wait_network(host)
    mutils.DINFO("network ok")

def make_sure_vm_stop_local():
    cmd = "hostname"
    host, stderr =  mutils.exec_cmd(cmd)

    if mutils.is_vm_running([host]):
        mutils.DWARN("%s lich was stopped, so kill kvm" % (host))
        mutils.vm_stop(host)
        mutils.DWARN("%s kill kvm ok" % (host))

def wait_network(host):
    ip = mutils.get_attr('ip')
    while True:
        if mutils.ping_ok(ip):
            break

        info = mutils.get_inject_info()
        mutils.DINFO("inject info %s" % (info))
        mutils.inject_info(host, info)
        mutils.DINFO("inject info ok")
        time.sleep(30)

def worker():
    if not mutils.is_lich_ready():
        make_sure_vm_stop_local()
        mutils.DINFO("lich not ready, exit.")
        exit()

    if not mutils.is_managervm_ready():
        mutils.DINFO("managervm not ready, exit.")
        exit()

    if not mutils.is_admin():
        mutils.DINFO("i am not admin, exit.")
        exit()

    if not mutils.is_managervm_ha():
        mutils.DINFO("manager vm was set to no HA, so just exit...")
        exit()

    hosts_all = mutils.cluster_hosts()
    hosts_online = [x for x in hosts_all if mutils.ping_ok(x)]
    check_hosts(hosts_all, hosts_online)

    if mutils.is_vm_running(hosts_online):
        mutils.DINFO("manager vm is running, it's ok, exit.")
        exit()

    mutils.DINFO("manager vm is stopped, start it ...")
    make_sure_vm_start(hosts_online)
    mutils.DINFO("manager vm start ok.")

class Admin(Daemon):
    def run(self):
        worker()

if __name__ == "__main__":
    usage = "usage: %prog [options] arg1 arg2"
    parser = OptionParser(usage=usage)

    parser.add_option('', "--start",
        action="store_true", dest="start", default=None,
        help="you can start it as a daemon with --daemon")
    parser.add_option('', "--stop",
        action="store_true", dest="stop", default=None,
        help="")
    parser.add_option('', "--restart",
        action="store_true", dest="restart", default=None,
        help="")
    parser.add_option('', "--stat",
        action="store_true", dest="stat", default=None,
        help="")
    parser.add_option('-d', "--daemon",
        action="store_true", dest="daemon", default=None,
        help="")

    if (len(sys.argv) <= 1):
        parser.print_help()
        exit(1)

    (options, args) = parser.parse_args()

    pidfile = "/var/run/managervm_admin.pid"
    stdout = "/var/log/managervm_admin.log"
    stderr = stdout
    admin = Admin(pidfile, stdout=stdout, stderr=stderr, name="managervm_admin")

    if options.start:
        if options.daemon:
            print 'start as daemon'
            admin.start()
        else:
            worker()
    elif options.stop:
        admin.stop()
    elif options.stat:
        if admin.stat():
            cmd = "cat %s" % admin.pidfile
            stdout, stderr = mutils.exec_cmd(cmd)
            pid = stdout.strip()
            print 'running pid: %s' % pid
        else:
            print 'stopped'
    elif options.restart:
        admin.restart()
    else:
        mutils.DERROR("not support")
        exit(1)
