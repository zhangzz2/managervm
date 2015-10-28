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

import managervm_utils as mutils
#from managervm_utils import VM_SYSTEMDISK
#from managervm_utils import DINFO, DWARN, DERROR, exec_cmd, exec_cmd_remote, VM_CHANNEL, VM_SYSTEMDISK

def make_sure_vm_start():
    host = mutils.get_host_runningvm()
    if host:
        mutils.DINFO("manager vm already is running in %s" % (host))
        return None

    host = mutils.select_host()
    mutils.vm_start(host)
    mutils.DINFO("manager vm select host %s, and start" % (host))

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

def wait_network():
    ip = get_attr('ip')
    info = get_vminfo()
    while True:
        if ping_ok(ip):

def worker():
    if not mutils.is_lich_ready():
        mutils.DINFO("lich not ready, exit.")
        exit()

    if not mutils.is_managervm_ready():
        mutils.DINFO("managervm not ready, exit.")
        exit()

    if not mutils.is_admin():
        mutils.DINFO("i am not admin, exit.")
        exit()

    if mutils.vm_is_running():
        mutils.DINFO("manager vm is running, it's ok, exit.")
        exit()

    if not mutils.is_managervm_ha():
        mutils.DINFO("manager vm was set to no HA, so just exit...")
        exit()

    mutils.DINFO("manager vm is stopped, start it ...")
    make_sure_vm_start()
    mutils.DINFO("manager vm start ok.")
    mutils.DINFO("wait network...")
    wait_network()
    mutils.DINFO("network ok")

if __name__ == "__main__":
    worker()
