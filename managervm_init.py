#!/usr/bin/env python2
#-*- coding: utf-8 -*-

import os

from managervm_utils import VM_SYSTEMDISK
from managervm_utils import exec_cmd

def install_systemdisk():
    pass

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
        DERROR(str(e))

    if _default is None:
        raise Exp(e.errno, str(e))

    #todo no enokey
    if e.errno = 126:
        return _default
    else:
        raise Exp(e.errno, str(e))

def set_cpu():
    cpu_num = _raw_input("cpu num [1]:", 1)
    set_attr("cpu", cpu_num)

def set_mem():
    mem = _raw_input("mem MB [512]:", 512)
    set_attr("mem", mem)

def set_bridge():
    br = _raw_input("bridge name [lichvirbr0]:", "eth0")
    set_attr("bridge", br)

def set_eth():
    eth = _raw_input("Ethernet name [eth0]:", "eth0")
    set_attr("eth", eth)

def set_mac():
    #todo get mac first as default
    _mac = get_attr('mac')
    mac = _raw_input("mac name [eth0]:", _mac)
    set_attr("mac", mac)

def _raw_input(info, default=None):
    value = raw_input(info)
    if value.strip() == "":
        value = default

    return value

if __name__ == "__main__":
    print "hello, word!"
    set_cpu()
