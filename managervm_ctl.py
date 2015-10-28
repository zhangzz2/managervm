#!/usr/bin/env python2
#-*- coding: utf-8 -*-

import os
import sys
from optparse import OptionParser

import managervm_utils as mutils

def upload_systemdisk(local_file):
    cmd = "set -o pipefail; qemu-img info %s | grep 'file format' | cut -d ':' -f 2" % (local_file)
    stdout, stderr = mutils.exec_cmd(cmd)
    format = stdout.strip()
    if format != "raw":
        raise Exp(1, 'need raw, not support %s' % format)

    cmd = "/opt/mds/lich/libexec/lich --copy :%s %s" % (local_file, mutils.VM_SYSTEMDISK)
    mutils.exec_cmd(cmd)

def conf():
    mutils.set_cpu()
    mutils.set_mem()
    mutils.set_bridge()
    mutils.set_eth()
    mutils.set_mac()
    mutils.set_ip()
    mutils.set_vnc()
    mutils.set_managervm_ready()

def status():
    cpu = mutils.get_attr("cpu", "")
    mem = mutils.get_attr("mem", "")
    bridge = mutils.get_attr("bridge", "")
    eth = mutils.get_attr("eth", "")
    mac = mutils.get_attr("mac", "")
    ip = mutils.get_attr("ip", "")
    vnc = mutils.get_attr("vnc", "")
    host = mutils.get_host_runningvm()
    is_managervm_ha = mutils.is_managervm_ha()
    is_managervm_ready = mutils.is_managervm_ready()
    is_lich_ready = mutils.is_lich_ready()

    #todo show info of systemdisk 

    if host is None:
        print "vm was stopped"
    else:
        print "vm was running in %s" % (host)

    print 'managervm HA: %s' % is_managervm_ha
    print 'managervm ready: %s' % is_managervm_ready
    print 'lich ready: %s' % is_lich_ready
    print 'cpu: %s' % cpu
    print 'mem: %s' % mem
    print 'bridge: %s' % bridge
    print 'eth: %s' % eth
    print 'ip: %s' % ip 
    print 'mac: %s' % mac
    print 'vnc: %s' % vnc

def stop_vm():
    host = mutils.get_host_runningvm()
    if host is None:
        print 'vm was stopped'
        return

    mutils.vm_stop(host)
    mutils.set_managervm_noha()

def start_vm(host=None):
    if not mutils.is_managervm_ready():
        mutils.DERROR("managervm is not ready")
        return

    if not mutils.is_lich_ready():
        mutils.DERROR("lich is not ready")
        return

    _host = mutils.get_host_runningvm()
    if _host is not None:
        DERROR("vm was start in host %s" % (_host))
        return

    if host is None:
        host = mutils.select_host()

    print 'vm will start host %s' % (host)
    mutils.vm_start(host)
    mutils.set_managervm_ha()

def merge_vm():
    raise

if __name__ == "__main__":
    usage = "usage: %prog [options] arg1 arg2"  
    parser = OptionParser(usage=usage)  
    parser.add_option('', "--stop_vm",  
        action="store_true", dest="stop_vm", default=None,  
        help="")  
    parser.add_option('', "--start_vm",  
        action="store_true", dest="start_vm", default=None,  
        help="start_vm by auto select host, or you can assign a host by --host [HOST]")
    parser.add_option('', "--host",  
        action="store", dest="host", default=None,  
        help="assign a host")
    parser.add_option('', "--conf",  
        action="store_true", dest="conf", default=None,  
        help="conf some env for vm")
    parser.add_option('', "--status",  
        action="store_true", dest="status", default=None,  
        help="get env of vm")
    parser.add_option('', "--upload_systemdisk",  
        action="store_true", dest="upload_systemdisk", default=None,  
        help="upload systemdisk, need assign a local file by --local_file [LOCALFILE]")
    parser.add_option('', "--local_file",  
        action="store", dest="local_file", default=None,  
        help="assign a local file that will be used as systemdisk, filename must be absolute path")

    if (len(sys.argv) <= 1):
        parser.print_help()
        exit(1)

    (options, args) = parser.parse_args()
    #print options
    #print args

    if options.stop_vm:
        stop_vm()
    elif options.start_vm:
        host = options.host
        if host is None:
            print 'will auto select host to start vm'
        start_vm(host)
    elif options.conf:
        conf()
    elif options.status:
        status()
    elif options.upload_systemdisk:
        local_file = options.local_file
        if local_file is None:
            mutils.DERROR("local_file was miss")
            exit(1)
        if not os.path.isabs(local_file):
            mutils.DERROR("local_file must be absolute path")
            exit(1)
        upload_systemdisk(local_file)
    else:
        mutils.DERROR("not support")
        exit(1)
