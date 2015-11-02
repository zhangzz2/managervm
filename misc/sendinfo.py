#!/usr/bin/env python2
#-*- coding: utf-8 -*-

import json
import socket

if __name__ == "__main__":
    print "hello, word!"
    info = {
            "additionalNics": [],
            "managementNic": {
                "deviceName": "eth0",
                "gateway": "192.168.1.1",
                "ip": "192.168.1.100",
                "isDefaultRoute": True,
                "mac": "fa:69:70:87:be:00",
                "netmask": "255.255.255.0"
            },
            "publicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEApfxaTkEEeF3p3TVpJi+XaBs8lpGuxnrBJXV6HAOh2qmJrJh2SfLZ+5M08iugdGR31/rZ84OYhAZ7pWwvdMUdTJuqcI+h48L97uyP4NXZI1Rj2fQk2STTNpn8jW8+6b40hwgiJmbFKBPZuXnhJ8r3JB0PjSGChlwfX+1dG/t+vsZ49vfpid35Om2rXKyXRCegXXE3EN74BpSmeW/QG6rs/U+8/TfaTLnn0dlU6vXgL0VMyoaOTSWmaLhIth6LPxf8nd5zuRGtTHV77JXMF5TXxPN39tcduZ8aPK/EhAtwHbVQRgbnxO0Pu4+yQW87xXdhd2PQssj0JLrIHkukSLzVow== root@zstack"
            }

    info = json.dumps(info)
    print info
    socket_path = "/opt/mds/managervm/agentSocket/applianceVm"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(socket_path)
    s.sendall(info)

    s.close()
