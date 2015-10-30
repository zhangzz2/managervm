#!/usr/bin/python
#coding:utf-8

from setuptools import setup, find_packages
from setuptools.command.sdist import sdist
import os
import subprocess
import time
import sys

from managervm import __version__ as version

realpath = os.path.dirname(os.path.realpath(__file__))

class local_sdist(sdist):
    """Customized sdist hook - builds the ChangeLog file from VC first"""
    def run(self):
        print "hello"
        sdist.run(self)

name = 'managervm'

setup(
    name=name,
    version=version,
    description='',
    license='License',
    author='www.huayunwangji.com',
    author_email='',
    url='www.huayunwangji.com',
    packages=find_packages(exclude=['test', 'bin']),
    test_suite='nose.collector',
    cmdclass={'sdist': local_sdist},
    classifiers=[
        'Development Status :: 4 - Beta',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.6',
        'Environment :: No Input/Output (Daemon)',
        ],
    install_requires=[],  #removed for better compat
    scripts=[
       ],
    )
