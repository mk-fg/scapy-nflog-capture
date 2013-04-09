#!/usr/bin/env python

import os, sys

from distutils.core import setup

# Error-handling here is to allow package to be built w/o README included
try:
	readme = open(os.path.join(
		os.path.dirname(__file__), 'README.txt' )).read()
except IOError: readme = ''

setup(

	name = 'scapy-nflog-capture',
	version = '13.04.5',
	author = 'Mike Kazantsev',
	author_email = 'mk.fraggod@gmail.com',
	license = 'WTFPL',
	keywords = [ 'nflog', 'scapy', 'plugin', 'driver', 'traffic', 'analysis',
		'analyze', 'capture', 'dump', 'network', 'linux', 'security', 'sniffer', 'spoof',
		'netfilter', 'iptables', 'xtables', 'filter', 'filtering', 'firewall', 'audit' ],
	url = 'http://github.com/mk-fg/scapy-nflog-capture',

	description = 'Driver for scapy to allow capturing packets via Linux NFLOG interface',
	long_description = readme,

	classifiers = [
		'Development Status :: 4 - Beta',
		'Intended Audience :: Developers',
		'Intended Audience :: System Administrators',
		'Intended Audience :: Telecommunications Industry',
		'License :: OSI Approved',
		'Operating System :: POSIX :: Linux',
		'Programming Language :: Python',
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 2 :: Only',
		'Topic :: Security',
		'Topic :: System :: Networking :: Monitoring',
		'Topic :: System :: Operating System Kernels :: Linux' ],

	py_modules = ['nflog_ctypes', 'scapy_nflog'],
	package_data = {'': ['README.txt']} )
