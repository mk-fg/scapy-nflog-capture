# -*- coding: utf-8 -*-
from __future__ import print_function

from threading import Thread
from collections import deque
import os

from scapy.all import conf, SuperSocket, ETH_P_ALL, IP, Scapy_Exception
from nflog_ctypes import nflog_generator, NFWouldBlock


class NFLOGReaderThread(Thread):
	'''Necessary only because libnetfilter_log returns
		packets in batches, and scapy expects to poll/read them one-by-one.'''

	daemon = True

	def __init__(self, queues):
		super(NFLOGReaderThread, self).__init__()
		self.queues, self.pipe = queues, deque()
		self.pipe_chk, self._pipe = os.pipe()
		self.pipe_chk, self._pipe = os.fdopen(self.pipe_chk), os.fdopen(self._pipe, 'w')

	def run(self):
		nflog = nflog_generator(self.queues, extra_attrs=['ts'], nlbufsiz=2*2**20)
		next(nflog)
		for pkt_info in nflog:
			self.pipe.append(pkt_info)
			self._pipe.write('.') # block until other thread reads it
			self._pipe.flush()


class NFLOGListenSocket(SuperSocket):

	desc = 'read packets at layer 3 using Linux NFLOG'

	queues = range(4)

	def __init__( self, iface=None, type=ETH_P_ALL,
			promisc=None, filter=None, nofilter=0, queues=None ):
		self.type, self.outs = type, None
		if queues is None: queues = self.queues
		self.nflog = NFLOGReaderThread(queues)
		self.nflog.start()
		self.ins = self.nflog.pipe_chk

	def recv(self, bufsize):
		self.ins.read(1) # used only for poll/sync
		pkt, ts = self.nflog.pipe.popleft()
		if pkt is None: return
		try: pkt = IP(pkt)
		except KeyboardInterrupt: raise
		except:
			if conf.debug_dissector: raise
			pkt = conf.raw_layer(pkt)
		pkt.time = ts
		return pkt

	def send(self, pkt):
		raise Scapy_Exception(
			'Cannot send anything with {}'.format(self.__class__.__name__) )

	def close(self):
		SuperSocket.close(self)


def install_nflog_listener():
	'Install as default scapy L2 listener.'
	conf.L2listen = NFLOGListenSocket
