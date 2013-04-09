from __future__ import unicode_literals, print_function

from scapy.all import conf, SuperSocket, ETH_P_ALL, IP, Scapy_Exception
from nflog_ctypes import nflog_generator


class SocketFD(int):
	'Mock "socket" class to wrap netlink fd int, so that it will work with s.fileno().'
	def fileno(self): return self


class NFLOGListenSocket(SuperSocket):

	desc = 'read packets at layer 3 using Linux NFLOG'

	queues = range(4)

	def __init__( self, iface=None, type=ETH_P_ALL,
			promisc=None, filter=None, nofilter=0, queues=None ):
		self.type, self.outs = type, None
		if queues is None: queues = self.queues
		self.nflog = nflog_generator(queues, extra_attrs=['ts'], nlbufsiz=2*2**20)
		self.ins = SocketFD(next(self.nflog)) # yields fd first

	def recv(self, bufsize):
		pkt, ts = next(self.nflog)
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
