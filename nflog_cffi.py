#-*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import os, sys, re, errno, types, socket

from cffi import FFI


# Try to work around insane "write_table" operations (which assume that
#  they can just write lextab.py and yacctab.py in current dir), used by default.
try: from ply.lex import Lexer
except ImportError: pass
else: Lexer.writetab = lambda s,*a,**k: None
try: from ply.yacc import LRGeneratedTable
except ImportError: pass
else: LRGeneratedTable.write_table = lambda s,*a,**k: None


_cdef = '''
struct timeval {
	long tv_sec;
	long tv_usec;
};

typedef unsigned char u_int8_t;
typedef unsigned short int u_int16_t;
typedef unsigned int u_int32_t;

int nflog_fd(struct nflog_handle *h);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);

struct nflog_handle *nflog_open(void);

int nflog_bind_pf(struct nflog_handle *h, u_int16_t pf);
int nflog_unbind_pf(struct nflog_handle *h, u_int16_t pf);

struct nflog_g_handle *nflog_bind_group(struct nflog_handle *h, u_int16_t num);
int nflog_unbind_group(struct nflog_g_handle *gh);

static const u_int8_t NFULNL_COPY_PACKET;

int nflog_set_mode(struct nflog_g_handle *gh, u_int8_t mode, unsigned int len);
int nflog_set_timeout(struct nflog_g_handle *gh, u_int32_t timeout);
int nflog_set_flags(struct nflog_g_handle *gh, u_int16_t flags);
int nflog_set_qthresh(struct nflog_g_handle *gh, u_int32_t qthresh);
int nflog_set_nlbufsiz(struct nflog_g_handle *gh, u_int32_t nlbufsiz);

typedef int nflog_callback(struct nflog_g_handle *gh,
struct nfgenmsg *nfmsg, struct nflog_data *nfd, void *data);
int nflog_callback_register(struct nflog_g_handle *gh, nflog_callback *cb, void *data);
int nflog_handle_packet(struct nflog_handle *h, char *buf, int len);

struct nfulnl_msg_packet_hdr *nflog_get_msg_packet_hdr(struct nflog_data *nfad);

u_int16_t nflog_get_hwtype(struct nflog_data *nfad);
u_int16_t nflog_get_msg_packet_hwhdrlen(struct nflog_data *nfad);
char *nflog_get_msg_packet_hwhdr(struct nflog_data *nfad);

u_int32_t nflog_get_nfmark(struct nflog_data *nfad);
int nflog_get_timestamp(struct nflog_data *nfad, struct timeval *tv);
u_int32_t nflog_get_indev(struct nflog_data *nfad);
u_int32_t nflog_get_physindev(struct nflog_data *nfad);
u_int32_t nflog_get_outdev(struct nflog_data *nfad);
u_int32_t nflog_get_physoutdev(struct nflog_data *nfad);
struct nfulnl_msg_packet_hw *nflog_get_packet_hw(struct nflog_data *nfad);
int nflog_get_payload(struct nflog_data *nfad, char **data);
char *nflog_get_prefix(struct nflog_data *nfad);
int nflog_get_uid(struct nflog_data *nfad, u_int32_t *uid);
int nflog_get_gid(struct nflog_data *nfad, u_int32_t *gid);
int nflog_get_seq(struct nflog_data *nfad, u_int32_t *seq);
int nflog_get_seq_global(struct nflog_data *nfad, u_int32_t *seq);
'''

_clibs_includes = '''
#include <sys/types.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <libnetfilter_log/linux_nfnetlink_log.h>
'''
_clibs_link = 'nfnetlink', 'netfilter_log'


class NFLogError(OSError): pass

NFWouldBlock = type('NFWouldBlock', (object,), dict())


class NFLOG(object):

	_instance = None

	def __new__(cls):
		if not cls._instance:
			cls._instance = super(NFLOG, cls).__new__(cls)
		return cls._instance

	def __init__(self):
		global _cdef, _clibs_includes, _clibs_link
		self.ffi = FFI()
		self.ffi.cdef(_cdef)
		self.libnflog = self.ffi.verify(_clibs_includes, libraries=list(_clibs_link))
		self.libnflog_cache = dict()
		_cdef = _clibs_includes = _clibs_link = None


	def _ffi_call( self, func, args,
			no_check=False, check_gt0=False, check_notnull=False ):
		'''Call libnflog function through cffi,
				checking return value and raising error, if necessary.
			Checks if return is >0 by default.'''
		res = func(*args)
		if no_check\
			or (check_gt0 and res > 0)\
			or (check_notnull and res)\
			or res >= 0: return res
		errno_ = self.ffi.errno
		raise NFLogError(errno_, os.strerror(errno_))

	def __getattr__(self, k):
		if not (k.startswith('nflog_') or k.startswith('c_')):
			return super(NFLOG, self).__getattr__(k)
		if k.startswith('c_'): k = k[2:]
		if k not in self.libnflog_cache:
			func = getattr(self.libnflog, k)
			self.libnflog_cache[k] = lambda *a,**kw: self._ffi_call(func, a, **kw)
		return self.libnflog_cache[k]


	def generator( self, qids,
			pf=(socket.AF_INET, socket.AF_INET6),
			qthresh=None, timeout=None, nlbufsiz=None,
			buff_size=None, extra_attrs=None, handle_overflows=True ):
		'''Generator that yields:
				- on first iteration - netlink fd that can be poll'ed
					or integrated into some event loop (twisted, gevent, ...).
					Also, that is the point where uid/gid/caps can be dropped.
				- on all subsequent iterations it does recv() on that fd,
					returning either None (if no packet can be assembled yet)
					or captured packet payload.
			qids: nflog group ids to bind to (nflog_bind_group)
			Keywords:
				pf: address families to pass to nflog_bind_pf
				extra_attrs: metadata to extract from captured packets,
					returned in a list after packet payload, in the same order
				nlbufsiz (bytes): set size of netlink socket buffer for the created queues
				qthresh (packets): set the maximum amount of logs in buffer for each group
				timeout (seconds): set the maximum time to push log buffer for this group
				buff_size (bytes): size of the batch to fetch
					from libnflog to process in python (default: min(nlbufsiz, 1 MiB))
				handle_overflows: supress ENOBUFS NFLogError on
					queue overflows (but do log warnings, default: True)'''

		handle = self.nflog_open(check_notnull=True)

		for pf in (pf if not isinstance(pf, int) else [pf]):
			self.nflog_unbind_pf(handle, pf)
			self.nflog_bind_pf(handle, pf)

		if isinstance(extra_attrs, bytes): extra_attrs = [extra_attrs]

		cb_results = list()
		@self.ffi.callback('nflog_callback')
		def recv_callback( qh, nfmsg, nfad, data, extra_attrs=extra_attrs,
				ts_slot=self.ffi.new('struct timeval *'),
				pkt_slot=self.ffi.new('char **'),
				ts_err_mask=frozenset([0, errno.EAGAIN]), result=None ):
			try:
				pkt_len = self.nflog_get_payload(nfad, pkt_slot)
				result = self.ffi.buffer(pkt_slot[0], pkt_len)[:]
				if extra_attrs:
					result = [result]
					for attr in extra_attrs:
						if attr == 'len': result.append(pkt_len)
						elif attr == 'ts':
							# Fails quite often (EAGAIN, SUCCESS, ...), not sure why
							try: self.nflog_get_timestamp(nfad, ts_slot)
							except NFLogError as err:
								if err.errno not in ts_err_mask: raise
								result.append(None)
							else: result.append(ts_slot.tv_sec + ts_slot.tv_usec * 1e-6)
						elif attr == 'prefix':
							result.append(self.ffi.string(self.nflog_get_prefix(nfad)) or None)
						else: raise NotImplementedError('Unknown nflog attribute: {}'.format(attr))
				cb_results.append(result)
			except:
				cb_results.append(StopIteration) # breaks the generator
				raise
			return 0

		for qid in (qids if not isinstance(qids, int) else [qids]):
			qh = self.nflog_bind_group(handle, qid, check_notnull=True)
			self.nflog_set_mode(qh, self.libnflog.NFULNL_COPY_PACKET, 0xffff)
			if qthresh: self.nflog_set_qthresh(qh, qthresh)
			if timeout: self.nflog_set_timeout(qh, int(timeout * 100))
			if nlbufsiz: self.nflog_set_nlbufsiz(qh, nlbufsiz)
			self.nflog_callback_register(qh, recv_callback, self.ffi.NULL)

		fd = self.nflog_fd(handle)
		if not buff_size:
			if nlbufsiz: buff_size = min(nlbufsiz, 1*2**20)
			else: buff_size = 1*2**20
		buff = self.ffi.new('char[]', buff_size)

		peek = yield fd # yield fd for poll() on first iteration
		while True:
			if peek:
				peek = yield NFWouldBlock # poll/recv is required
				continue

			# Receive/process netlink data, which may contain multiple packets
			try: nlpkt_size = self.c_recv(fd, buff, buff_size, 0)
			except NFLogError as err:
				if handle_overflows and err.errno == errno.ENOBUFS:
					log.warn( 'nlbufsiz seem'
						' to be insufficient to hold unprocessed packets,'
						' consider raising it via corresponding function keyword' )
					continue
				raise
			self.nflog_handle_packet(handle, buff, nlpkt_size, no_check=True)

			# yield individual L3 packets
			for result in cb_results:
				if result is StopIteration: raise result
				peek = yield result
			cb_results = list()



if __name__ == '__main__':
	qids = 0, 1
	src = NFLOG().generator(qids, extra_attrs=['len', 'ts'])
	fd = next(src)
	print('Netlink fd: {}, capturing packets from nflog queues: {}'.format(fd, qids))
	for pkt in src:
		if pkt is None: continue
		pkt, pkt_len, ts = pkt
		print('Got packet, len: {}, ts: {}'.format(pkt_len, ts))
		# print('Payload:', pkt.encode('hex'))
