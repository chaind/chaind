lib_LTLIBRARIES = libchain.la
ACLOCAL_AMFLAGS = -I ../m4

headers = bitcoin.h blockchain.h block.h coin_view.h crypto.h deque.h hashes.h inv.h libchain.h network.h peer_discovery.h script.h script_opcodes.h serialize.h transaction.h util.h vector.h
pkginclude_HEADERS = $(headers)

libchain_la_SOURCES = peer_discovery.c serialize.c hashes.c inv.c util.c transaction.c script.c block.c blockchain.c coin_view.c crypto.c
libchain_la_SOURCES += $(headers)
libchain_la_CFLAGS = -std=gnu99 -Wall

CLEANFILES = *~
