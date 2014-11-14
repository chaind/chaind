bin_PROGRAMS = chaind

headers = chaind.h database_address.h database_blockchain.h database.h database_transaction.h memory_pool.h network_manager.h network_peer.h logging.h config.h dbus.h dbus-block.h introspection/chaind.h
chaind_SOURCES = main.c chaind.c network_manager.c network_peer.c memory_pool.c database.c logging.c config.c dbus.c dbus-block.c $(headers)
chaind_CFLAGS = -I$(top_srcdir) -Wall -std=gnu99 @libmongoc_CFLAGS@ @libconfig_CFLAGS@ @dbus_CFLAGS@ @memcached_CFLAGS@
chaind_LDADD = -L$(top_builddir)/libchain/.libs -lchain @LIBS@ @libmongoc_LIBS@ @libconfig_LIBS@ @dbus_LIBS@ @memcached_LIBS@

CLEANFILES = *~
