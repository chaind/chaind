chaind
======

chaind is a fully verifying, fully indexing Bitcoin node implementation in C.
chaind makes use of modern high performance libraries such as MongoDB, GNU MP,
and Judy to remain modular and light-weight.

chaind is *not* wallet software. chaind does not store private keys. chaind is
alpha. Use at your own risk.

Features and Goals
==================

The goal of chaind is to develop a fully functional Bitcoin peer node, absent
of wallet support. The belief here is that processing of Bitcoin transactions
and blocks should be fully independent from the protection of private keys.

chaind aims to be scalable, fast, and modular.  D-Bus is used to spread Bitcoin
messages around the system.  In the future, chaind will fully support block and
transaction objects via D-Bus and shm.

This project also provides libchain. libchain aims to make developing Bitcoin
applications easier.  In the future, it will also make it easy to write user
applications that communicate with chaind and its database.

Installation
============

chaind requires the installation of several third-party packages. Before
compiling make sure you have installed all prerequisites:

```
$ apt-get install autotools-dev pkg-config libgmp-dev libjudy-dev mongodb-server libmemcached-dev libtomcrypt-dev
```

You will also need to install the mongo-c driver
(http://api.mongodb.org/c/current/installing.html#build-yourself) and
libsecp256k1 (https://github.com/bitcoin/secp256k1).

Then run:

```
$ ./configure && make && make install
```

After installation completes, edit example.conf to your liking. Save to
/etc/chaind.conf and execute:

```
$ chaind -c /etc/chaind.conf
```

If you wish to monitor the progress of chaind, run the following command:

```
$ tail -f /var/log/syslog
```

chaind has initial support for DBus messages, so if you wish to monitor them
run:

```
$ dbus-monitor --system path=/org/sarcharsoftware/chaind
```

or

```
$ dbus-monitor --session path=/org/sarcharsoftware/chaind
```

Whether you use --system or --session depends on your configuration.

Developers
==========

Add "CFLAGS=-g -O2 -DLOG_STDOUT" to your ./configure environment.

TODO
====

Lots. Contact me.

