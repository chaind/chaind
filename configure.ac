AC_PREREQ([2.69])
AC_INIT([chaind], [0.0.0], [bugs@chaind.org])
AC_CONFIG_SRCDIR([libchain/libchain.h])
AC_CONFIG_SRCDIR([src/chaind.h])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([dist-bzip2 foreign])
AC_CONFIG_SUBDIRS([libchain])

# Macros for libtool
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_INSTALL

# Checks for standard header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h syslog.h stdarg.h poll.h])

# Checks for libraries.
# (I really don't want these checks duplicated here, most of them should
# only be required in libchain, but with --disable-shared they need to
# be specified when linking chaind)
AC_SEARCH_LIBS([Judy1Test], [Judy], [], [have_libJudy=no])
AC_CHECK_HEADERS([Judy.h], [], [have_libJudy=no])

AC_SEARCH_LIBS([__gmpz_set], [gmp], [], [have_libgmp=no])
AC_CHECK_HEADERS([gmp.h], [], [have_libgmp=no])

AC_SEARCH_LIBS([pthread_create], [pthread], [], [have_libpthread=no])
AC_CHECK_HEADERS([pthread.h], [], [have_libpthread=no])

AC_SEARCH_LIBS([secp256k1_ec_pubkey_verify], [secp256k1], [], [have_libsecp256k1=no])
AC_CHECK_HEADERS([secp256k1.h], [], [have_libsecp256k1=no])

AC_SEARCH_LIBS([sha256_init], [tomcrypt], [], [have_libtomcrypt=no])
AC_CHECK_HEADERS([tomcrypt.h], [], [have_libtomcrypt=no])

if test x"$have_libJudy" = x"no"; then
    echo
    echo "libJudy is missing or development headers are not installed"
    echo
    (exit 1); exit 1
fi

if test x"$have_libgmp" = x"no"; then
    echo
    echo "libgmp is missing or development headers are not installed"
    echo
    (exit 1); exit 1
fi

if test x"$have_libpthread" = x"no"; then
    echo
    echo "libpthread is missing or development headers are not installed"
    echo
    (exit 1); exit 1
fi

if test x"$have_libsecp256k1" = x"no"; then
    echo
    echo "libsecp256k1 is missing or development headers are not installed"
    echo
    (exit 1); exit 1
fi

if test x"$have_libtomcrypt" = x"no"; then
    echo
    echo "libtomcrypt is missing or development headers are not installed"
    echo
    (exit 1); exit 1
fi

# MongoDB checks
PKG_CHECK_MODULES([libmongoc], [libmongoc-1.0 >= 1.0], [have_libmongoc=yes])

if test x"$have_libmongoc" = x"yes"; then
    old_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$libmongoc_CFLAGS $CPPFLAGS"
    AC_CHECK_HEADERS([mongoc.h], [], [have_libmongoc=no])
    CPPFLAGS=$old_CPPFLAGS
fi

if test x"$have_libmongoc" != x"yes"; then
    echo
    echo "libmongoc is missing or development headers are not installed"
    echo
    (exit 1); exit 1
fi

PKG_CHECK_MODULES([libconfig], [libconfig >= 1.4], [], [
    AC_MSG_ERROR([libconfig 1.4 or newer not found.])
])

PKG_CHECK_MODULES([dbus], [dbus-1 >= 1.8], [], [
    AC_MSG_ERROR([dbus 1.8 or newer not found.])
])

PKG_CHECK_MODULES([memcached], [libmemcached >= 0.8.0], [], [
    AC_MSG_ERROR([libmemcached 0.8.0 or newer not found.])
])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday inet_ntoa memset select socket syslog va_start poll])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_CONFIG_HEADERS([chaind_config.h])
AC_OUTPUT
