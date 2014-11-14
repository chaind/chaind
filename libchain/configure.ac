AC_PREREQ([2.69])
AC_INIT([libchain], [0.0.0], [bugs@chaind.org])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([libchain.h])
AC_CONFIG_HEADERS([libchain_config.h])

# Configure libtool
AC_CONFIG_MACRO_DIR([../m4])
LT_PREREQ([2.2])
LT_INIT([shared static])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for standard header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for libraries.
AC_SEARCH_LIBS([Judy1Test], [Judy], [], [have_libJudy=no])
AC_CHECK_HEADERS([Judy.h], [], [have_libJudy=no])

AC_SEARCH_LIBS([__gmpz_set], [gmp], [], [have_libgmp=no])
AC_CHECK_HEADERS([gmp.h], [], [have_libgmp=no])

AC_SEARCH_LIBS([pthread_create], [pthread], [], [have_libpthread=no])
AC_CHECK_HEADERS([pthread.h], [], [have_libpthread=no])

AC_SEARCH_LIBS([secp256k1_ecdsa_pubkey_verify], [secp256k1], [], [have_libsecp256k1=no])
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
AC_CHECK_FUNCS([gettimeofday inet_ntoa memset select socket])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
