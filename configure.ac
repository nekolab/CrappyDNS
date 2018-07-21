#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([CrappyDNS], [0.1-dev], [ratsunny@gmail.com])
AC_CONFIG_SRCDIR([src/crappydns.h])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects foreign -Wall -Werror])

CXXFLAGS="-std=c++11 -Os -Wall"

# Checks for programs.
AC_PROG_CXX

# Checks for libraries.
AC_CHECK_LIB(resolv, res_query, [],
    [AC_CHECK_LIB(resolv, __res_query, [],
        [AC_MSG_ERROR([libresolv not found.])])])

AC_CHECK_LIB(uv, uv_run, [], [AC_MSG_ERROR([libuv not found.])])

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h sys/socket.h])
AC_CHECK_HEADERS([arpa/inet.h arpa/nameser.h arpa/nameser_compat.h])
AC_CHECK_HEADERS([getopt.h pwd.h grp.h errno.h])
AC_CHECK_HEADERS([uv.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([strdup strstr strtol])
AC_CHECK_FUNCS([geteuid getpwuid getpwnam getpwuid_r getpwnam_r setgid setuid initgroups])

AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT
