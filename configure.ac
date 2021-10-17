#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([openpam-modules], [20211004], [galaxy-at-openwall.com.au])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Wno-portability])

dnl
dnl By default, everything under PAM is installed below /usr.
dnl
AC_PREFIX_DEFAULT(/usr)

dnl and some hacks to use /etc and /lib
test "${prefix}" = "NONE" && prefix="/usr"
if test ${prefix} = '/usr'
then
dnl If we use /usr as prefix, use /etc for config files
	if test ${sysconfdir} = '${prefix}/etc'
	then
		sysconfdir="/etc"
	fi
	if test ${libdir} = '${exec_prefix}/lib'
	then
		case "$host_cpu" in
		    x86_64|ppc64|s390x|sparc64)
			libdir="/lib64" ;;
		    *)
			libdir="/lib" ;;
		esac
	fi
	if test ${sbindir} = '${exec_prefix}/sbin'
	then
		sbindir="/sbin"
	fi
dnl If we use /usr as prefix, use /usr/share/man for manual pages
	if test ${mandir} = '${prefix}/man'
	then
		mandir='${prefix}/share/man'
	fi
dnl Add security to include directory
	if test ${includedir} = '${prefix}/include'
	then
		includedir="${prefix}/include/security"
	fi

dnl Add /var directory
	if test ${localstatedir} = '${prefix}/var'
	then
		localstatedir="/var"
	fi

fi

dnl This should be called before any macros that run the C compiler.
AC_USE_SYSTEM_EXTENSIONS

LT_INIT([disable-static])
AC_ENABLE_STATIC([no])
AC_ENABLE_SHARED([yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.

dnl Largefile support
AC_SYS_LARGEFILE

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h netdb.h shadow.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([getspnam strcasecmp strchr])

AC_ARG_ENABLE([symbol-versioning],
AS_HELP_STRING([--disable-symbol-versioning],[Disable symbol versioning in shared objects]))

AC_CACHE_CHECK([whether symbol versioning is supported], ac_cv_symbol_versioning, [dnl
AC_COMPILE_IFELSE([AC_LANG_SOURCE([dnl
#define NEW_VERSION(name, version) \
  asm (".symver " #name "," #name "@@@" #version);
int foo(int x) { return x + 1; }
NEW_VERSION (foo, TEST_2.34)
])], ac_cv_symbol_versioning=yes, ac_cv_symbol_versioning=no)])
if test "$ac_cv_symbol_versioning" = "no"; then
    if test "x$enable_symbol_versioning" != "xno"; then
        AC_MSG_ERROR([Symbol versioning is not supported.
                      Use --disable-symbol-versioning to build without.])
    fi
fi

AM_CONDITIONAL(SYMBOL_VERSIONING, [test "x$enable_symbol_versioning" != "xno"])
AS_IF([test "x$enable_symbol_versioning" = "xno"],
      [AC_MSG_WARN([Disabling symbol versioning breaks ABI compatibility.])
       enable_symbol_versioning=no],[enable_symbol_versioning=yes])

AC_ARG_ENABLE(securedir,
        AS_HELP_STRING([--enable-securedir=DIR],[path to location of PAMs @<:@default=$libdir/security@:>@]),
        SECUREDIR=$enableval, SECUREDIR=$libdir/security)
AC_SUBST(SECUREDIR)

AC_ARG_ENABLE(sconfigdir,
        AS_HELP_STRING([--enable-sconfigdir=DIR],[path to module conf files @<:@default=$sysconfdir/security@:>@]),
        SCONFIGDIR=$enableval, SCONFIGDIR=$sysconfdir/security)
AC_SUBST(SCONFIGDIR)

AC_CONFIG_FILES([Makefile
                 modules/Makefile
                 modules/pam_deny/Makefile
                 modules/pam_nologin/Makefile
                 modules/pam_permit/Makefile
                 modules/pam_rootok/Makefile
                 modules/pam_securetty/Makefile
                 modules/pam_shells/Makefile
                 modules/pam_unix/Makefile
                 modules/pam_wheel/Makefile])
AC_OUTPUT
