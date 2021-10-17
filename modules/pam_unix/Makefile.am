dist_man8_MANS = pam_unix.8

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/include \
        $(WARN_CFLAGS)
AM_LDFLAGS = -no-undefined -avoid-version -module
if SYMBOL_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_unix.la
pam_unix_la_LIBADD = -lpam

#check_PROGRAMS = tst-pam_unix-retval
#tst_pam_unix_retval_LDADD = -lpam

noinst_HEADERS = util.h

pam_unix_la_SOURCES = pam_unix.c util.c

