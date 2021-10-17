dist_man8_MANS = pam_rootok.8

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/include \
        $(WARN_CFLAGS)
AM_LDFLAGS = -no-undefined -avoid-version -module
if SYMBOL_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_rootok.la
pam_rootok_la_LIBADD = -lpam

#check_PROGRAMS = tst-pam_rootok-retval
#tst_pam_rootok_retval_LDADD = -lpam
