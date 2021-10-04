dist_man8_MANS = pam_shells.8

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/include \
        $(WARN_CFLAGS)
AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_shells.la
pam_shells_la_LIBADD = -lpam

#check_PROGRAMS = tst-pam_shells-retval
#tst_pam_shells_retval_LDADD = -lpam
