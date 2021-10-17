dist_man8_MANS = pam_permit.8

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/include \
        $(WARN_CFLAGS)
AM_LDFLAGS = -no-undefined -avoid-version -module
if SYMBOL_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_permit.la
pam_permit_la_LIBADD = -lpam

#check_PROGRAMS = tst-pam_permit-retval
#tst_pam_permit_retval_LDADD = -lpam
