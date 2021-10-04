dist_man8_MANS = pam_wheel.8

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/include \
        $(WARN_CFLAGS)
AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_wheel.la
pam_wheel_la_LIBADD = -lpam

#check_PROGRAMS = tst-pam_wheel-retval
#tst_pam_wheel_retval_LDADD = -lpam
