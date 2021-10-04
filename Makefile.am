AUTOMAKE_OPTIONS = 1.16.4 gnu dist-xz no-dist-gzip check-news

SUBDIRS = modules

CLEANFILES = *~

EXTRA_DIST =

ACLOCAL_AMFLAGS = -I m4

export TAR_OPTIONS = --owner=0 --group=0 --numeric-owner --mode=go-w,go+rX

gen_changelog_start_date = 2014-08-22
gen-ChangeLog:
	if test -d .git; then						\
		( $(top_srcdir)/gitlog-to-changelog --append-dot	\
		  --since=$(gen_changelog_start_date) &&		\
		  echo && echo &&					\
		  echo 'See repository history for earlier changes.'	\
		) > $(distdir)/ChangeLog.new &&				\
		rm -f $(distdir)/ChangeLog &&				\
		mv $(distdir)/ChangeLog.new $(distdir)/ChangeLog;	\
	fi

dist-hook: gen-ChangeLog
.PHONY: gen-ChangeLog
