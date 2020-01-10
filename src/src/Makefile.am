AM_CFLAGS = @NSS_CFLAGS@
LDADD = @NSS_LIBS@
noinst_PROGRAMS = hmac
bin_PROGRAMS = sha512hmac sha384hmac sha256hmac sha1hmac
man_MANS = sha512hmac.8 $(srcdir)/sha384hmac.8 $(srcdir)/sha256hmac.8 $(srcdir)/sha1hmac.8
EXTRA_DIST = sha512hmac.8.in sha384hmac.8 sha256hmac.8 sha1hmac.8 \
	     md5hmac.8 md4hmac.8 md2hmac.8

HERE_CFLAGS = -DMAKE_CHECK_DIRECTORY=\"$(abs_builddir)\"

sumdir = @CHECK_DIRECTORY_OR_BINDIR@
sum_DATA = \
	@CHECK_PREFIX@sha512hmac.@CHECK_SUFFIX@ \
	@CHECK_PREFIX@sha384hmac.@CHECK_SUFFIX@ \
	@CHECK_PREFIX@sha256hmac.@CHECK_SUFFIX@ \
	@CHECK_PREFIX@sha1hmac.@CHECK_SUFFIX@
noinst_DATA = @CHECK_PREFIX@hmac.@CHECK_SUFFIX@
CLEANFILES = $(sum_DATA) $(noinst_DATA) $(non_fips_programs) $(non_fips_data)
@CHECK_PREFIX@sha512hmac.@CHECK_SUFFIX@: sha512hmac
	$(builddir)/$^ -S > $(builddir)/$@
@CHECK_PREFIX@sha384hmac.@CHECK_SUFFIX@: sha384hmac
	$(builddir)/$^ -S > $(builddir)/$@
@CHECK_PREFIX@sha256hmac.@CHECK_SUFFIX@: sha256hmac
	$(builddir)/$^ -S > $(builddir)/$@
@CHECK_PREFIX@sha1hmac.@CHECK_SUFFIX@: sha1hmac
	$(builddir)/$^ -S > $(builddir)/$@
@CHECK_PREFIX@hmac.@CHECK_SUFFIX@: hmac
	$(builddir)/$^ -S > $(builddir)/$@

non_fips_programs = md5hmac md4hmac md2hmac
non_fips_data = \
	@CHECK_PREFIX@md5hmac.@CHECK_SUFFIX@ \
	@CHECK_PREFIX@md4hmac.@CHECK_SUFFIX@ \
	@CHECK_PREFIX@md2hmac.@CHECK_SUFFIX@
@CHECK_PREFIX@md5hmac.@CHECK_SUFFIX@: md5hmac
	$(builddir)/$^ -S > $(builddir)/$@
@CHECK_PREFIX@md4hmac.@CHECK_SUFFIX@: md4hmac
	$(builddir)/$^ -S > $(builddir)/$@
@CHECK_PREFIX@md2hmac.@CHECK_SUFFIX@: md2hmac
	$(builddir)/$^ -S > $(builddir)/$@

if NON_FIPS
AM_CFLAGS += -DNON_FIPS=1
bin_PROGRAMS += $(non_fips_programs)
sum_DATA += $(non_fips_data)
man_MANS += $(srcdir)/md5hmac.8 $(srcdir)/md4hmac.8 $(srcdir)/md2hmac.8
endif
