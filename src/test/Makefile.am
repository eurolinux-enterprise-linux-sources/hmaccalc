AM_CFLAGS = @NSS_CFLAGS@ -DMAKE_CHECK_DIRECTORY=\"$(abs_builddir)\" -DALLOW_ANY_TRUNCATION
LDADD = @NSS_LIBS@

EXTRA_DIST = $(check_SCRIPTS)
check_SCRIPTS = run-tests.sh
check_PROGRAMS = run-test sha512hmac sha384hmac sha256hmac sha1hmac

check_DATA = \
	@CHECK_PREFIX@sha512hmac.@CHECK_SUFFIX@ \
	@CHECK_PREFIX@sha384hmac.@CHECK_SUFFIX@ \
	@CHECK_PREFIX@sha256hmac.@CHECK_SUFFIX@ \
	@CHECK_PREFIX@sha1hmac.@CHECK_SUFFIX@
@CHECK_PREFIX@sha512hmac.@CHECK_SUFFIX@: sha512hmac
	$(builddir)/$^ -S > $(builddir)/$@
@CHECK_PREFIX@sha384hmac.@CHECK_SUFFIX@: sha384hmac
	$(builddir)/$^ -S > $(builddir)/$@
@CHECK_PREFIX@sha256hmac.@CHECK_SUFFIX@: sha256hmac
	$(builddir)/$^ -S > $(builddir)/$@
@CHECK_PREFIX@sha1hmac.@CHECK_SUFFIX@: sha1hmac
	$(builddir)/$^ -S > $(builddir)/$@

check:
	$(builddir)/run-tests.sh $(builddir)
