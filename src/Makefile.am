EXTRA_DIST = hmaccalc.spec LICENSE README
SUBDIRS = src test

VERSION=$(shell rpm -q --specfile $(top_srcdir)/hmaccalc.spec --qf '%{version}\n' | head -n1)
RELEASE=$(shell rpm -q --specfile $(top_srcdir)/hmaccalc.spec --qf '%{release}\n' | head -n1)
GITTAG=hmaccalc-$(shell rpm -q --specfile $(top_srcdir)/hmaccalc.spec --qf '%{version}\n' --define 'dist %{nil}' | head -n1)
distdir=$(GITTAG)

tag:
	git tag $(GITTAG)

force-tag:
	git tag -f $(GITTAG)

ORIGIN=$(shell git config remote.origin.url 2> /dev/null || /bin/pwd)
ARCHIVEOUTDIR=$(shell cd $(top_srcdir) && pwd)

local-archive:
	$(MAKE) archive ORIGIN=$(ARCHIVEOUTDIR)

archive:
	repo=`pwd`; \
	tmpdir=`mktemp -d /tmp/make_archive_XXXXXX`; \
	if test -d "$$tmpdir" ; then \
		git clone $(ORIGIN) $$tmpdir/hmaccalc;\
		cd $$tmpdir/hmaccalc;\
		git checkout $(GITTAG);\
		./autogen.sh;\
		./configure;\
		make dist;\
		mkdir -p $$tmpdir/rpm-build-top;\
		rpmbuild \
			--define "_topdir $$tmpdir/rpm-build-top" \
			--define "_sourcedir $$tmpdir/rpm-build-top" \
			--define "_specdir $$tmpdir/rpm-build-top" \
			--define "_builddir $$tmpdir/rpm-build-top" \
			--define "_srpmdir $$tmpdir/rpm-build-top" \
			--define "_rpmdir $$tmpdir/rpm-build-top" \
			--define "_rpmdir $$tmpdir/rpm-build-top" \
			-tb $(distdir).tar.gz;\
		cp -v $(distdir).tar.gz $(ARCHIVEOUTDIR)/;\
		rm -fr $$tmpdir;\
	fi
