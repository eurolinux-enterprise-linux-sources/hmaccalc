AC_INIT(hmaccalc,0.9.12)
AM_INIT_AUTOMAKE(foreign)
AC_PROG_CC
PKG_CHECK_MODULES(NSS,nss)
AC_CONFIG_HEADER(src/config.h)

mybindir=`eval echo "$bindir" | sed s,^NONE,"$prefix",`
mybindir=`eval echo "$mybindir" | sed s,^NONE,"$ac_default_prefix",`

CHECK_DIRECTORY=
AC_ARG_ENABLE(sum-directory,
	      AS_HELP_STRING([--enable-sum-directory=],[directory in which the binary's checksum file can be found (default is the same as the binary)]),
	      if test x$enableval != xno ; then
	          if test x$enableval != xyes ; then
		      # a specific choice
		      CHECK_DIRECTORY="$enableval"
	              CHECK_DIRECTORY_OR_BINDIR="$enableval"
	          else
		      # "yes"
		      CHECK_DIRECTORY="$mybindir"
	              CHECK_DIRECTORY_OR_BINDIR='$(bindir)'
	          fi
	      else
		  # "no"
		  CHECK_DIRECTORY=
	          CHECK_DIRECTORY_OR_BINDIR='$(bindir)'
	      fi,
	      CHECK_DIRECTORY=
	      CHECK_DIRECTORY_OR_BINDIR='$(bindir)')
AC_ARG_ENABLE(sum-prefix,
	      AS_HELP_STRING([--enable-sum-prefix=.],[prefix to add to filenames when deriving the binary's checksum file's name (no default)]),
	      if test x$enableval != xno ; then
		  CHECK_PREFIX="$enableval"
	      else
		  CHECK_PREFIX=
	      fi
	      ,CHECK_PREFIX=)
AC_ARG_ENABLE(sum-suffix,
	      AS_HELP_STRING([--enable-sum-suffix=EXT],[suffix to add to filenames when deriving the binary's checksum file's name (default "hmac")]),
	      if test x$enableval != xno ; then
		  CHECK_SUFFIX="$enableval"
	      else
		  CHECK_SUFFIX=
	      fi
	      ,CHECK_SUFFIX=hmac)
AC_SUBST(CHECK_DIRECTORY)
AC_SUBST(CHECK_DIRECTORY_OR_BINDIR)
AC_SUBST(CHECK_PREFIX)
AC_SUBST(CHECK_SUFFIX)
AC_ARG_ENABLE(non-fips,
	      AS_HELP_STRING([--enable-non-fips],[enable md2/md4/md5 variations]),
	      if test x$enableval != xno ; then
		  NON_FIPS=true
		  FIPS_MAN=".\\\" "
		  NON_FIPS_MAN=
	      else
		  NON_FIPS=false
		  FIPS_MAN=
		  NON_FIPS_MAN=".\\\" "
	      fi,
	      NON_FIPS=false
	      FIPS_MAN=
	      NON_FIPS_MAN=".\\\" "
)
AM_CONDITIONAL(NON_FIPS,test x$NON_FIPS = xtrue)
AC_SUBST(FIPS_MAN)
AC_SUBST(NON_FIPS_MAN)
AC_PATH_PROG(PRELINK_CMD,prelink,,[$PATH$PATH_SEPARATOR/usr/sbin$PATH_SEPARATOR/sbin$PATH_SEPARATOR/usr/local/sbin])
if test -n "$PRELINK_CMD" ; then
	AC_DEFINE_UNQUOTED(PRELINK_CMD,"$PRELINK_CMD",[Define to the full path to the prelink command.])
fi
	      
AC_DEFINE_UNQUOTED(CHECK_DIRECTORY,"$CHECK_DIRECTORY",[Define to the directory which contains the hmac for a binary.])
AC_DEFINE_UNQUOTED(CHECK_PREFIX,"$CHECK_PREFIX",[Define to the prefix which contains the hmac for a binary.])
AC_DEFINE_UNQUOTED(CHECK_SUFFIX,"$CHECK_SUFFIX",[Define to the suffix which contains the hmac for a binary.])
AC_DEFINE(DIRSEP,'/',[Define to the character which separates portions of a pathname.])
AC_DEFINE(PATHSEP,':',[Define to the character which separates portions of the PATH environment variable.])
DEFAULT_CONFIG_DIR=/etc/pki/nssdb
AC_DEFINE_UNQUOTED(DEFAULT_CONFIG_DIR,"$DEFAULT_CONFIG_DIR",[Define to the default location of the NSS configuration directory.])
AC_SUBST(DEFAULT_CONFIG_DIR)
AC_OUTPUT(Makefile src/Makefile src/sha512hmac.8 test/Makefile)
