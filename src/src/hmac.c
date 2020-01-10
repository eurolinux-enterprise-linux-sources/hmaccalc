/*
 * Copyright 2008,2009,2013 Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pub.h>
#include <secmod.h>

#define IPAD 0x36
#define OPAD 0x5c

#ifndef MAX
#define MAX(_a,_b) ((_a > _b) ? _a : _b)
#endif

/* Hashing algorithms we know how to use. */
static struct hashinfo {
	const char *hash;
	SECOidTag tag;
	unsigned int blocksize;
	unsigned int digestsize; 
} known_algorithms[] = {
	{"sha512", SEC_OID_SHA512, 1024 / 8, 512 / 8},
	{"sha384", SEC_OID_SHA384, 1024 / 8, 384 / 8},
	{"sha256", SEC_OID_SHA256,  512 / 8, 256 / 8},
	{"sha1",   SEC_OID_SHA1,    512 / 8, 160 / 8},
#ifdef NON_FIPS
	{"md5",    SEC_OID_MD5,     512 / 8, 128 / 8},
	{"md4",    SEC_OID_MD4,     512 / 8, 128 / 8},
	{"md2",    SEC_OID_MD2,     512 / 8, 128 / 8},
#endif
};

/* Take the key argument passed on the command line, and produce the B-byte
 * string which should be XORd with the ipad and opad values.  If the key is
 * too large to fit into the buffer, reduce it using the hash function.
 * Because the key is zero-padded, we don't _require_ padding bytes. */
static SECStatus
prepare_key(const char *keyopt, SECOidTag tag,
	    unsigned char *key, unsigned int size)
{
	unsigned int length;
	length = strlen(keyopt);
	if (length > size) {
		/* Reduce the key size by hashing it down, then zero-padding
		 * the result.  Or by zero-filling it, then hashing it down. */
		memset(key, '\0', size);
		if (PK11_HashBuf(tag, key,
				 (unsigned char *) keyopt,
				 length) != SECSuccess) {
			return SECFailure;
		}
	} else {
		/* Zero-pad the key. */
		memcpy(key, keyopt, length);
		if (length < size) {
			memset(key + length, '\0', size - length);
		}
	}
	return SECSuccess;
}

/* Take the key file name passed on the command line, and produce the B-byte
 * string which should be XORd with the ipad and opad values.  If the file is
 * too large to fit into the buffer, reduce it using the hash function.
 * Because the key is zero-padded, we don't _require_ padding bytes. */
static int
readf(FILE *fp, unsigned char *key, int length)
{
	int i, done;
	done = 0;
	while (done < length) {
		i = fread(key + done, 1, length - done, fp);
		if (i <= 0) {
			return -1;
		}
		done += i;
	}
	return done;
}
static SECStatus
prepare_key_file(const char *keyopt, SECOidTag tag,
		 unsigned char *key, unsigned int size)
{
	struct stat st;
	unsigned int length, total;
	FILE *fp;
	PK11Context *ctx;
	unsigned char buf[BUFSIZ];
	SECStatus status;

	fp = fopen(keyopt, "r");
	if (fp == NULL) {
		fprintf(stderr, "%s: %s\n", keyopt, strerror(errno));
		return SECFailure;
	}
	if (fstat(fileno(fp), &st) == -1) {
		fprintf(stderr, "%s: %s\n", keyopt, strerror(errno));
		fclose(fp);
		return SECFailure;
	}
	if (st.st_size > size) {
		/* Reduce the key size by hashing it down, then zero-padding
		 * the result.  Or by zero-filling it, then hashing it down. */
		memset(key, '\0', size);
		ctx = PK11_CreateDigestContext(tag);
		total = 0;
		while (!feof(fp)) {
			length = fread(buf, 1, sizeof(buf), fp);
			if (length <= 0) {
				fclose(fp);
				return SECFailure;
			}
			total += length;
			status = PK11_DigestOp(ctx, buf, length);
			if (status != SECSuccess) {
				fclose(fp);
				return status;
			}
		}
		if (total != st.st_size) {
			fprintf(stderr, "Read unexpected number of bytes "
				"from %s.\n", keyopt);
			fclose(fp);
			return SECFailure;
		}
		status = PK11_DigestFinal(ctx, key, &length, size);
		if (status != SECSuccess) {
			fprintf(stderr, "Error computing digest of \"%s\".\n",
				keyopt);
			fclose(fp);
			return status;
		}
		if (length > size) {
			fprintf(stderr, "Computed digest is %d bytes, "
				"which is too big.\n", length);
			fclose(fp);
			return SECFailure;
		}
		memset(key + length, '\0', size - length);
		PK11_DestroyContext(ctx, PR_TRUE);
	} else {
		/* Zero-pad the key. */
		if (readf(fp, key, st.st_size) != st.st_size) {
			fclose(fp);
			fprintf(stderr, "Error reading \"%s\": %s\n", keyopt,
				strerror(errno));
			return SECFailure;
		}
		if (st.st_size < size) {
			memset(key + st.st_size, '\0', size - st.st_size);
		}
	}
	fclose(fp);
	return SECSuccess;
}

/* Compute the HMAC or sum for the named file with the specified algorithm,
 * using precomputed inner and outer keys if we're generating an HMAC, and
 * returning the result in both raw and hex-encoded form. */
static SECStatus
compute_one(const char *filename, int unprelink, int binary,
	    struct hashinfo *algorithm,
	    unsigned char *ikeyval, unsigned char *okeyval,
	    unsigned char *result, char *hex_result)
{
	SECStatus status;
	PK11Context *ctx;
	unsigned char buf[BUFSIZ];
	char tempfile[PATH_MAX];
	FILE *fp;
	size_t n;
	int pfd[2], tempfd;
	unsigned int len, u;

	/* Try to open the file. */
	fp = NULL;
	snprintf(tempfile, sizeof(tempfile), "%s", filename);
	if (unprelink) {
		if (strcmp(filename, "-") == 0) {
			snprintf(tempfile, sizeof(tempfile), "%s/hmacXXXXXX",
				 getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
			tempfd = mkstemp(tempfile);
			if (tempfd == -1) {
				return SECFailure;
			}
			fp = fdopen(tempfd, binary ? "wb" : "w");
			if (fp != NULL) {
				while ((n = fread(buf, 1,
						  sizeof(buf), stdin)) > 0) {
					fwrite(buf, 1, n, fp);
				}
				fclose(fp);
			}
		}
		if (pipe(pfd) == 0) {
			switch (fork()) {
			case 0:
				/* We're the child.  Close everything except
				 * stdout, and try to pipe the output of
				 * "prelink -y" to the parent. */
				close(pfd[0]);
				pfd[0] = open("/dev/null", O_RDWR);
				if (pfd[0] != -1) {
					dup2(pfd[0], STDIN_FILENO);
					dup2(pfd[1], STDOUT_FILENO);
					dup2(pfd[0], STDERR_FILENO);
#ifdef PRELINK_CMD
					execl(PRELINK_CMD, "prelink",
					      "-y", tempfile, NULL);
#endif
					execlp("prelink", "prelink",
					       "-y", tempfile, NULL);
					/* If we failed to run "prelink -y",
					 * try to just "cat" the file. */
					fp = fopen(filename,
						   binary ? "rb" : "r");
					if (fp != NULL) {
						while ((n = fread(buf, 1,
								  sizeof(buf),
								  fp)) > 0) {
							write(pfd[1], buf, n);
						}
						fclose(fp);
					}
				}
				_exit(1);
				break;
			case -1:
				/* Unhandled failure. */
				break;
			default:
				/* Treat the read end of the pipe as if it's
				 * the file we're trying to read. */
				fp = fdopen(pfd[0], binary ? "rb" : "r");
				close(pfd[1]);
				break;
			}
		}
	}
	if (fp == NULL) {
		fp = strcmp(filename, "-") ?
		     fopen(filename, binary ? "rb" : "r") :
		     stdin;
	}
	if (fp == NULL) {
		fprintf(stderr, "Error opening \"%s\": %s.\n", filename,
			strerror(errno));
		if (strcmp(tempfile, filename) != 0) {
			unlink(tempfile);
		}
		return errno;
	}

	/* Create the inner context (or the only one, if we're unkeyed). */
	ctx = PK11_CreateDigestContext(algorithm->tag);
	if (ctx == NULL) {
		fprintf(stderr, "Error starting up digest.\n");
		fclose(fp);
		if (strcmp(tempfile, filename) != 0) {
			unlink(tempfile);
		}
		return SECFailure;
	}

	/* If we're doing an HMAC, digest the inner key. */
	if (ikeyval != NULL) {
		status = PK11_DigestOp(ctx, ikeyval, algorithm->blocksize);
		if (status != SECSuccess) {
			fprintf(stderr, "Error digesting HMAC key.\n");
			PK11_DestroyContext(ctx, PR_TRUE);
			fclose(fp);
			if (strcmp(tempfile, filename) != 0) {
				unlink(tempfile);
			}
			return status;
		}
	}

	/* Hash the file's contents. */
	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
		status = PK11_DigestOp(ctx, buf, n);
		if (status != SECSuccess) {
			fprintf(stderr, "Error digesting.\n");
			PK11_DestroyContext(ctx, PR_TRUE);
			fclose(fp);
			if (strcmp(tempfile, filename) != 0) {
				unlink(tempfile);
			}
			return status;
		}
	}
	if (fp != stdin) {
		fclose(fp);
	}

	/* Recover the output of the inner context. */
	status = PK11_DigestFinal(ctx, result, &len, algorithm->digestsize);
	if (status != SECSuccess) {
		fprintf(stderr, "Error recovering result.\n");
		PK11_DestroyContext(ctx, PR_TRUE);
		if (strcmp(tempfile, filename) != 0) {
			unlink(tempfile);
		}
		return status;
	}
	PK11_DestroyContext(ctx, PR_TRUE);

	/* If we're doing an HMAC, calculate the outer value. */
	if (okeyval != NULL) {
		/* Create a context. */
		ctx = PK11_CreateDigestContext(algorithm->tag);
		if (ctx == NULL) {
			fprintf(stderr, "Error starting up HMAC.\n");
			PK11_DestroyContext(ctx, PR_TRUE);
			if (strcmp(tempfile, filename) != 0) {
				unlink(tempfile);
			}
			return status;
		}
		/* Hash the outer key. */
		status = PK11_DigestOp(ctx, okeyval, algorithm->blocksize);
		if (status != SECSuccess) {
			fprintf(stderr, "Error digesting HMAC key.\n");
			PK11_DestroyContext(ctx, PR_TRUE);
			if (strcmp(tempfile, filename) != 0) {
				unlink(tempfile);
			}
			return status;
		}
		/* Hash the inner digest. */
		status = PK11_DigestOp(ctx, result, len);
		if (status != SECSuccess) {
			fprintf(stderr, "Error digesting inner digest.\n");
			PK11_DestroyContext(ctx, PR_TRUE);
			if (strcmp(tempfile, filename) != 0) {
				unlink(tempfile);
			}
			return status;
		}
		/* Recover the output of the outer context. */
		status = PK11_DigestFinal(ctx, result, &len,
					  algorithm->digestsize);
		if (status != SECSuccess) {
			fprintf(stderr, "Error recovering result.\n");
			PK11_DestroyContext(ctx, PR_TRUE);
			if (strcmp(tempfile, filename) != 0) {
				unlink(tempfile);
			}
			return status;
		}
		PK11_DestroyContext(ctx, PR_TRUE);
	}
	/* Generate the hex-encoded output. */
	for (u = 0; u < algorithm->digestsize; u++) {
		sprintf(hex_result + (u * 2), "%02x", result[u]);
	}
	if (strcmp(tempfile, filename) != 0) {
		unlink(tempfile);
	}
	return SECSuccess;
}

#ifndef NON_FIPS
static SECStatus
enable_fips(void)
{
	/* Relyea: unloading the internal module causes it to be reloaded in
	 * FIPS mode. */
	SECMODModule *m;
	if (PK11_IsFIPS()) {
		return SECSuccess;
	} else {
		m = SECMOD_GetInternalModule();
		if (m == NULL) {
			return SECFailure;
		}
		if (SECMOD_DeleteInternalModule(m->commonName) != SECSuccess) {
			return SECFailure;
		}
		if (PK11_IsFIPS()) {
			return SECSuccess;
		} else {
			return SECFailure;
		}
	}
}
#endif

#ifdef CHECK_SUFFIX
/* Build the name of the file, based on a (possibly relative) filename, which
 * will hold the checksum which corresponds to the file. */
static char *
build_sum_filename(const char *path)
{
	char *name;
#ifdef MAKE_CHECK_DIRECTORY
	const char *directory = MAKE_CHECK_DIRECTORY;
#else
#ifdef CHECK_DIRECTORY
	const char *directory = CHECK_DIRECTORY;
#else
	const char *directory = NULL;
#endif
#endif
	const char *p, *q;
	char cwd[PATH_MAX];
	name = NULL;
	if ((directory != NULL) && (strlen(directory) > 0)) {
		name = malloc(strlen(directory) + 1 +
			      strlen(path) +
			      strlen(CHECK_PREFIX) + 1 +
			      strlen(CHECK_SUFFIX) + 1);
		if (name != NULL) {
			p = strrchr(path, DIRSEP);
			strcpy(name, directory);
			name[strlen(directory) + 1] = '\0';
			name[strlen(directory)] = DIRSEP;
			strcat(name, CHECK_PREFIX);
			strcat(name, p + 1);
			strcat(name, "." CHECK_SUFFIX);
		}
	} else {
		if (strchr(path, DIRSEP) == NULL) {
			strncpy(cwd, getenv("PATH"), sizeof(cwd) - 1);
			cwd[sizeof(cwd) - 1] = '\0';
			p = cwd;
			q = cwd + strlen(cwd);
			while ((*p != '\0') && (p < q)) {
				if (strchr(p, ':') != NULL) {
					cwd[strchr(p, ':') - cwd] = '\0';
				}
				name = malloc(strlen(p) + 1 +
					      strlen(CHECK_PREFIX) +
					      strlen(path) + 1 +
					      strlen(CHECK_SUFFIX) + 1);
				if (name != NULL) {
					sprintf(name, "%s%c%s%s",
						p, DIRSEP,
						CHECK_PREFIX,
						path);
					if (access(name, X_OK) == 0) {
						strcat(name, "." CHECK_SUFFIX);
						break;
					}
				}
				free(name);
				name = NULL;
				p += strlen(p) + 1;
			}
		} else {
			/* Absolute path. */
			name = malloc(strlen(path) +
				      strlen(CHECK_PREFIX) + 1 +
				      strlen(CHECK_SUFFIX) + 1);
			if (name != NULL) {
				p = strrchr(path, DIRSEP);
				memcpy(name, path, p - path + 1);
				name[p - path + 1] = '\0';
				strcat(name, CHECK_PREFIX);
				strcat(name, p + 1);
				strcat(name, "." CHECK_SUFFIX);
			}
		}
	}
	return name;
}
#endif

static void
truncate_hex(char *hex, int bits)
{
	unsigned int term, final;
	const char hexchars[] = "00112233445566778899aAbBcCdDeEfF", *p;
	term = howmany(bits, 4);
	hex[term] = '\0';
	if ((bits % 4) != 0) {
		p = strchr(hexchars, hex[term - 1]);
		if (p != NULL) {
			final = (p - hexchars) / 2;
			final >>= (4 - (bits % 4));
			final <<= (4 - (bits % 4));
			sprintf(hex + term - 1, "%.1x", final);
		}
	}
}

int
main(int argc, char **argv)
{
	SECStatus status;
	FILE *fp;
	int i, c, ret, Pflag, qflag, sflag, bflag, truncate, checked;
	size_t n;
	unsigned int u;
	struct hashinfo *algorithm, *default_algorithm;
	const char *configdir, *copt, *kopt, *Kopt, *default_key;
	unsigned char *ikeyval, *okeyval, *sikeyval, *sokeyval, *result;
	char *filename, *hex_result, *expected;
	char cmd[PATH_MAX], cbuf[LINE_MAX];
	const char *usage = "Usage: hmac [OPTIONS] [-u | -k keyfile | -K key ] "
			    "[-c file [-q] | file [...] ]\n"
			    "-d DIRECTORY  use alternate configuration directory\n"
			    "-S            output self-test MAC on stdout\n"
			    "-u            compute an unkeyed digest\n"
			    "-k KEYFILE    use the specified key file\n"
			    "-K KEYVALUE   use the specified key\n"
			    "-b            read files in binary mode\n"
			    "-c            check hashes from file\n"
			    "-q            suppress check output\n"
			    "-P            unprelink before computing\n"
			    "-t BITS       truncate HMACs at BITS bits\n"
			    "-h ALGORITHM  use the specified hash algorithm "
#ifdef NON_FIPS
			    "(sha512/sha384/sha256/sha1/md5/md4/md2)\n";
#else
			    "(sha512/sha384/sha256/sha1)\n";
#endif

	/* Default settings: SHA-512, key = "FIPS-FTW-RHT2009". */
	configdir = DEFAULT_CONFIG_DIR;
	Kopt = default_key = "FIPS-FTW-RHT2009";
	kopt = NULL;
	copt = NULL;
	ret = 0;
	Pflag = 0;
	qflag = 0;
	sflag = 0;
	bflag = 0;
	truncate = 0;

	memset(cmd, '\0', sizeof(cmd));
	if (readlink("/proc/self/exe", cmd, sizeof(cmd) - 1) == -1) {
		strncpy(cmd, argv[0], sizeof(cmd) - 1);
	}

#ifndef DEFAULT_HASH
	/* Offer to select the algorithm using a prefix or suffix of the
	 * command name. */
	algorithm = &known_algorithms[0];
	default_algorithm = &known_algorithms[0];
	for (u = 0;
	     u < sizeof(known_algorithms) /
		 sizeof(known_algorithms[0]);
	     u++) {
		c = strlen(known_algorithms[u].hash);
		if (strlen(cmd) > c) {
			const char *p;
			if (strcasecmp(known_algorithms[u].hash,
				       cmd + strlen(cmd) - c) == 0) {
				default_algorithm = &known_algorithms[u];
				algorithm = default_algorithm;
				break;
			}
			p = strrchr(cmd, DIRSEP);
			if (p != NULL) {
				p++;
				if (strncasecmp(known_algorithms[u].hash,
						p, c) == 0) {
					default_algorithm = &known_algorithms[u];
					algorithm = default_algorithm;
					break;
				}
			}
		}
	}
#else
	/* Locate the hard-coded default hash algorithm. */
	default_algorithm = NULL;
	algorithm = NULL;
	for (u = 0;
	     u < sizeof(known_algorithms) /
		 sizeof(known_algorithms[0]);
	     u++) {
		if (strcmp(known_algorithms[u].hash, DEFAULT_HASH) == 0) {
			default_algorithm = &known_algorithms[u];
			algorithm = default_algorithm;
			break;
		}
	}
#endif

	while ((c = getopt(argc, argv, "Sbc:Pqd:h:k:K:t:u")) != -1) {
		switch (c) {
		case 'b':
			bflag++;
			break;
		case 'h':
			/* Select an algorithm other than the first. */
			for (u = 0;
			     u < sizeof(known_algorithms) /
			         sizeof(known_algorithms[0]);
			     u++) {
				if (!strcasecmp(optarg,
						known_algorithms[u].hash)) {
					algorithm = &known_algorithms[u];
					break;
				}
			}
			if (u >= sizeof(known_algorithms) /
				 sizeof(known_algorithms[0])) {
				fprintf(stderr, "Unrecognized hash \"%s\".\n",
					optarg);
				fprintf(stderr, "Recognized hashes: ");
				for (u = 0;
				     u < sizeof(known_algorithms) /
					 sizeof(known_algorithms[0]);
				     u++) {
					fprintf(stderr, "%s%s",
						u > 0 ? "," : "",
						known_algorithms[u].hash);
				}
				fprintf(stderr, "\n");
				exit(1);
			}
			break;
		case 'S':
			sflag++;
			break;
		case 'c':
			/* Check sums rather than just computing them. */
			copt = optarg;
			break;
		case 'P':
			Pflag++;
			break;
		case 'q':
			qflag++;
			break;
		case 'd':
			/* Use a configuration directory other than our
			 * compiled-in default. */
			configdir = optarg;
			break;
		case 'K':
			/* Use a key other than the default. */
			kopt = NULL;
			Kopt = optarg;
			break;
		case 'k':
			/* Use a key from a file. */
			kopt = optarg;
			Kopt = NULL;
			break;
		case 't':
			/* Truncate values to a specific bit length. */
			truncate = atoi(optarg);
			if (truncate <= 0) {
				truncate = (unsigned int) -1;
			}
			break;
		case 'u':
			/* Don't use a key -> compute an unkeyed hash rather
			 * than an HMAC. */
			kopt = NULL;
			Kopt = NULL;
			break;
		default:
			fprintf(stderr, "%s", usage);
			exit(-1);
			break;
		}
	}

	/* Either we're in checking mode, or we have the names of one or more
	 * files to hash, or we're in self-digest mode. */
	if (sflag) {
		if (copt != NULL) {
			fprintf(stderr,
				"-S and -c are not compatible\n%s", usage);
			exit(-1);
		}
		if (optind != argc) {
			fprintf(stderr,
				"-S can't be used with input files\n%s", usage);
			exit(-1);
		}
		if ((Kopt != default_key) || (kopt != NULL)) {
			fprintf(stderr,
				"-S can't be used with non-default key, "
				"or unkeyed\n%s",
				usage);
			exit(-1);
		}
		if (algorithm != default_algorithm) {
			fprintf(stderr,
				"-S can't be used with non-default hash\n%s",
				usage);
			exit(-1);
		}
	} else {
		if (((copt == NULL) && (optind == argc)) ||
		    ((copt != NULL) && (optind != argc))) {
			fprintf(stderr, "%s", usage);
			exit(-1);
		}
	}
	if (truncate == (unsigned int) -1) {
		fprintf(stderr, "Invalid bit length specified for -t.\n%s",
			usage);
		exit(-1);
	}

	/* Initialize NSS. */
	status = NSS_NoDB_Init(configdir);
	if (status != SECSuccess) {
		fprintf(stderr, "Error initializing NSS.\n");
		exit(status);
	}
#ifndef NON_FIPS
	status = enable_fips();
	if (status != SECSuccess) {
		fprintf(stderr, "Error ensuring FIPS mode.\n");
		NSS_Shutdown();
		exit(status);
	}
#endif
#ifndef ALLOW_ANY_TRUNCATION
	/* Per section 5, enforce a lower bound on the number of bits we're
	 * willing to truncate to. */
	if (truncate > 0) {
		if (truncate < (algorithm->digestsize * 8) / 2) {
			fprintf(stderr, "Error: asked to truncate "
				"%d-bit HMAC value to less than "
				"half its size (%d).\n",
				algorithm->digestsize * 8, truncate);
			NSS_Shutdown();
			exit(-1);
		} else {
			if (truncate < 80) {
				fprintf(stderr, "Error: asked to truncate "
					"%d-bit HMAC value to less than "
					"80 bits.\n",
					algorithm->digestsize * 8);
				NSS_Shutdown();
				exit(-1);
			}
		}
	}
#endif

	/* Allocate space to store the result.  (This will be used as temporary
	 * storage for the on-disk sum of this binary, and if we're computing
	 * or checking HMACs, it will also be used as the temporary storage for
	 * the inner digest.) */
	result = malloc(MAX(algorithm->digestsize * 2 + 2,
			    default_algorithm->digestsize * 2 + 2));
	if (result == NULL) {
		fprintf(stderr, "Out of memory.\n");
		NSS_Shutdown();
		exit(ENOMEM);
	}

	/* Allocate space to store a hex-encoded copy of the result. */
	hex_result = malloc(MAX(algorithm->digestsize * 2 + 1,
				default_algorithm->digestsize * 2 + 1));
	if (hex_result == NULL) {
		fprintf(stderr, "Out of memory.\n");
		NSS_Shutdown();
		exit(ENOMEM);
	}

	/* Generate the default/self-test key. */
	sikeyval = malloc(default_algorithm->blocksize);
	if (sikeyval == NULL) {
		fprintf(stderr, "Out of memory.\n");
		NSS_Shutdown();
		exit(ENOMEM);
	}
	sokeyval = malloc(default_algorithm->blocksize);
	if (sokeyval == NULL) {
		fprintf(stderr, "Out of memory.\n");
		NSS_Shutdown();
		exit(ENOMEM);
	}
	/* Produce a key (before XOR padding). */
	status = prepare_key(default_key, default_algorithm->tag,
			     sikeyval, default_algorithm->blocksize);
	if (status != SECSuccess) {
		fprintf(stderr, "Error processing default HMAC key.\n");
		NSS_Shutdown();
		exit(status);
	}
	/* Copy the plain key. */
	memcpy(sokeyval, sikeyval, default_algorithm->blocksize);
	/* Now XOR the keys with their corresponding pad values. */
	for (u = 0; u < default_algorithm->blocksize; u++) {
		sikeyval[u] ^= IPAD;
	}
	for (u = 0; u < default_algorithm->blocksize; u++) {
		sokeyval[u] ^= OPAD;
	}

	/* If we're generating an HMAC, initialize the inner and outer keys. */
	ikeyval = NULL;
	okeyval = NULL;
	if ((Kopt != NULL) || (kopt != NULL)) {
		ikeyval = malloc(algorithm->blocksize);
		if (ikeyval == NULL) {
			fprintf(stderr, "Out of memory.\n");
			NSS_Shutdown();
			exit(ENOMEM);
		}
		okeyval = malloc(algorithm->blocksize);
		if (okeyval == NULL) {
			fprintf(stderr, "Out of memory.\n");
			NSS_Shutdown();
			exit(ENOMEM);
		}
		/* Produce a key (before XOR padding). */
		status = Kopt ? prepare_key(Kopt, algorithm->tag,
					    ikeyval, algorithm->blocksize) :
				prepare_key_file(kopt, algorithm->tag,
						 ikeyval, algorithm->blocksize);
		if (status != SECSuccess) {
			fprintf(stderr, "Error processing HMAC key.\n");
			NSS_Shutdown();
			exit(status);
		}
		/* Copy the plain key. */
		memcpy(okeyval, ikeyval, algorithm->blocksize);
		/* Now XOR the keys with their corresponding pad values. */
		for (u = 0; u < algorithm->blocksize; u++) {
			ikeyval[u] ^= IPAD;
		}
		for (u = 0; u < algorithm->blocksize; u++) {
			okeyval[u] ^= OPAD;
		}
	}

	/* If we're computing over ourselves, just do that.  Otherwise check
	 * ourselves before checking anything else. */
	if (sflag) {
		/* Compute the checksum over this binary, and output just the
		 * sum on stdout. */
		ret = compute_one(cmd, 1, 1, default_algorithm,
				  sikeyval, sokeyval, result, hex_result);
		if (ret == SECSuccess) {
			if (fwrite(hex_result, 1,
				   default_algorithm->digestsize * 2,
				   stdout) != default_algorithm->digestsize * 2) {
				fprintf(stderr, "Error outputting value.\n");
				ret = errno;
				goto shutdown;
			}
			ret = 0;
		}
		goto shutdown;
#ifdef CHECK_SUFFIX
	} else {
		/* Compute the checksum over this binary, and compare it to the
		 * contents of the file whose name is the same as this one, but
		 * with the suffix appended. */
		ret = compute_one(cmd, 1, 1, default_algorithm,
				  sikeyval, sokeyval, result, hex_result);
		if (ret == SECSuccess) {
			/* Build the expected checksum filename and open it.
			 * We might need to get fancy and search $PATH to find
			 * the binary, but for now just assume that we were
			 * invoked using a full path. */
			filename = build_sum_filename(cmd);
			if (filename == NULL) {
				fprintf(stderr, "Out of memory.\n");
				ret = ENOMEM;
				goto shutdown;
			}
			fp = fopen(filename, "rb");
			if (fp == NULL) {
				fprintf(stderr, "%s: %s\n", filename,
					strerror(errno));
				free(filename);
				ret = ENOMEM;
				goto shutdown;
			}
			/* Try to read a bit too much, in case there's more
			 * data in there than we want. */
			n = fread(result, 1,
				  default_algorithm->digestsize * 2 + 2, fp);
			if ((n < default_algorithm->digestsize * 2) ||
			    ((n > default_algorithm->digestsize * 2) &&
			     (strchr("\r\n", result[default_algorithm->digestsize * 2]) == NULL))) {
				fprintf(stderr, "%s: %s read, expected "
					"%u bytes for %s HMAC\n",
					filename,
					n > default_algorithm->digestsize * 2 ?
					"long" : "short",
					default_algorithm->digestsize,
					default_algorithm->hash);
				fclose(fp);
				free(filename);
				ret = EINVAL;
				goto shutdown;
			}
			fclose(fp);
			/* Compare the just-read value to the just-computed
			 * value. */
			if (strncasecmp((const char *) result,
				        hex_result,
					default_algorithm->digestsize * 2) != 0) {
				fprintf(stderr, "SELF TEST FAILED (%s)\n",
					filename);
				free(filename);
				ret = EINVAL;
				goto shutdown;
			}
			free(filename);
		} else {
			/* Something went wrong digesting the binary. */
			goto shutdown;
		}
#endif
	}

	/* Walk the list of named files. */
	ret = ENOENT;
	if (copt == NULL) {
		for (i = optind; i < argc; i++) {
			/* Sum the named file. */
			ret = compute_one(argv[i], Pflag, bflag, algorithm,
					  ikeyval, okeyval, result, hex_result);
			if (ret != SECSuccess) {
				break;
			}
			/* Output. */
			if ((truncate > 0) &&
			    (truncate < (algorithm->digestsize * 8))) {
				truncate_hex(hex_result, truncate);
			}
			printf("%s %c%s\n", hex_result, bflag ? '*' : ' ',
			       argv[i]);
			ret = 0;
		}
	} else {
		/* Open the checkfile. */
		fp = strcmp(copt, "-") ? fopen(copt, "r") : stdin;
		if (fp == NULL) {
			fprintf(stderr, "Error opening \"%s\": %s.\n", copt,
				strerror(errno));
			ret = errno;
		} else {
			/* Iterate through the files named by the input file. */
			ret = 0;
			checked = 0;
			while (fgets(cbuf, sizeof(cbuf), fp) != NULL) {
				/* Skip up to the first non-whitespace. */
				expected = cbuf;
				expected += strspn(expected, " \t");
				if (*expected == '#') {
					continue;
				}
				/* Isolate the expected value and the path. */
				filename = expected + strcspn(expected, " \t");
				if ((filename - expected) !=
				    (truncate ?
				     howmany(truncate, 4) :
				     (algorithm->digestsize * 2))) {
					/* Not a value we'd produce. */
					filename += strspn(filename, " \t");
					filename[strcspn(filename, "\r\n")] = '\0';
					fprintf(stderr, "%s: FAILED\n"
						" value to be checked was the"
						" wrong size (read %d chars,"
						" expected %d chars)\n",
						filename,
						strcspn(expected, " \t"),
						truncate ?
						howmany(truncate, 4) :
						(algorithm->digestsize * 2));
					ret = -1;
					break;
				}
				filename += strspn(filename, " \t");
				expected[strcspn(expected, " \t")] = '\0';
				if ((truncate > 0) &&
				    (truncate < (algorithm->digestsize * 8)) &&
				    (strlen(expected) > howmany(truncate, 4))) {
					truncate_hex(expected, truncate);
				}
				filename[strcspn(filename, "\r\n")] = '\0';
				/* Figure out if we're checking in binary mode
				 * or not. */
				bflag = (filename[0] == '*');
				if (bflag) {
					filename++;
				}
				/* Compute the HMAC or checksum. */
				status = compute_one(filename, Pflag, bflag,
						     algorithm,
						     ikeyval, okeyval, result,
						     hex_result);
				if (status != SECSuccess) {
					ret = status;
					break;
				}
				/* Compare the value to the stored value. */
				if ((truncate > 0) &&
				    (truncate < (algorithm->digestsize * 8))) {
					truncate_hex(hex_result, truncate);
				}
				checked++;
				if (strcasecmp(expected, hex_result) != 0) {
					if (!qflag) {
						fprintf(stderr, "%s: FAILED\n"
							" computed = %s\n"
							" expected = %s\n",
							filename, hex_result,
							expected);
					}
					ret = -1;
					break;
				} else {
					if (!qflag) {
						fprintf(stderr, "%s: OK\n",
							filename);
					}
				}
			}
			if (fp != stdin) {
				fclose(fp);
			}
			if (checked == 0) {
				fprintf(stderr, "%s: no properly formatted %s "
					"checksum lines found\n", copt,
					default_algorithm->hash);
				ret = -1;
			}
		}
	}

shutdown:
	/* Clean up and exit. */
	NSS_Shutdown();
	memset(sikeyval, '\0', default_algorithm->blocksize);
	memset(sokeyval, '\0', default_algorithm->blocksize);
	if (ikeyval != NULL) {
		memset(ikeyval, '\0', algorithm->blocksize);
		free(ikeyval);
	}
	if (okeyval != NULL) {
		memset(okeyval, '\0', algorithm->blocksize);
		free(okeyval);
	}
	free(sikeyval);
	free(sokeyval);
	free(hex_result);
	free(result);
	return ret;
}
