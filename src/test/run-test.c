/*
 * Copyright 2009 Red Hat, Inc.
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	const char *tool, *key, *data, *result, *p;
	const char digits[] = "00112233445566778899aAbBcCdDeEfF";
	char keyfile[PATH_MAX], datafile[PATH_MAX], checkfile[PATH_MAX],
	     cmd[PATH_MAX * 4 + 4], *truncate;
	int fd, status, i;
	unsigned char c;
	FILE *fp;
	if (argc < 4) {
		printf("Incorrect invocation.\n");
		exit(1);
	}
	tool = argv[1];
	key = argv[2];
	data = argv[3];
	result = argv[4];
	truncate = argv[5]; /* either NULL or a value */
	strcpy(keyfile, "keyXXXXXX");
	fd = mkstemp(keyfile);
	if (fd == -1) {
		printf("Error creating temporary file.\n");
		exit(1);
	}
	close(fd);
	strcpy(datafile, "dataXXXXXX");
	fd = mkstemp(datafile);
	if (fd == -1) {
		printf("Error creating temporary file.\n");
		unlink(keyfile);
		exit(1);
	}
	close(fd);
	strcpy(checkfile, "checkXXXXXX");
	fd = mkstemp(checkfile);
	if (fd == -1) {
		printf("Error creating temporary file.\n");
		unlink(keyfile);
		unlink(datafile);
		exit(1);
	}
	close(fd);
	fp = fopen(keyfile, "w");
	if (strncmp(key, "0x", 2) == 0) {
		for (i = 2, c = 0; key[i] != '\0'; i++) {
			p = strchr(digits, key[i]);
			if ((i % 2) == 1) {
				c <<= 4;
			}
			if (p != NULL) {
				c |= ((p - digits) / 2);
			}
			if ((i % 2) == 1) {
				fputc(c, fp);
				c = 0;
			}
		}
	} else {
		fprintf(fp, "%s", key);
	}
	fflush(fp);
	fsync(fileno(fp));
	fclose(fp);
	fp = fopen(datafile, "w");
	if (strncmp(data, "0x", 2) == 0) {
		for (i = 2, c = 0; data[i] != '\0'; i++) {
			p = strchr(digits, data[i]);
			if ((i % 2) == 1) {
				c <<= 4;
			}
			if (p != NULL) {
				c |= ((p - digits) / 2);
			}
			if ((i % 2) == 1) {
				fputc(c, fp);
				c = 0;
			}
		}
	} else {
		fprintf(fp, "%s", data);
	}
	fflush(fp);
	fsync(fileno(fp));
	fclose(fp);
	if (strncmp(result, "0x", 2) == 0) {
		fp = fopen(checkfile, "w");
		fprintf(fp, "%s  %s\n", result + 2, datafile);
		fflush(fp);
		fsync(fileno(fp));
		fclose(fp);
	} else {
		printf("Error writing expected result to temporary file.\n");
		status = 1;
		goto finish;
	}
	sprintf(cmd, "%s -q -k \"%s\" -c \"%s\" %s %s",
		tool, keyfile, checkfile,
		truncate ? "-t" : "", truncate ? truncate : "");
	status = system(cmd);
finish:
	unlink(keyfile);
	unlink(datafile);
	unlink(checkfile);
	return status ? 1 : 0;
}
