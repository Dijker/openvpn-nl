/*
 *  A simple client for openvpn --management-external-key.
 *
 *  Copyright (C) 2012 Fox Crypto B.V. <openvpn@fox-it.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * This code depends only on PolarSSL.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <polarssl/base64.h>
#include <polarssl/error.h>
#include <polarssl/rsa.h>
#include <polarssl/x509.h>

#define USAGE ("Usage: %s [-l] [-H host] port key\n" \
    "Client for openvpn --management-external-key\n" \
    "\n" \
    "  -H host  connect to host instead of localhost\n" \
    "  -l       request OpenVPN logs\n" \
    "  port     port of the OpenVPN management interface\n" \
    "  key      keyfile (in PEM format) to use\n")

/* Management interface requesting a signature */
#define RSA_PROMPT_PREFIX ">RSA_SIGN:"
#define RSA_RESP_PREFIX "rsa-sig\r\n"
#define RSA_RESP_SUFFIX "\r\nEND\r\n"

#ifndef __GNUC__
#define __attribute__(x) /* gcc only */
#endif

int main(int argc, char **argv);
/* Connect to management interface; returns socket or terminates program */
static inline int open_sock(const char *host, const char *port);
/* Communicate with OpenVPN */
static inline void management_client(int management_sock, const char *keyfile,
    int request_logs) __attribute__((noreturn));
/*
 * Write some initial commands requesting logs etc. Returns 0 on success, or
 * nonzero and sets errno.
 */
static inline int write_initial_commands(int management_sock,
    int request_logs);
/*
 * Handle a line of line_len characters; if partial, line is an incomplete last
 * line.
 *
 * Returns a pointer to a statically allocated string containing a response, or
 * NULL on error.
 */
static inline const char *handle_line(const char *line, size_t line_len,
    int partial, rsa_context *rsa);
/* Called by handle_line() to handle RSA_SIGN requests */
static inline const char *rsa_resp(const char *line, size_t line_len,
    rsa_context *rsa);
static char handle_line_resp[1024];
/* Repeated write: like write(), but continue writing on signals etc. */
static inline ssize_t rwrite(int fd, const void *buf, size_t count);

int
main(int argc, char **argv)
{
	const char	*port, *host, *progname, *keyfile;
	int		 sock, opt, request_logs;

	/*
	 * Parse arguments
	 */
	progname = argv[0];

	request_logs = 0;
	host = "localhost";

	while ((opt = getopt(argc, argv, "lH:")) != -1) {
		switch (opt) {
		case 'l':
			request_logs = 1;
			break;
		case 'H':
			host = optarg;
			break;
		default:
			errx(127, USAGE, progname);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2)
		errx(127, USAGE, progname);

	port = argv[0];
	keyfile = argv[1];

	/* XXX Management protocol password? */

	printf("Connecting to %s:%s...\n", host, port);
	sock = open_sock(host, port);

	management_client(sock, keyfile, request_logs);
	/* NOTREACHED */
}

static inline int
open_sock(const char *host, const char *port)
{
	struct addrinfo		*addrs, hints;
	int			 rv, sock;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((rv = getaddrinfo(host, port, NULL, &addrs)) != 0)
		errx(1, "Failed to resolve %s port %s: %s", host, port,
		    gai_strerror(rv));

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "Failed to create socket");

	/* Connect to first address; good enough. */
	if (connect(sock, addrs[0].ai_addr, addrs[0].ai_addrlen) != 0)
		err(1, "Failed to connect to %s port %s", host, port);

	return sock;
}

static inline void
management_client(int management_sock, const char *keyfile, int request_logs)
{
	char		 buf[4096];
	const char	*resp;
	size_t		 buf_len, i, eol;
	ssize_t		 bytes_read;
	int		 rv;
	rsa_context	 rsa;

	rsa_init(&rsa, RSA_PKCS_V15, 0);

	if ((rv = x509parse_keyfile(&rsa, keyfile, NULL)) != 0) {
		error_strerror(rv, buf, sizeof(buf));
		errx(1, "Failed to load %s: %s", keyfile, buf);
	}

	if (write_initial_commands(management_sock, request_logs) != 0)
		err(1, "Failed to write initial commands\n");

	buf_len = 0;
	while (1) {
		/*
		 * Read from management interface
		 */
		if (sizeof(buf) - buf_len == 0)
			err(1, "Line longer than buffer");

		bytes_read = read(management_sock, &buf[buf_len],
		    sizeof(buf) - buf_len);
		if (bytes_read == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			err(1, "Failed to read()");
		}

		if (bytes_read == 0) {
			(void) handle_line(buf, buf_len, 1, &rsa);
			fprintf(stderr, "Management connection terminated.\n");
			exit(0);
		}

		buf_len += bytes_read;

		i = 0;
		while (1) {
			/*
			 * Find whole line in buf[i..eol] and parse it.
			 */
			for (eol = i;
			    eol < buf_len && buf[eol] != '\n';
			    eol++);
			if (eol == buf_len)
				break;

			assert(buf[eol] == '\n');

			if ((resp = handle_line(&buf[i], eol + 1 - i, 0, &rsa))
			    == NULL)
				errx(1, "Failed to handle line");
			errno = EINVAL;
			if (strlen(resp) > SSIZE_MAX ||
			    rwrite(management_sock, resp, strlen(resp)) !=
			    (ssize_t) strlen(resp))
				err(1, "Failed to write response (\"%s\")",
				    resp);

			i = eol + 1;
		}

		/* Copy unparsed data to front (fast enough) */
		bcopy(&buf[i], buf, buf_len - i);
		buf_len -= i;
	}
	/* NOTREACHED */
}

static inline int
write_initial_commands(int management_sock, int request_logs)
{
	const char *initial_commands;

	if (request_logs)
		initial_commands = "log on all\necho on all\nbytecount 10\n";
	else
		initial_commands = "echo on all\nbytecount 10\n";

	if (rwrite(management_sock, initial_commands,
		    strlen(initial_commands)) !=
	    (ssize_t) strlen(initial_commands))
		return -1;

	return 0;
}

static inline const char *
handle_line(const char *line, size_t line_len, int partial_line,
    rsa_context *rsa)
{
	size_t			 i;

	/* Print line */
	for (i = 0; i < line_len; i++)
		putchar(line[i]);
	if (partial_line)
		putchar('\n');

	if (!partial_line && line_len >= sizeof(RSA_PROMPT_PREFIX) &&
	    strncmp(line, RSA_PROMPT_PREFIX, sizeof(RSA_PROMPT_PREFIX) - 1)
	    == 0)
		return rsa_resp(line, line_len, rsa);
	else {
		/* Not an RSA_SIGN request, stop processing */
		handle_line_resp[0] = '\0';
		return handle_line_resp;
	}
}

static inline const char *
rsa_resp(const char *line, size_t line_len, rsa_context *rsa)
{
	unsigned char		 raw_data[1024], sig[1024];
	size_t			 raw_data_len, out_len;

	/* Base64-decode the relevant part of the line into raw_data */
	assert(line_len >= sizeof(RSA_PROMPT_PREFIX) - 1);
	assert(strncmp(line, RSA_PROMPT_PREFIX, sizeof(RSA_PROMPT_PREFIX) - 1)
	    == 0);
	assert(line[line_len - 2] == '\r');
	assert(line[line_len - 1] == '\n');

	raw_data_len = sizeof(raw_data);
	if (base64_decode(raw_data, &raw_data_len,
		    (const unsigned char *)
		    &line[sizeof(RSA_PROMPT_PREFIX) - 1],
		    line_len - (sizeof(RSA_PROMPT_PREFIX) - 1) - 2) != 0)
		goto err;

	/*
	 * Sign raw_data.
	 *
	 * Note that we need no PRNG (f_prng = NULL) for PKCS1.5 encoding
	 */
	if (sizeof(sig) < rsa->len ||
	    rsa_pkcs1_sign(rsa, NULL, NULL, RSA_PRIVATE, SIG_RSA_RAW,
		    raw_data_len, raw_data, sig) != 0)
		goto err;

	/* Base64-encode signature */
	memcpy(handle_line_resp, RSA_RESP_PREFIX, sizeof(RSA_RESP_PREFIX) - 1);

	out_len = sizeof(handle_line_resp) - (sizeof(RSA_RESP_PREFIX) - 1) -
	    (sizeof(RSA_RESP_SUFFIX) - 1) + 1;
	if (base64_encode((unsigned char *)
		    &handle_line_resp[sizeof(RSA_RESP_PREFIX) - 1], &out_len,
		    sig, rsa->len) != 0)
		goto err;
	out_len += sizeof(RSA_RESP_PREFIX) - 1;

	memcpy(&handle_line_resp[out_len], RSA_RESP_SUFFIX,
	    sizeof(RSA_RESP_SUFFIX) - 1);

	return handle_line_resp;

err:
	return NULL;
}

static inline ssize_t
rwrite(int fd, const void *vbuf, size_t count)
{
	const char * const
	    		 buf = vbuf;
	size_t		 i;
	ssize_t		 bytes_written;
	int		 old_errno;

	old_errno = errno;

	i = 0;
	do {
		bytes_written = write(fd, &buf[i], count - i);
		if (bytes_written == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return bytes_written;
		}
		if (bytes_written == 0)
			goto done;

		i += bytes_written;
	} while (i < count);

done:
	errno = old_errno;
	return i;
}
