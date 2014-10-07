/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2010-2012 Fox Crypto B.V. <openvpn@fox-it.com>
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

/**
 * @file Restricted ciphers and digests code file.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"
#include "allowed_crypto.h"

#ifdef ENABLE_CRYPTO

#ifdef ENABLE_CRYPTO_POLARSSL
const char *allowed_tls_ciphers[] = {
    "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384",
    "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256",
    "TLS-DHE-RSA-WITH-AES-256-CBC-SHA",
    NULL
  };
#else
const char *allowed_tls_ciphers =
    "SSL-EDH-RSA-AES-256-SHA";
#endif
/* Fox-IT hardening: only accept these data channel ciphers. */
const char *allowed_data_channel_ciphers[] = {
    "AES-256-CBC",
    NULL
  };

/* Fox-IT hardening: only accept these data channel digests. */
const char *allowed_data_channel_digests[] = {
    "SHA256",
    NULL
  };

/* Fox-IT hardening: only accept these PRNG digests. */
const char *allowed_prng_digests[] = {
    "SHA256",
    NULL
  };


/*
 * Check whether a given cipher name is listed as allowed.
 * Return 1 if the cipher is allowed, otherwise return 0.
 */
int is_allowed_data_channel_cipher(const char *name)
{
  const char **allowed = allowed_data_channel_ciphers;
  for (; *allowed; ++allowed)
  {
    if (!strcasecmp(*allowed, name))
      return 1;
  }
  return 0;
}

/*
 * Check whether a given digest name is listed as allowed.
 * Return 1 if the digest is allowed, otherwise return 0.
 */
int is_allowed_data_channel_digest(const char *name)
{
  const char **allowed = allowed_data_channel_digests;
  for (; *allowed; ++allowed)
  {
    if (!strcasecmp(*allowed, name))
      return 1;
  }
  return 0;
}

/*
 * Check whether a given digest name is listed as allowed.
 * Return 1 if the digest is allowed, otherwise return 0.
 */
int is_allowed_prng_digest(const char *name)
{
  const char **allowed = allowed_prng_digests;
  for (; *allowed; ++allowed)
  {
    if (!strcasecmp(*allowed, name))
      return 1;
  }
  return 0;
}

#ifdef ENABLE_CRYPTO_POLARSSL
/*
 * Check whether a given TLS cipher name is listed as allowed.
 * Return 1 if the digest is allowed, otherwise return 0
 */
int is_allowed_tls_cipher(const char *name)
{
  const char **allowed = allowed_tls_ciphers;
  for (; *allowed; ++allowed)
  {
    if (!strcasecmp(*allowed, name))
      return 1;
  }
  return 0;
}
#endif

#endif /* ENABLE_CRYPTO */
