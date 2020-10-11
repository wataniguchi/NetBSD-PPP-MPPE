/*
 * ppp_mppe_compress.c - interface MPPE to the PPP code.
 * This version is for use with NetBSD kernel 9.
 *
 * By Frank Cusack <frank@google.com>.
 * Copyright (c) 2002,2003,2004 Google, Inc.
 * All rights reserved.
 * Copyright (c) 1999 Darrin B. Jewell <dbj@NetBSD.org>
 * Copyright (c) 2004, 2005 Quentin Garnier <cube@NetBSD.org>
 * Copyright (c) 2020 Wataru Taniguchi <wataru@taniguchifamily.com>
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied.
 *
 * Changelog:
 *      2/15/04 - TS: added #include <version.h> and testing for Kernel
 *                    version before using 
 *                    MOD_DEC_USAGE_COUNT/MOD_INC_USAGE_COUNT which are
 *                    deprecated in 2.6
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>

#define PACKETPTR	struct mbuf *

#include <net/ppp_defs.h>
#include <net/if_ppp.h>
#include <net/ppp-comp.h>

#include <sys/sha1.h>
#include "arc4.h"

int mppe_in_use;
#define MOD_INC_USE_COUNT	mppe_in_use++
#define MOD_DEC_USE_COUNT	mppe_in_use--

#ifdef MPPE_DEBUG
#define DPRINTF(x)	aprint_normal x
#else
#define DPRINTF(x)
#endif

/*
 * State for an MPPE (de)compressor.
 */
typedef struct ppp_mppe_state {
    unsigned char	master_key[MPPE_MAX_KEY_LEN];
    unsigned char	session_key[MPPE_MAX_KEY_LEN];
    void		*arcfour_context; /* encryption state */
    unsigned 		keylen;		/* key length in bytes             */
					/* NB: 128-bit == 16, 40-bit == 8! */
					/* If we want to support 56-bit,   */
					/* the unit has to change to bits  */
    unsigned char	bits;		/* MPPE control bits */
    unsigned		ccount;		/* 12-bit coherency count (seqno)  */
    unsigned		stateful;	/* stateful mode flag */
    int			discard;	/* stateful mode packet loss flag */
    int			sanity_errors;	/* take down LCP if too many */
    int			unit;
    int			debug;
    struct compstat	stats;
} ppp_mppe_state;

/* ppp_mppe_state.bits definitions */
#define MPPE_BIT_A	0x80	/* Encryption table were (re)inititalized */
#define MPPE_BIT_B	0x40	/* MPPC only (not implemented) */
#define MPPE_BIT_C	0x20	/* MPPC only (not implemented) */
#define MPPE_BIT_D	0x10	/* This is an encrypted frame */

#define MPPE_BIT_FLUSHED	MPPE_BIT_A
#define MPPE_BIT_ENCRYPTED	MPPE_BIT_D

#define MPPE_BITS(p) ((p)[4] & 0xf0)
#define MPPE_CCOUNT(p) ((((p)[4] & 0x0f) << 8) + (p)[5])
#define MPPE_CCOUNT_SPACE 0x1000	/* The size of the ccount space */

#define MPPE_OVHD	2		/* MPPE overhead/packet */
#define SANITY_MAX	1600		/* Max bogon factor we will tolerate */

static void	GetNewKeyFromSHA __P((unsigned char *StartKey,
				      unsigned char *SessionKey,
				      unsigned SessionKeyLength,
				      unsigned char *InterimKey));
static void	mppe_rekey __P((ppp_mppe_state *state, int));
static void	*mppe_alloc __P((unsigned char *options, int optlen));
static void	mppe_free __P((void *state));
static int	mppe_init __P((void *state, unsigned char *options,
			       int optlen, int unit, int debug, const char *));
static int	mppe_comp_init __P((void *state, unsigned char *options,
				    int optlen,
				    int unit, int hdrlen, int debug));
static int	mppe_decomp_init __P((void *state, unsigned char *options,
				      int optlen, int unit,
				      int hdrlen, int mru, int debug));
static int	mppe_compress __P((void *state, struct mbuf **opkt,
				   struct mbuf *ipkt,
				   int isize, int osize));
static void	mppe_incomp __P((void *state, struct mbuf *mp));
static int	mppe_decompress __P((void *state, struct mbuf *ipkt,
				     struct mbuf **opkt));
static void	mppe_comp_reset __P((void *state));
static void	mppe_decomp_reset __P((void *state));
static void	mppe_comp_stats __P((void *state, struct compstat *stats));


/*
 * Key Derivation, from RFC 3078, RFC 3079.
 * Equivalent to Get_Key() for MS-CHAP as described in RFC 3079.
 */
static void
GetNewKeyFromSHA(unsigned char *MasterKey, unsigned char *SessionKey,
		 unsigned SessionKeyLength, unsigned char *InterimKey)
{
    SHA1_CTX Context;
    unsigned char Digest[20];

    unsigned char SHApad1[40] =
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    unsigned char SHApad2[40] =
    { 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
      0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
      0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
      0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2 };

    /* assert(SessionKeyLength <= SHA1_SIGNATURE_SIZE); */

    SHA1Init(&Context);
    SHA1Update(&Context, MasterKey, SessionKeyLength);
    SHA1Update(&Context, SHApad1, sizeof(SHApad1));
    SHA1Update(&Context, SessionKey, SessionKeyLength);
    SHA1Update(&Context, SHApad2, sizeof(SHApad2));
    SHA1Final(Digest, &Context);

    memcpy(InterimKey, Digest, SessionKeyLength);
}

/*
 * Perform the MPPE rekey algorithm, from RFC 3078, sec. 7.3.
 * Well, not what's written there, but rather what they meant.
 */
static void
mppe_rekey(ppp_mppe_state *state, int initial_key)
{
    unsigned char InterimKey[MPPE_MAX_KEY_LEN];

    GetNewKeyFromSHA(state->master_key, state->session_key,
		     state->keylen, InterimKey);
    if (!initial_key) {
	arc4_setkey(state->arcfour_context, InterimKey, state->keylen);
	arc4_encrypt(state->arcfour_context, state->session_key, InterimKey,
			state->keylen);
    } else {
	memcpy(state->session_key, InterimKey, state->keylen);
    }
    if (state->keylen == 8) {
	/* See RFC 3078 */
	state->session_key[0] = 0xd1;
	state->session_key[1] = 0x26;
	state->session_key[2] = 0x9e;
    }
    arc4_setkey(state->arcfour_context, state->session_key, state->keylen);
}


/*
 * Allocate space for a (de)compressor.
 */
static void *
mppe_alloc(unsigned char *options, int optlen)
{
    ppp_mppe_state *state;

    if (optlen != CILEN_MPPE + sizeof(state->master_key)
	|| options[0] != CI_MPPE
	|| options[1] != CILEN_MPPE)
	return NULL;

    state = (ppp_mppe_state *) malloc(sizeof(*state), M_DEVBUF, M_NOWAIT);
    if (state == NULL)
	return NULL;
    state->arcfour_context = NULL;

    MOD_INC_USE_COUNT;
    memset(state, 0, sizeof(*state));

    /* Save keys. */
    memcpy(state->master_key, &options[CILEN_MPPE], sizeof(state->master_key));
    memcpy(state->session_key, state->master_key, sizeof(state->master_key));
    /*
     * We defer initial key generation until mppe_init(), as mppe_alloc()
     * is called frequently during negotiation.
     */

    return (void *) state;
}

/*
 * Deallocate space for a (de)compressor.
 */
static void
mppe_free(void *arg)
{
    ppp_mppe_state *state = (ppp_mppe_state *) arg;

    if (state) {
	if (state->arcfour_context)
	    free(state->arcfour_context, M_DEVBUF);
	free(state, M_DEVBUF);
	MOD_DEC_USE_COUNT;
    }
}


/* 
 * Initialize (de)compressor state.
 */
static int
mppe_init(void *arg, unsigned char *options, int optlen, int unit, int debug,
	  const char *debugstr)
{
    ppp_mppe_state *state = (ppp_mppe_state *) arg;
    unsigned char mppe_opts;

    if (optlen != CILEN_MPPE
	|| options[0] != CI_MPPE
	|| options[1] != CILEN_MPPE)
	return 0;

    MPPE_CI_TO_OPTS(&options[2], mppe_opts);
    if (mppe_opts & MPPE_OPT_128)
	state->keylen = 16;
    else if (mppe_opts & MPPE_OPT_40)
	state->keylen = 8;
    else {
	aprint_error("%s[%d]: unknown key length\n", debugstr, unit);
	return 0;
    }
    if (mppe_opts & MPPE_OPT_STATEFUL)
	state->stateful = 1;

    state->arcfour_context = malloc(arc4_ctxlen(), M_DEVBUF, M_NOWAIT);
    if (state->arcfour_context == NULL)
	return 0;

    /* Generate the initial session key. */
    mppe_rekey(state, 1);

    if (debug) {
	int i;
	char mkey[sizeof(state->master_key) * 2 + 1];
	char skey[sizeof(state->session_key) * 2 + 1];

	aprint_normal("%s[%d]: initialized with %d-bit %s mode\n", debugstr,
	       unit, (state->keylen == 16)? 128: 40,
	       (state->stateful)? "stateful": "stateless");

	for (i = 0; i < (int)sizeof(state->master_key); i++)
	    snprintf(mkey + i * 2, sizeof(mkey) - i * 2, "%.2x", state->master_key[i]);
	for (i = 0; i < (int)sizeof(state->session_key); i++)
	    snprintf(skey + i * 2, sizeof(skey) - i * 2, "%.2x", state->session_key[i]);
	aprint_normal("%s[%d]: keys: master: %s initial session: %s\n",
	       debugstr, unit, mkey, skey);
    }

    /*
     * Initialize the coherency count.  The initial value is not specified
     * in RFC 3078, but we can make a reasonable assumption that it will
     * start at 0.  Setting it to the max here makes the comp/decomp code
     * do the right thing (determined through experiment).
     */
    state->ccount = MPPE_CCOUNT_SPACE - 1;

    /*
     * Note that even though we have initialized the key table, we don't
     * set the FLUSHED bit.  This is contrary to RFC 3078, sec. 3.1.
     */
    state->bits = MPPE_BIT_ENCRYPTED;

    state->unit  = unit;
    state->debug = debug;

    return 1;
}



static int
mppe_comp_init(void *arg, unsigned char *options, int optlen, int unit,
	       int hdrlen, int debug)
{
    /* ARGSUSED */
    return mppe_init(arg, options, optlen, unit, debug, "mppe_comp_init");
}

/*
 * We received a CCP Reset-Request (actually, we are sending a Reset-Ack),
 * tell the compressor to rekey.  Note that we MUST NOT rekey for
 * every CCP Reset-Request; we only rekey on the next xmit packet.
 * We might get multiple CCP Reset-Requests if our CCP Reset-Ack is lost.
 * So, rekeying for every CCP Reset-Request is broken as the peer will not
 * know how many times we've rekeyed.  (If we rekey and THEN get another
 * CCP Reset-Request, we must rekey again.)
 */
static void
mppe_comp_reset(void *arg)
{
    ppp_mppe_state *state = (ppp_mppe_state *) arg;

    state->bits |= MPPE_BIT_FLUSHED;
}

/*
 * Compress (encrypt) a packet.
 * It's strange to call this a compressor, since the output is always
 * MPPE_OVHD + 2 bytes larger than the input.
 */
int
mppe_compress(void *arg, struct mbuf **mret, struct mbuf *mp,
	      int isize, int osize)
{
    ppp_mppe_state *state = (ppp_mppe_state *) arg;
    int proto;
    unsigned char *ibuf, *obuf;

    *mret = NULL;
    ibuf = mtod(mp, unsigned char *);
    /*
     * Check that the protocol is in the range we handle.
     */
    proto = PPP_PROTOCOL(ibuf);
    if (proto < 0x0021 || proto > 0x00fa) {
	DPRINTF(("unhandled proto %d\n", proto));
	return 0;
    }

    /* Make sure we have enough room to generate an encrypted packet. */
    /* XXX */
    if (osize + MPPE_OVHD < isize + MPPE_OVHD) {
	/* Drop the packet if we should encrypt it, but can't. */
	aprint_normal("mppe_compress[%d]: osize too small! "
	       "(have: %d need: %d)\n", state->unit,
	       osize, isize + MPPE_OVHD + 2);
	/* XXX */
	return 0;
    }

    osize = isize + MPPE_OVHD + 2;

    /* Allocate an mbuf chain to hold the encrypted packet */
    {
      struct mbuf *mfirst = NULL;
      struct mbuf *mprev;
      struct mbuf *m = NULL;
      int bleft = isize+MPPE_OVHD+2;
      do {
	mprev = m;
	MGET(m,M_DONTWAIT, MT_DATA);
	if (m == NULL) {
	  m_freem(mfirst);
	  /* XXX: what should we do here?  If we return NULL, the data
	   * will go out unencrypted. We can't use M_WAITOK, since this
	   * will be called from splsoftnet()
	   */
	  panic("ppp%d/mppe: unable to allocate mbuf to encrypt packet",
		state->unit);
	}
	m->m_len = 0;
	if (mfirst == NULL) {
	  mfirst = m;
	  m_copy_pkthdr(m,mp);
	  if (bleft > MHLEN) {
	    MCLGET(m, M_DONTWAIT);
	  }
	} else {
	  mprev->m_next = m;
	  if (bleft > MLEN) {
	    MCLGET(m, M_DONTWAIT);
	  }
	}
	bleft -= M_TRAILINGSPACE(m);
      } while (bleft > 0);
      *mret = mfirst;
    }

    obuf = mtod(*mret, unsigned char *);

    /*
     * Copy over the PPP header and set control bits.
     */
    obuf[0] = PPP_ADDRESS(ibuf);
    obuf[1] = PPP_CONTROL(ibuf);
    obuf[2] = PPP_COMP >> 8;		/* isize + MPPE_OVHD + 1 */
    obuf[3] = PPP_COMP;			/* isize + MPPE_OVHD + 2 */
    obuf += PPP_HDRLEN;

    state->ccount = (state->ccount + 1) % MPPE_CCOUNT_SPACE;
    if (state->debug >= 7)
	aprint_verbose("mppe_compress[%d]: ccount %d\n", state->unit,
	       state->ccount);
    obuf[0] = state->ccount >> 8;
    obuf[1] = state->ccount & 0xff;

    if (!state->stateful ||			/* stateless mode     */
	((state->ccount & 0xff) == 0xff) ||	/* "flag" packet      */
	(state->bits & MPPE_BIT_FLUSHED)) {	/* CCP Reset-Request  */
	/* We must rekey */
	if (state->debug && state->stateful)
	    aprint_verbose("mppe_compress[%d]: rekeying\n", state->unit);
	mppe_rekey(state, 0);
	state->bits |= MPPE_BIT_FLUSHED;
    }
    obuf[0] |= state->bits;
    state->bits &= ~MPPE_BIT_FLUSHED;	/* reset for next xmit */

    ibuf  += 2;	/* skip to proto field */
    isize -= 2;
    (*mret)->m_len += PPP_HDRLEN + MPPE_OVHD;

    /* March down input and output mbuf chains, encoding with RC4 */
    {
      struct mbuf *mi = mp;	/* mbuf in */
      struct mbuf *mo = *mret;	/* mbuf out */
      int maxi, maxo;
      maxi = mi->m_len-2;
      maxo = M_TRAILINGSPACE(mo);
      while (mi) {
	if (maxi < maxo) {
	  arc4_encrypt(state->arcfour_context,
	      mtod(mo,unsigned char *)+mo->m_len,
	      mtod(mi,unsigned char *)+mi->m_len-maxi,
	      maxi);
	  mo->m_len += maxi;
	  maxo -= maxi;
	  mi = mi->m_next;
	  if (mi) {
	    maxi = mi->m_len;
	  }
	} else if (maxi > maxo) {
	  arc4_encrypt(state->arcfour_context,
	      mtod(mo,unsigned char *)+mo->m_len,
	      mtod(mi,unsigned char *)+mi->m_len-maxi,
	      maxo);
	  mo->m_len += maxo;
	  maxi -= maxo;
	  mo = mo->m_next;
	  if (mo) {
	    maxo = M_TRAILINGSPACE(mo);
	  }
	} else {
	  arc4_encrypt(state->arcfour_context,
	      mtod(mo,unsigned char *)+mo->m_len,
	      mtod(mi,unsigned char *)+mi->m_len-maxi,
	      maxi);
	  mo->m_len += maxi;
	  mi = mi->m_next;
	  mo = mo->m_next;
	  if (mi) {
	    maxi = mi->m_len;
	    maxo = M_TRAILINGSPACE(mo);
	  }
	}
      }
    }

    state->stats.unc_bytes += isize;
    state->stats.unc_packets++;
    state->stats.comp_bytes += osize;
    state->stats.comp_packets++;

    return osize;
}

/*
 * Since every frame grows by MPPE_OVHD + 2 bytes, this is always going
 * to look bad ... and the longer the link is up the worse it will get.
 */
static void
mppe_comp_stats(void *arg, struct compstat *stats)
{
    ppp_mppe_state *state = (ppp_mppe_state *) arg;

    *stats = state->stats;
}


static int
mppe_decomp_init(void *arg, unsigned char *options, int optlen, int unit,
		 int hdrlen, int mru, int debug)
{
    /* ARGSUSED */
    return mppe_init(arg, options, optlen, unit, debug, "mppe_decomp_init");
}

/*
 * We received a CCP Reset-Ack.  Just ignore it.
 */
static void
mppe_decomp_reset(void *arg)
{
    /* ARGSUSED */
    return;
}

/*
 * Decompress (decrypt) an MPPE packet.
 */
int
mppe_decompress(void *arg, struct mbuf *mp, struct mbuf **mret)
{
    ppp_mppe_state *state = (ppp_mppe_state *) arg;
    unsigned ccount;
    int flushed;
    int sanity = 0, isize;
    unsigned char *ibuf, *obuf;

    if (!mp) {
	DPRINTF(("ppp%d/mppe: null input packet\n",state->unit));
	return DECOMP_ERROR;
    }

    if (mp->m_len <= PPP_HDRLEN + MPPE_OVHD) {
	if (state->debug)
	    aprint_error("mppe_decompress[%d]: short pkt (%d)\n",
		   state->unit, mp->m_len);
	return DECOMP_ERROR;
    }

    ibuf = mtod(mp,unsigned char *);
    flushed = MPPE_BITS(ibuf) & MPPE_BIT_FLUSHED;

    ccount = MPPE_CCOUNT(ibuf);
    if (state->debug >= 7)
	aprint_error("mppe_decompress[%d]: ccount %d\n", state->unit,
	       ccount);

    /* sanity checks -- terminate with extreme prejudice */
    if (!(MPPE_BITS(ibuf) & MPPE_BIT_ENCRYPTED)) {
	DPRINTF(("mppe_decompress[%d]: ENCRYPTED bit not set!\n",
	       state->unit));
	state->sanity_errors += 100;
	sanity = 1;
    }
    if (!state->stateful && !flushed) {
	DPRINTF(("mppe_decompress[%d]: FLUSHED bit not set in "
	       "stateless mode!\n", state->unit));
	state->sanity_errors += 100;
	sanity = 1;
    }
    if (state->stateful && ((ccount & 0xff) == 0xff) && !flushed) {
	DPRINTF(("mppe_decompress[%d]: FLUSHED bit not set on "
	       "flag packet!\n", state->unit));
	state->sanity_errors += 100;
	sanity = 1;
    }

    if (sanity) {
	if (state->sanity_errors < SANITY_MAX)
	    return DECOMP_ERROR;
	else
	    /*
	     * Take LCP down if the peer is sending too many bogons.
	     * We don't want to do this for a single or just a few
	     * instances since it could just be due to packet corruption.
	     */
	    return DECOMP_FATALERROR;
    }

    /*
     * Check the coherency count.
     */

    if (!state->stateful) {
	/* RFC 3078, sec 8.1.  Rekey for every packet. */
	while (state->ccount != ccount) {
	    mppe_rekey(state, 0);
	    state->ccount = (state->ccount + 1) % MPPE_CCOUNT_SPACE;
	}
    } else {
	/* RFC 3078, sec 8.2. */
	if (!state->discard) {
	    /* normal state */
	    state->ccount = (state->ccount + 1) % MPPE_CCOUNT_SPACE;
	    if (ccount != state->ccount) {
		/*
		 * (ccount > state->ccount)
		 * Packet loss detected, enter the discard state.
		 * Signal the peer to rekey (by sending a CCP Reset-Request).
		 */
		state->discard = 1;
		return DECOMP_ERROR;
	    }
	} else {
	    /* discard state */
	   if (!flushed) {
		/* ccp.c will be silent (no additional CCP Reset-Requests). */
		return DECOMP_ERROR;
	    } else {
		/* Rekey for every missed "flag" packet. */
		while ((ccount & ~0xff) != (state->ccount & ~0xff)) {
		    mppe_rekey(state, 0);
		    state->ccount = (state->ccount + 256) % MPPE_CCOUNT_SPACE;
		}

		/* reset */
		state->discard = 0;
		state->ccount = ccount;
		/*
		 * Another problem with RFC 3078 here.  It implies that the
		 * peer need not send a Reset-Ack packet.  But RFC 1962
		 * requires it.  Hopefully, M$ does send a Reset-Ack; even
		 * though it isn't required for MPPE synchronization, it is
		 * required to reset CCP state.
		 */
	    }
	}
	if (flushed)
	    mppe_rekey(state, 0);
    }

    /* Allocate an mbuf chain to hold the decrypted packet */
    {
	struct mbuf *mfirst = 0;
	struct mbuf *mprev;
	struct mbuf *m = 0;
	int bleft;
	isize = 0;
	for (m=mp; m; m= m->m_next) isize += m->m_len;
	bleft = isize-MPPE_OVHD;
	do {
	    mprev = m;
	    MGET(m,M_DONTWAIT, MT_DATA);
	    if (m == NULL) {
		m_freem(mfirst);
#ifdef DEBUG
		aprint_error("ppp%d/mppe: unable to allocate mbuf to decrypt packet\n",
		    state->unit);
#endif
		return DECOMP_ERROR;
	    }
	    m->m_len = 0;
	    if (mfirst == NULL) {
		mfirst=m;
		m_copy_pkthdr(m,mp);
		if (bleft > MHLEN) {
		    MCLGET(m, M_DONTWAIT);
		}
	    } else {
		mprev->m_next = m;
		if (bleft > MLEN) {
		    MCLGET(m, M_DONTWAIT);
		}
	    }
	    bleft -= M_TRAILINGSPACE(m);
	} while (bleft > 0);
	*mret = mfirst;
    }

    obuf = mtod(*mret, unsigned char *);

    /*
     * Fill in the first part of the PPP header.  The protocol field
     * comes from the decrypted data.
     */
    obuf[0] = PPP_ADDRESS(ibuf);	/* +1 */
    obuf[1] = PPP_CONTROL(ibuf);	/* +1 */
    obuf  += 2;
    (*mret)->m_len += 2;
    ibuf  += PPP_HDRLEN + MPPE_OVHD;
    isize -= PPP_HDRLEN + MPPE_OVHD;	/* -6 */
					/* net osize: isize-4 */

#ifdef notyet
    /*
     * Decrypt the first byte in order to check if it is
     * a compressed or uncompressed protocol field.
     */
    arc4_decrypt(state->arcfour_context, obuf, ibuf, 1);

    /*
     * Do PFC decompression.
     * This would be nicer if we were given the actual sk_buff
     * instead of a char *.
     */
    if ((obuf[0] & 0x01) != 0) {
	obuf[1] = obuf[0];
	obuf[0] = 0;
	obuf++;
    }
#endif

    /* And finally, decrypt the rest of the packet. */
	/* March down input and output mbuf chains, decoding with RC4 */
	{
	    struct mbuf *mi = mp;	/* mbuf in */
	    struct mbuf *mo = *mret;	/* mbuf out */
	    int maxi, maxo;
	    maxi = mi->m_len-6;	/* adjust for PPP_HDRLEN and MPPE_OVERHEAD */
	    maxo = M_TRAILINGSPACE(mo);
	    while (mi) {
		if (maxi < maxo) {
		    arc4_encrypt(state->arcfour_context,
			mtod(mo,unsigned char *)+mo->m_len,
			mtod(mi,unsigned char *)+mi->m_len-maxi,
			maxi);
		    mo->m_len += maxi;
		    maxo -= maxi;
		    mi = mi->m_next;
		    if (mi) {
			maxi = mi->m_len;
		    }
		} else if (maxi > maxo) {
		    arc4_encrypt(state->arcfour_context,
			mtod(mo,unsigned char *)+mo->m_len,
			mtod(mi,unsigned char *)+mi->m_len-maxi,
			maxo);
		    mo->m_len += maxo;
		    maxi -= maxo;
		    mo = mo->m_next;
		    if (mo) {
			maxo = M_TRAILINGSPACE(mo);
		    }
		} else {
		    arc4_encrypt(state->arcfour_context,
			mtod(mo,unsigned char *)+mo->m_len,
			mtod(mi,unsigned char *)+mi->m_len-maxi,
			maxi);
		    mo->m_len += maxi;
		    mi = mi->m_next;
		    mo = mo->m_next;
		    if (mi) {
			maxi = mi->m_len;
			maxo = M_TRAILINGSPACE(mo);
		    }
		}
	    }
	}
    state->stats.unc_bytes += (*mret)->m_len;
    state->stats.unc_packets++;
    state->stats.comp_bytes += isize;
    state->stats.comp_packets++;

    /* good packet credit */
    state->sanity_errors >>= 1;

    return DECOMP_OK;
}

/*
 * Incompressible data has arrived (this should never happen!).
 * We should probably drop the link if the protocol is in the range
 * of what should be encrypted.  At the least, we should drop this
 * packet.  (How to do this?)
 */
static void
mppe_incomp(void *arg, struct mbuf *mp)
{
    ppp_mppe_state *state = (ppp_mppe_state *) arg;
    struct mbuf *m;

    for (m=mp;m;m = m->m_next) {
      (state->stats).inc_bytes += m->m_len;
      (state->stats).unc_bytes += m->m_len;
    }
    (state->stats).inc_packets++;
    (state->stats).unc_packets++;
}

/*************************************************************
 * Module interface table
 *************************************************************/

/*
 * Procedures exported to if_ppp.c.
 */
static struct compressor ppp_mppe = {
    .compress_proto =	CI_MPPE,		/* compress_proto */
    .comp_alloc =	mppe_alloc,		/* comp_alloc */
    .comp_free =	mppe_free,		/* comp_free */
    .comp_init =	mppe_comp_init,		/* comp_init */
    .comp_reset =	mppe_comp_reset,	/* comp_reset */
    .compress =		mppe_compress,		/* compress */
    .comp_stat =	mppe_comp_stats,	/* comp_stat */
    .decomp_alloc =	mppe_alloc,		/* decomp_alloc */
    .decomp_free =	mppe_free,		/* decomp_free */
    .decomp_init =	mppe_decomp_init,	/* decomp_init */
    .decomp_reset =	mppe_decomp_reset,	/* decomp_reset */
    .decompress =	mppe_decompress,	/* decompress */
    .incomp =		mppe_incomp,		/* incomp */
    .decomp_stat =	mppe_comp_stats,	/* decomp_stat */
};

MODULE(MODULE_CLASS_MISC, mppe, "if_ppp");

static int
mppe_modcmd(modcmd_t cmd, void *arg)
{
	switch (cmd) {
	case MODULE_CMD_INIT:
		return ppp_register_compressor(&ppp_mppe, 1);
	case MODULE_CMD_FINI:
		return ppp_unregister_compressor(&ppp_mppe, 1);
	case MODULE_CMD_STAT:
		return 0;
	default:
		return ENOTTY;
	}

	return ENOTTY;
}
