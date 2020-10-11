.include "../Makefile.inc"

#S?=    /usr/src/sys
KMOD=	mppe
SRCS=	ppp_mppe_compress.c arc4.c

.include <bsd.kmodule.mk>
