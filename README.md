NetBSD kernel module to add MPPE compression support to version 9 kernel

tested with NetBSD 9.99.72 and 9.99.77

Makefile works in usr/src/sys/modules/examples/mppe 

Files:

 ppp_mppe_compress.c.orig : Extracted from kernel_ppp_mppe-0.0.4-src.tgz for Linux 2.x kernels
 
 patch-aa : Distributed as a part of /usr/pkgsrc/net/mppe-lkm for NetBSD 5.1
 
ppp_mppe_compress.c.orig + patch-aa made the basis for the current ppp_mppe_compress.c
