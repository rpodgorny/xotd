/*
 * xotd.c	This file contains an implementation of RFC1613 XOT
 *		(X.25 over TCP/IP), using x25tap Linux module.
 *
 * Version:	xotd.c 0.04 (1999-01-08)
 *
 * Author:	Stephane Fillod, <sfillod@charybde.gyptis.frmug.org>
 *
 *		This program is free software; you can redistribute it
 *		and/or  modify it under  the terms of  the GNU General
 *		Public  License as  published  by  the  Free  Software
 *		Foundation;  either  version 2 of the License, or  (at
 *		your option) any later version.
 *
 * 		This program is distributed in the hope that it will be useful,
 * 		but WITHOUT ANY WARRANTY; without even the implied warranty of
 *		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *		GNU General Public License for more details.
 *
 * Modifications:
 *
 * 10/2002 by JH:
 *
 *	Fix this up so we can talk to multiple remote xot devices
 *
 *	Tell X.25 if TCP call clears
 *
 *	Don't try to use same TCP call for multiple X.25 calls,
 *		leads to horrid clearing windows.
 *
 *	Make outbound calls in thread, to avoid blocking everyone
 *
 *  08/2006 by Shaun Pereira
 *  	Fix to run multiple tap devices on Linux host
 *
 */

#include <pthread.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/types.h>
#include <linux/types.h>	/* don't move this one ! */
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <syslog.h>
#include <netdb.h>
#include <fcntl.h>
#include <termio.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <ctype.h>

#include <linux/netlink.h>

/* see include/linux/netlink.h*/
#define NETLINK_TAPBASE 17

#define XOT_PORT 1998
#define XOT_VERSION 0

#define MAX_PKT_LEN 1030	/* 1024 bytes of data + PLP header */
#define MIN_PKT_LEN 3

#define CALL_REQUEST			0x0B
#define CALL_ACCEPT			0x0F
#define CLEAR_REQUEST			0x13
#define CLEAR_CONFIRMATION		0x17
#define RESTART_REQUEST			0xFB
#define RESTART_CONFIRMATION		0xFF

#define RR(pr)		  		(0x01 + (pr << 5))
#define RNR(pr)				(0x05 + (pr << 5))
#define REJ(pr)				(0x09 + (pr << 5))


/* #define KEEPLCI0 (NOT IMPLEMENTED) */

#define DEBUG 1
#define FROM_TAP 1
#define TO_TAP 2
/*
 * The famous xot header
 *
 */

struct xot_header {
        u_int16_t version;
        u_int16_t length;
};


/*
 * Information kept for each xot connection:
 *
 */

struct xot {
	int sock;			/* socket connected to remote */
	int cleared;			/* True if we've sent CLR REQ */
	struct xot_device *device;	/* backpointer to device */
	int lci;
	pthread_t thread;		/* inbound thread id */
	pthread_mutex_t lock;
	int busy;
	int closing;
	
	struct xot_header head;		/* Should be contig */
	unsigned char call [256];
};


/*
 * Information for each remote xot device we know
 *
 */

struct xot_device {
	int max_addr;		/* Number of addresses for this one */
	struct sockaddr *addr;
	int tap;		/* The x25tap device it talks to. */
	int max_xot;		/* The biggest LCI it can use */
	struct xot **xot;	/* Table of virtual circuits */
	pthread_t thread;	/* Outbound thread id */
	pthread_mutex_t lock;
};

int max_device;

pthread_cond_t wait_for_idle;

struct xot_device *device;

int isVerbose = 0;

int lport = XOT_PORT;
int rport = XOT_PORT;


void usage();

void daemon_start(void);
void printd (const char *format, ...);
void print_x25 (const char *head, const unsigned char *buf, int len);
void dump_packet(const unsigned char* pkt, int len,int direction);

static int  writen(int fd, unsigned char *ptr, int nbytes);
static int  readn(int fd, unsigned char *ptr, int nbytes);

struct xot *find_xot_for_call (int fd, struct sockaddr_in *addr);

int create_outbound (struct xot_device *dev);
void create_inbound (struct xot *xot);

void *outbound(void*);
void *inbound(void*);

void read_config (char *name);
void config_device (char *device_name, char *remote, char *circuits);


static char *addr (struct sockaddr *sa) {

	switch (sa->sa_family) {
	    case AF_INET:
		return inet_ntoa (((struct sockaddr_in *)sa)->sin_addr);
	    default:
		return "unknown address family";
	}
}

	

/* xot must be locked before use */
   
static void busy_xot (struct xot *xot) {
	++xot->busy;
	printd ("busy (%d)", xot->busy);
}
	

/* xot MUST NOT be locked before use; asymetry rules */

void idle_xot (struct xot *xot) {

	pthread_mutex_lock (&xot->lock);

	printd ("idle (busy = %d, closing = %d)", xot->busy, xot->closing);
	
	if (!--xot->busy && xot->closing) {
		pthread_cond_broadcast (&wait_for_idle);
	}

	pthread_mutex_unlock (&xot->lock);
}
    


static inline int get_lci(const unsigned char *packet)
{
	return (packet[0] & 0x0F) * 256 + packet[1];
}

static int unit_of_devname(const char *devname)
{
	int len;

	if (!devname || !*devname)
		return -1;
	len = strlen(devname);
	while (len>0 && isdigit(devname[len-1]))
		len--;
	return atoi(devname+len);
}

int main(int argc, char *argv[])
{
    int    sock;
    struct sockaddr_in addr;

    int    on = 1;
    char   c;
    char   *bindto = NULL;
    int    errflg=0;
    int    unit=0;
    int    bindtointerface=0;

    char   *config = NULL;
    
    struct xot_device *dev;

    while ((c = getopt(argc, argv, "l:r:b:vf:h")) != -1)
        switch (c) {
        case 'v':
            if(isVerbose)
                errflg++;
            else
                isVerbose++;
            break;
        case 'r':
            rport = atoi(optarg);
            break;
        case 'l':
            lport = atoi(optarg);
            break;
        case 'b':
            bindto = optarg;
            bindtointerface++;
            break;
        case 'h':
            errflg++;
            break;
        case 'f':
            config = optarg;
            break;
        default:
            errflg++;
	}

#ifdef DEBUG
	isVerbose++;
	setvbuf (stderr, NULL, _IOLBF, BUFSIZ);
#endif

    if (config) {
	    if (argc > optind)
		    ++errflg;
	    else
		    read_config (config);
    }
    else {
	    if (argc - optind  < 2 || argc - optind > 3)
		    ++errflg;
	    else
		    config_device (argv[optind], argv[optind+1],
				   argc - optind > 2 ? argv[optind+2] : NULL);
    }

    if (errflg || max_device == 0) {
	    usage ();
	    return 1;
    }
	    

#ifndef DEBUG
    /* Let's become a daemon */
    daemon_start(); 

    openlog("xotd", LOG_PID /*|LOG_NOWAIT*/, LOG_DAEMON);
#endif

    pthread_cond_init (&wait_for_idle, NULL);
    
    /* Make socket for incoming XOT calls */

    if ((sock = socket (AF_INET, SOCK_STREAM, 0)) == -1) {
	printd ("Error creating socket: %s",strerror(errno));
	return 2;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR/*|SO_DEBUG*/, &on, sizeof on);

    memset(&addr, 0, sizeof addr);
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons (lport);

    if (bindtointerface) {
	if(inet_aton(bindto,&addr.sin_addr) == 0) {
	    printd("Error with bind address");
            return 2;
        }
    } else {
    	addr.sin_addr.s_addr = htonl (INADDR_ANY);
    }
    
    if (bind (sock, (struct sockaddr *) &addr, sizeof addr) == -1) {
	    printd ("Error binding socket: %s", strerror(errno));
	    close (sock);
	    return 2;
    }
    
    if (listen (sock, 8) == -1) {
	printd ("Error listening socket: %s", strerror (errno));
	close (sock);
	return 2;
    }

    /* Start all the outbound threads, copy x.25 -> tcp */
    
    unit = 0;
    
    for (dev = device; dev < device + max_device; ++dev) {
	    if (create_outbound (dev)) ++unit;
    }

    if (!unit) return 2;
    
#ifdef DEBUG
    printd ("Waiting for connections.");
#endif
    
    for (;;) {
        socklen_t len = sizeof addr;
        int fd;
        struct xot *xot;
	
        if ((fd = accept (sock, (struct sockaddr *) &addr, &len)) == -1) {
            printd ("accept error: %s", strerror(errno));
            exit (1);
        }

        if (!(xot = find_xot_for_call (fd, &addr))) {
            close (fd);
            continue;
        }

        create_inbound (xot);
    }
 
    return 0;
}

void usage()
{
	fprintf(stderr,
		"\n"
		"Usage:\txotd [-v] device_name remote_name [ circuits ]\n"
		"or:\txotd [-v] -f config-file\n"
		"\n"
		"Config file format:\n"
		"\n"
		"device-name remote name [ circuits]\n"
		"\n");
}



/*
 * Create a new outbound thread, copy x.25 -> tcp
 *
 */

int create_outbound (struct xot_device *dev) {

	int unit;
	struct sockaddr_nl addr;
	int e;
	
	unit = dev->tap + NETLINK_TAPBASE;
	
	if ((dev->tap = socket (AF_NETLINK, SOCK_RAW, unit)) == -1) {
		printd ("Error creating netlink socket: %s" ,
			 strerror(errno));
		return 0;
	}

	memset(&addr, 0, sizeof addr);
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = 1; 

	if (bind (dev->tap, (struct sockaddr *) &addr,sizeof addr) == -1) {
		printd ("Error binding netlink socket: %s",
			strerror(errno));
		close (dev->tap);
		return 0;
	}

	pthread_mutex_init (&dev->lock, NULL);

	if ((e = pthread_create (&dev->thread, NULL, outbound, dev))) {
		printd ("pthread_create (outbound): %s", strerror (e));
		close (dev->tap);
		return 0;
	}

	return 1;
}



/*
 * Create a inbound thread for a xot connection
 *
 * ... fix, should cope with failure.
 *
 */

void create_inbound (struct xot *xot) {

	int e;
	
	pthread_attr_t attr;
	
	pthread_attr_init (&attr);
	pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);

	if ((e = pthread_create (&xot->thread, &attr, inbound, xot))) {
		printd ("pthread_create (inbound): %s", strerror (e));
		/* clean up ... */
		return;
	}
	
	pthread_attr_destroy(&attr);
}



/*
 * Find a xot to handle an incoming call
 *
 */

struct xot *find_xot_for_call (int fd, struct sockaddr_in *addr) {
	struct xot_device *dev;
	struct xot *xot;
	int lci;

	/* First find the device */

	for (dev = device; dev < device + max_device; ++dev) {
		struct sockaddr *a;

		for (a = dev->addr; a < dev->addr + dev->max_addr; ++a) {
			if (((struct sockaddr_in *)a)->sin_addr.s_addr == addr->sin_addr.s_addr)
				goto found_device;
		}
	}

	printd ("call from unknown address %s", inet_ntoa (addr->sin_addr));

	return NULL;

found_device:

	/* Now look for a free lci.  Count down like a DCE */

	/* Fixme - doesn't allow LCI0 */

	pthread_mutex_lock (&dev->lock);
	
	for (lci = dev->max_xot - 1; lci; --lci) {
		if (!dev->xot [lci]) goto found_lci;
	}

	pthread_mutex_unlock (&dev->lock);
	
	printd ("Too many vc's from %s", inet_ntoa (addr->sin_addr));

	return NULL;

found_lci:

	xot = calloc (sizeof *xot, 1);

	xot->device = dev;

	xot->sock = fd;
	xot->lci = lci;

	pthread_mutex_init (&xot->lock, NULL);

	dev->xot [lci] = xot;

	pthread_mutex_unlock (&dev->lock);
	
	return xot;
}



/*
 * Find the xot connection for an outbound packet
 *
 */

struct xot *find_xot_for_packet (struct xot_device *dev,
				 unsigned char *packet,
				 int len)
{

	struct xot *xot;
	unsigned char *tap_packet = packet - 1;
	
	int lci = get_lci (packet);

	printd("find_xot_for_packet");	

	if (lci == 0) {		/* ignore this one, see 6.4 in RFC */
		if (packet[2] == RESTART_REQUEST) {
			packet [2] = RESTART_CONFIRMATION;
			write (dev->tap, packet - 1, 1 + 3);
			dump_packet(packet,4,TO_TAP);
		}
#ifdef DEBUG
		printd("Drop packet, lci=0");
#endif
		return NULL;
	}

	if (lci >= dev->max_xot) {
		printd ("Bad lci %d - max %d", lci, dev->max_xot);
		goto force_clear;
	}

	pthread_mutex_lock (&dev->lock);
		
	if (!(xot = dev->xot [lci])) {

		/* Not connected */

		switch (packet [2]) {
		    case CLEAR_CONFIRMATION:
			/* discard the message */

			pthread_mutex_unlock (&dev->lock);
			
			return NULL;

		    default:

			pthread_mutex_unlock (&dev->lock);

			printd ("no connection and packet not CALL");

			goto force_clear;

		    case CALL_REQUEST:
			break;	
			/* All is good, make the call */
		}

		xot = dev->xot [lci] = calloc (sizeof *xot, 1);

		xot->device = dev;

		xot->sock = -1;
		xot->lci = lci;

		pthread_mutex_init (&xot->lock, NULL);
		
		pthread_mutex_unlock (&dev->lock);

		/* Save call packet 'till connected to remote */

		xot->head.length = htons (len);
		xot->head.version = htons (XOT_VERSION);
		
		memcpy (xot->call, packet, len);

		/* Create thread for TCP->X.25, it'll make the call */
		
		create_inbound (xot);

		return NULL;	/* send call after connected */
	}

	/* DANGER - locked device, then xot - always in that order! */
	
	pthread_mutex_lock (&xot->lock);

	pthread_mutex_unlock (&dev->lock);

	if (xot->sock == -1) {
		/* Not yet connected, only legal thing is CLEAR REQUEST */

		xot->cleared = packet [2];

		pthread_mutex_unlock (&xot->lock);
		
		return NULL;
	}

	if (xot->closing) {

		/* It's being closed */

		pthread_mutex_unlock (&xot->lock);
		
		return NULL;
	}

	busy_xot (xot);
		
	pthread_mutex_unlock (&xot->lock);
			
	if (packet [2] == CALL_REQUEST) {
		printd ("call request on active channel");
		idle_xot (xot);
		goto force_clear;
	}
		
	xot->cleared = packet [2];

	/* Copy GFI, LCI from call packet */
	packet [0] = (packet [0] & 0xa0) | (xot->call [0] & 0x3f); 
	packet [1] = xot->call [1];

	return xot;

force_clear:

	printd ("fake clear");
			
	packet[2] = CLEAR_REQUEST;
	packet[3] = 0x05;
	packet[4] = 0;
	
	write (dev->tap, tap_packet, 1 + 5);
	dump_packet(tap_packet,6,TO_TAP);
		
	return NULL;
}



/*
 * The outbound thread, read from Linux X.25 and send out
 * to remote xot devices over TCP
 *
 * One thread per local xot device
 *
 */

void *outbound(void *arg)
{
    struct xot_device *dev = arg;
	
    int nread;

    /* Many ways of addressing same data.  UGERLY */
    
    unsigned char full_packet [sizeof (struct xot_header) + MAX_PKT_LEN];
    struct xot_header *header = (struct xot_header *) full_packet;
    unsigned char *packet = full_packet + sizeof *header;
    unsigned char *tap_packet = packet - 1;
    
    for (;;) {

	struct xot *xot;

	nread = read (dev->tap, tap_packet, MAX_PKT_LEN + 1);

	dump_packet(tap_packet,nread,FROM_TAP);	

	if (nread < 0) {
		printd("read error: %s", strerror(errno));
		break;
	}
	
	if (nread == 0)		/* strange, ignore it!? */
		continue;

	--nread;	/* Ignore NETLINK byte */
	
	switch (*tap_packet) {
	    case 0x00:  			/* data request */
		if (nread < MIN_PKT_LEN)	/* invalid packet size ? */
			break;

#ifdef DEBUG
		print_x25 ("Tap->TCP", packet, nread);
#endif

		if (!(xot = find_xot_for_packet (dev, packet, nread)))
			break;

		printd ("forward to TCP");
		
		header->version = htons (XOT_VERSION);
		header->length = htons (nread);

		nread += sizeof header;

		/* Don't care if write fails, read should fail too
		   and that'll tell X.25 for us */
		
		writen (xot->sock, (unsigned char *) header, nread);
	
		if (packet [2]  == CLEAR_CONFIRMATION) {
			/* After this packet this vc is available for use */

			printd ("outbound done with xot %p", xot);

			/* This should kill the inbound side */
			
			shutdown (xot->sock, SHUT_RDWR);

			/* We should not send on this xot */

			pthread_mutex_lock (&dev->lock);

			if (dev->xot [xot->lci] == xot) {
				dev->xot [xot->lci] = NULL;
			}
			else {
				printd ("already zapped (in)");
			}

			pthread_mutex_unlock (&dev->lock);

		}

		idle_xot (xot);

		break;

	    case 0x01: /* Connection request, send back ACK */
#ifdef DEBUG
		printd("Tap->TCP: [conn.req], %d data bytes", nread);
#endif

		*tap_packet = 0x01;

		if (write(dev->tap, tap_packet, 1) != 1) {
			printd("write error: %s",strerror(errno));
			return NULL;
		}
		dump_packet(tap_packet,1,TO_TAP);
	        break;

	    case 0x02: /* Disconnect request */
#ifdef DEBUG
		printd("Tap->TCP: [clr.req], %d data bytes", nread);
#endif
		*tap_packet = 0x02;
		if (write(dev->tap, tap_packet, 1) != 1) {
		    printd("write error: %s",strerror(errno));
		    return NULL;
		}
		dump_packet(tap_packet,1,TO_TAP);
	        break;
		
	    case 0x03: 
#ifdef DEBUG
		printd("Tap->TCP: [param], %d data bytes", nread);
#endif
	        printd("changing parameters not supported");
	        break;
		
	    default:
	        printd("read from tap: unknown command %#x",*tap_packet);
		break;
	}
    }

    if (isVerbose)
        printd("exiting Tap outbound!");

    close (dev->tap);

    return NULL;
}


/*
 * Send data from TCP to X.25
 *
 * One thread per active X.25 connection.
 *
 */

void *inbound(void *arg)
{
    struct xot *xot = arg;
    struct xot_device *dev = xot->device;

    int nread, len;

    struct xot_header header;
    unsigned char tap_packet [MAX_PKT_LEN + 1];
    unsigned char *packet = tap_packet + 1;
    
    if (isVerbose)
	printd("lci=%d New TCP connection (tap inbound).", xot->lci);

    if (xot->sock == -1) {

	    int sock;
	    struct sockaddr *a;
	    
	    /* It's up to us to make the call */
		
	    for (a = dev->addr; a < dev->addr + dev->max_addr; ++a) {
		    sock = socket (a->sa_family, SOCK_STREAM, 0);
		    if (sock == -1) {
			    printd ("socket: %s", strerror (errno));
			    goto clear;
		    }
		    
		    if (connect (sock, a, sizeof *a) == 0) goto ok;
		    
		    printd ("%s: %s", addr (a), strerror (errno));
		    close (sock);
	    }

	    /* all call attempts failed; tell X.25 */
	    
	    goto clear;

ok:
	    pthread_mutex_lock (&xot->lock);

	    printd ("connected to %s", addr (a));
	    
	    if (xot->cleared == CLEAR_REQUEST) {
		    /* but X.25 has decided to give up. */

		    pthread_mutex_unlock (&xot->lock);
		    
		    goto clear;
	    }

	    xot->sock = sock;

	    pthread_mutex_unlock (&xot->lock);

	    /* OK, send out the call packet */

	    len = ntohs (xot->head.length) + sizeof xot->head;

	    printd ("write %d bytes call request", len);

	    printd ("gfi=%02x lcn=%02x pti=%02x",
		    xot->call[0], xot->call[1], xot->call[2]);
	    
	    len = writen (xot->sock, (unsigned char *) &xot->head, len);

	    if (len < 0)
		    printd("readn error: %s", strerror(errno));
		    
    }
		    
    *tap_packet = 0x00;	/* Data.ind */

    do {

	nread = readn (xot->sock, (unsigned char*) &header, sizeof header);
	if (nread != sizeof header) {
		if (nread < 0 && ( errno != EPIPE || errno != ENOTCONN))
			printd("readn error: %s", strerror(errno));
		break;	/* abort */
	}

	len = ntohs (header.length);

	if (ntohs (header.version) != XOT_VERSION) {
		printd("XOT version not supported: %d", ntohs(header.version));
		break;	/* and close the connexion */
	}

	if (len == 0) {
#ifdef DEBUG
		printd("Zero length packet received!");
#endif
		continue;	/* discard it */
	}

	/*
	 * TODO: replace MAX_PKT_LEN by the X.25 device MTU (packet size)
	 */
	
	if (len > MAX_PKT_LEN || len < MIN_PKT_LEN) {
		printd("Invalid packet size: %d", len);
		break;	/* and close the connexion */
	}

	nread = readn (xot->sock, packet, len);	/* read the remainder */
	if (nread != len)
		if (nread < 0) {
			printd("readn error: %s",strerror(errno));
		break;
	}

#ifdef DEBUG
	print_x25 ("TCP->Tap", packet, len);
#endif

	switch (packet[2]) {

	    case CLEAR_CONFIRMATION:
		
		pthread_mutex_lock (&dev->lock);

		if (dev->xot [xot->lci] == xot) {
			dev->xot[xot->lci] = NULL;
		}

		pthread_mutex_unlock (&dev->lock);
		
		xot->cleared = CLEAR_CONFIRMATION;
		break;

	    case CALL_REQUEST:

		/* Should check he doesn't send 2 calls */

		if ((xot->head.length = len) > sizeof xot->call) {
			xot->head.length = sizeof xot->call;
		}
		
		memcpy (xot->call, packet, xot->head.length);
	}

	/* Check gfi, lci of packet */
	
	if ((packet [0] & 0x3f) != (xot->call[0] & 0x3f) ||
	    packet [1] != xot->call [1])
	{
		printd ("Bad GFI/LCN %02x, %02x", packet [0], packet [1]);
		break;
	}
	
	/* Fix LCI to be what we want */

	packet [0] = (packet [0] & 0xf0) + xot->lci / 256;
	packet [1] = xot->lci;
	
	if (write (dev->tap, tap_packet, nread + 1) != nread + 1) {
		printd("Tap write error: %s",strerror(errno));
		break;
	}
	dump_packet(tap_packet, nread +1,TO_TAP);

	/* If we get a clear confirm from remote then we can hang up */
	
    }
    while (xot->cleared != CLEAR_CONFIRMATION);

clear:
    if (isVerbose)
	printd("TCP connection closed (tap inbound), lci=%d.", xot->lci);

    switch (xot->cleared) {
	case CLEAR_CONFIRMATION:
	    /* Nothing to send to X.25 */
	    break;
	case CLEAR_REQUEST:
	    printd ("send clear confirmation to x.25");
	    packet [2] = CLEAR_CONFIRMATION;
	    len = 3;
	    goto send;
	    
	default:
	    printd ("send clear request to x.25");
	    packet [2] = CLEAR_REQUEST;
	    packet [3] = 0;
	    packet [4] = 0;
	    len = 5;

send:
	    packet [0] = 0x10 + xot->lci / 256;
	    packet [1] = xot->lci;
	    
	    write (xot->device->tap, tap_packet, len + 1);
	    dump_packet(tap_packet, len + 1,TO_TAP);
    }

    /* Wait for outbound side to finish work */
    
    pthread_mutex_lock (&xot->lock);

    ++xot->closing;

    while (xot->busy) {
	    printd ("wait for idle");
	    pthread_cond_wait (&wait_for_idle, &xot->lock);
    }

    pthread_mutex_unlock (&xot->lock);

    pthread_mutex_lock (&dev->lock);

    if (dev->xot [xot->lci] == xot) {
	    dev->xot [xot->lci] = NULL;
    } else {
	    printd ("already zapped (out)");
    }

    pthread_mutex_unlock (&dev->lock);
    
    printd ("idle");

    close (xot->sock);

    pthread_mutex_destroy (&xot->lock);
    
    free (xot);

    printd ("done");
    
    return NULL;
}



/*
 * Write "n" bytes to a descriptor.
 * Use in place of write() when fd is a stream socket.
 */
static int writen(int fd, unsigned char *ptr, int nbytes)
{
	int	nleft, nwritten;

	nleft = nbytes;
	while (nleft > 0) {
		nwritten = write(fd, ptr, nleft);
		if (nwritten <= 0)
			return nwritten;		/* error */
		nleft -= nwritten;
		ptr   += nwritten;
	}
	return nbytes - nleft;
}

/*
 * Read "n" bytes from a descriptor.
 * Use in place of read() when fd is a stream socket.
 */
static int readn(int fd, unsigned char *ptr, int nbytes)
{
	int	nread, nleft;

	if (!ptr)
		return -1;

	nleft = nbytes;
	while (nleft > 0) {
		nread = read(fd, ptr, nleft);
		if (nread <= 0)
			return nread;		/* error */
		nleft -= nread;
		ptr   += nread;
	}
	return nbytes - nleft;
}

/*
 * print debug messages
 *
 */
void printd(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
#ifndef DEBUG
	vsyslog(LOG_INFO,format,ap);
#else
	{
		char buf [BUFSIZ];
		char *p = buf;
		int left = sizeof buf - 1;
		int len;

		len = snprintf (p, left, "xotd[%d]:", (int) getpid ());
		p += len;
		left -= len;

		if ((len = vsnprintf (p, left, format, ap)) < 0) len = left;
		p += len;

		*p++ = '\n';

		write (fileno (stderr), buf, p - buf);
	}
#endif
	va_end(ap);
}

#ifdef DEBUG

/*
 * print a pretty description of X.25 packet
 *
 */

void print_x25 (const char *head, const unsigned char *packet, int len) {
	int gfi = *packet;
	
	int extended = (gfi & 0x30) == 0x20;

	int lci = get_lci (packet);
	int pti = packet [2];
	
	if (!(pti & 1)) {	/* Data packet */
		int ps = pti >> 1, pr, m;
		if (extended) {
			pr = packet[3];
			m = pr & 1;
			pr >>= 1;
		}
		else {
			ps &= 0x7;
			m = pti & 0x10;
			pr = pti >> 5;
		}
		printd ("%s lci=%d DATA (ps=%d, pr=%d%s%s%s)",
			head,
			lci, ps, pr,
			m ? ", M" : "",
			(gfi & 0x80) ? ", Q" : "",
			(gfi & 0x40) ? ". D" : "");
	}
	else switch (pti) {
	    case RR(0):
		if (extended) {
			printd ("%s lci=%d RR (pr=%d)", head,
				lci, packet[3] >> 1);
			break;
		}
	    case RR(1): case RR(2): case RR(3):
	    case RR(4): case RR(5): case RR(6): case RR(7):
		printd ("%s lci=%d RR (pr=%d)", head, lci, pti >> 5);
		break;
	    case RNR(0):
		if (extended) {
			printd ("%s lci=%d RNR(pr=%d)", head,
				lci, packet[3] >> 1);
			break;
		}
	    case RNR(1): case RNR(2): case RNR(3):
	    case RNR(4): case RNR(5): case RNR(6): case RNR(7):
		printd ("%s lci=%d RNR (pr=%d)", head, lci, pti >> 5);
		break;
	    case REJ(0):
		if (extended) {
			printd ("%s lci=%d REJ (pr=%d)", head,
				lci, packet[3] >> 1);
			break;
		}
	    case REJ(1): case REJ(2): case REJ(3):
	    case REJ(4): case REJ(5): case REJ(6): case REJ(7):
		printd ("%s lci=%d REJ (pr=%d)", head, lci, pti >> 5);
		break;
	    case CALL_REQUEST:
		printd ("%s lci=%d CALL REQUEST", head, lci);
		break;
	    case CALL_ACCEPT:
		printd ("%s lci=%d CALL ACCEPT", head, lci);
		break;
	    case CLEAR_REQUEST:
		printd ("%s lci=%d CLEAR REQUEST", head, lci);
		break;
	    case CLEAR_CONFIRMATION:
		printd ("%s lci=%d CLEAR CONFIRMATION", head, lci);
		break;
	    case RESTART_REQUEST:
		printd ("%s lci=%d RESTART REQUEST", head, lci);
		break;
	    case RESTART_CONFIRMATION:
		printd ("%s lci=%d RESTART CONFIRMATION", head, lci);
		break;
	    default:
		printd ("%s lci=%d pti=0x%02x", head, lci, pti);
	}
}
#endif


/*
 * Detach a daemon process from login session context.
 */
void daemon_start(void)
{

	if (fork())
		exit(0);
	chdir("/");
	umask(0);
	close(0);
	close(1);
	close(2);
	open("/", O_RDONLY);
	dup2(0, 1);
	dup2(0, 2);
	setsid();
}


/*
 * Read our configuration file
 *
 */

void read_config (char *name) {

	FILE *f;
	char line [80];

	if (strcmp (name, "-") == 0) {
		f = stdin;
	}
	else if (!(f = fopen (name, "r"))) {
		perror (name);
		exit (1);
	}

	while (fgets (line, sizeof line, f)) {

		char *device_name = strtok (line, " \t\n");
		char *remote_name = strtok (NULL, " \t\n");
		char *circuits = strtok (NULL, " \t\n");

		if (!device_name || *device_name == '#') continue;

		if (!remote_name) {
			fprintf (stderr, "Bad line %s in %s\n",
				 device_name, name);
			continue;
		}

		config_device (device_name, remote_name, circuits);
	}

	if (f != stdin) fclose (f);
}


void config_device (char *device_name, char *remote_name, char *circuits) {

	struct hostent *host;
	int n;

	int unit = unit_of_devname (device_name);
	int vc;

	struct xot_device *dev;
	
	if (unit < 0 || unit > MAX_LINKS - NETLINK_TAPBASE - 1) {
		fprintf (stderr, "Invalid netlink tap unit %s\n",
			 device_name);
		return;
	}

	if (!(host = gethostbyname (remote_name))) {
		fprintf (stderr, "Can't find %s for %s\n",
			 remote_name, device_name);
		return;
	}

	if (!circuits) {
		vc = 256;
	}
	else if (sscanf (circuits, "%d", &vc) != 1 ||
		 vc <= 0 || vc > 4095) {
		fprintf (stderr, "Bad vc's %s for %s\n",
			 circuits, device_name);
		return;
	}

	++max_device;

	device = realloc (device, max_device * sizeof *device);

	dev = &device [max_device - 1];

	dev->tap = unit;

	dev->max_xot = vc;
	dev->xot = calloc (dev->max_xot, sizeof *dev->xot);
    
	for (n = 0; host->h_addr_list[n]; ++n);

	dev->addr = calloc (n, sizeof  *device->addr);
	dev->max_addr = n;

	for (n = 0; n < dev->max_addr; ++n) {
		struct sockaddr_in *addr =
			(struct sockaddr_in *) (&dev->addr[n]);
	    
		addr->sin_family = AF_INET;
		addr->sin_port = htons (rport);
		memcpy (&addr->sin_addr,
			host->h_addr_list[n],
			host->h_length);
	}
}

void dump_packet(const unsigned char* pkt, int len,int direction)
{
	int i;
	if (direction == TO_TAP) {
		printf("TAP Wrote ");
	} else {
		printf("TAP Read  ");
	}
	for(i=0;i<len;i++) {
		printf("%02X ",pkt[i]);
	}	
	printf("\n");
}
