/* ------------------------------------------------------------------
 * N Scan - IP/TCP Packets Forge
 * ------------------------------------------------------------------ */

#include "nscan.h"

/**
 * \brief               Compute Internet checksum
 *
 * \param addr          A pointer to the data
 * \param len           The 32 bits data size
 *
 * \return              Sum a 16 bits checksum
 */

static unsigned short in_cksum ( const unsigned short *addr, int len )
{
    register int sum = 0;
    unsigned short answer = 0;
    register const unsigned short *w = addr;
    register int nleft = len;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while ( nleft > 1 )
    {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if ( nleft == 1 )
    {
        *( unsigned char * ) ( &answer ) = *( unsigned char * ) w;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = ( sum >> 16 ) + ( sum & 0xffff );     /* add hi 16 to low 16 */
    sum += ( sum >> 16 );       /* add carry */
    answer = ~sum;      /* truncate to 16 bits */
    return ( answer );
}

/**
 * \brief               Setup packet forge socket
 *
 * \param sctx          Scanner context
 *
 * \return              On success 0, otherwise -1
 */

int forge_setup ( struct scanner_ctx *sctx )
{
    struct pseudo_tcp p_tcp;
    int yes = 1;

    /* Prepare raw socket address */
    sctx->fsin.sin_family = AF_INET;
    sctx->fsin.sin_port = htons ( sctx->dest_port );

    /* Prepare IP/TCP SYN packet  */
    memset ( &sctx->p, '\0', sizeof ( struct packet ) );

    /* Prepare IP packet header */
    sctx->p.ip.version = 4;
    sctx->p.ip.ihl = IPHSIZE >> 2;
    sctx->p.ip.tos = 0;
    sctx->p.ip.tot_len = htons ( IPHSIZE + TCPHSIZE );
    sctx->p.ip.id = 0;
    sctx->p.ip.frag_off = 0;
    sctx->p.ip.ttl = 64;
    sctx->p.ip.protocol = IPPROTO_TCP;
    sctx->p.ip.check = 0;
    sctx->p.ip.saddr = sctx->src_addr;

    /* Prepare TCP packet header */
    sctx->p.tcp.doff = TCPHSIZE >> 2;
    sctx->p.tcp.urg = 0;
    sctx->p.tcp.ack = 0;
    sctx->p.tcp.psh = 0;
    sctx->p.tcp.rst = 0;
    sctx->p.tcp.syn = 1;
    sctx->p.tcp.fin = 0;
    sctx->p.tcp.window = 0;
    sctx->p.tcp.check = 0;
    sctx->p.tcp.urg_ptr = 0;
    sctx->p.tcp.source = htons ( sctx->src_port );
    sctx->p.tcp.dest = htons ( sctx->dest_port );

    /* Prepare Pseudo-TCP header */
    p_tcp.saddr = sctx->p.ip.saddr;
    p_tcp.daddr = sctx->p.ip.daddr;
    p_tcp.mbz = 0;
    p_tcp.ptcl = IPPROTO_TCP;
    p_tcp.tcpl = htons ( TCPHSIZE );
    memcpy ( &p_tcp.tcp, &sctx->p.tcp, TCPHSIZE );

    /* Compute the tcp checksum */
    sctx->p.tcp.check = in_cksum ( ( unsigned short * ) &p_tcp, sizeof(p_tcp) );

    /* Allocate socket */
    if ( ( sctx->fsock = socket ( PF_INET, SOCK_RAW, IPPROTO_TCP ) ) < 0 )
    {
        perror ( "socket" );
        return -1;
    }

    /* Set raw mode on socket  */
    if ( setsockopt ( sctx->fsock, IPPROTO_IP, IP_HDRINCL, ( char * ) &yes, sizeof ( yes ) ) < 0 )
    {
        perror ( "setsockopt" );
        close ( sctx->fsock );
        return -1;
    }
    
    return 0;
}

/**
 * \brief               Update IP/TCP packet checksum
 *
 * \param checksum      Packet checksum reference
 * \param field         32-bit Field to be updated
 * \param addr          New value to be set
 *
 * \return              On success 0, otherwise -1
 */

static void cksum_update_u32(unsigned short* checksum, unsigned int* field, unsigned int value)
{
  unsigned int sum;
  unsigned int old_value;
  
  old_value = ~ntohl(*field);
  sum = ~ntohs(*checksum) & 0xffff;
  sum += (old_value >> 16) + (old_value & 0xffff);
  sum += (value >> 16) + (value & 0xffff);
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  *checksum = htons(~sum & 0xffff);
  *field = htonl(value);
}

/**
 * \brief               Send IP/TCP SYN packet
 *
 * \param sctx          Scanner context
 * \param addr          Peer remote address
 *
 * \return              On success 0, otherwise -1
 */

static int send_syn ( struct scanner_ctx *sctx, unsigned int addr )
{
    /* Update socket and packet dest address */
    sctx->fsin.sin_addr.s_addr = addr;
    cksum_update_u32(&sctx->p.tcp.check,&sctx->p.ip.daddr, ntohl(addr));
    cksum_update_u32(&sctx->p.tcp.check,&sctx->p.tcp.seq, ntohl(rand (  ) % 65536));
    cksum_update_u32(&sctx->p.tcp.check,&sctx->p.tcp.ack_seq, ntohl(rand (  ) % 65536));

    /* IP packet identifier should be unique */  
    sctx->p.ip.id = rand (  );

    /* Send crafted IP/TCP packet */
    if ( sendto ( sctx->fsock, &sctx->p, IPHSIZE + TCPHSIZE, 0, ( struct sockaddr * ) &sctx->fsin, sizeof ( struct sockaddr_in ) ) < 0 )
    {
        perror ( "sendto" );
        return -1;
    }

    return 0;
}

/**
 * \brief               Packets forge task
 *
 * \param sctx          Scanner context
 * \param addr          First address of block
 * \param size          Block address count
 *
 * \return              On success 0, otherwise -1
 */

int forge_task ( struct scanner_ctx *sctx, unsigned int addr, unsigned int size )
{
    unsigned int nacks;
    unsigned int i;

    /* Show address range length */
    printf ( "* Scanning %u IPs ...\n", size );

    /* Scan each peer within given range */
    for ( i = 0; i < size; i++ )
    {
        /* Show work progress from time to time */
        if ( i + 1 == size || i % 256 == 0 )
        {
            nacks = sctx->nack;
            sctx->nack = 0;
            printf ( "* Progress %u%% (%u/%u), %u ACKs\n",
                    100 * ( i + 1 ) / size, ( i + 1 ), size, nacks );
        }

        /* ACK packets must be grabbed - do not overload network */
        usleep ( 10000 );

        /* Send SYN packet */
        if ( send_syn ( sctx, htonl ( ntohl ( addr ) + i ) ) < 0 )
        {
            return -1;
        }

        /* Inrement sent packets counter */
        sctx->send_tot++;
    }

    return 0;
}
