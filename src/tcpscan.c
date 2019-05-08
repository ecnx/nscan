/* ------------------------------------------------------------------
 * N Scan - Reply IP/TCP Packets Scanner
 * ------------------------------------------------------------------ */

#include "nscan.h"

/**
 * \brief               Packets scanner task entry point
 *
 * \param args          Arguments passed to task
 *
 * \return              NULL
 */

void *scanner_entry_point ( void *args )
{
    if ( scanner_task ( ( struct scanner_ctx * ) args ) < 0 )
    {
        exit ( 1 );
    }

    return NULL;
}

/**
 * \brief               Format IPv4 address plus new line to string
 *
 * \param in            Socket address
 * \param buffer        String buffer
 * \param size          String buffer size
 *
 * \return              On success 0, otherwise negative value
 */

static void format_peer ( struct in_addr in, char *buffer, size_t size )
{
    snprintf ( buffer, size, "%d.%d.%d.%d\n",
        ( ( unsigned char * ) &in )[0],
        ( ( unsigned char * ) &in )[1],
        ( ( unsigned char * ) &in )[2], ( ( unsigned char * ) &in )[3] );
}

/**
 * \brief               Log peer if packet matches pattern
 *
 * \param sctx          Scanner context
 * \param buffer        Packet data buffer
 * \param len           Packet data length
 *
 */

static void analyse_packet ( struct scanner_ctx *sctx, const unsigned char *buffer, size_t len )
{
    unsigned short iphdrlen = 0;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct sockaddr_in saddr;
    char message[64];

    /* Calculate packet segments offsets */
    iph = ( struct iphdr * ) buffer;
    iphdrlen = iph->ihl * 4;
    if ( iphdrlen > len )
    {
        return;
    }
    tcph = ( struct tcphdr * ) ( buffer + iphdrlen );
    saddr.sin_addr.s_addr = iph->saddr;

    /* Log peer if packet is SYN, ACK and tcp port number are matched */
    if ( tcph->syn && tcph->ack && tcph->source == htons ( sctx->dest_port )
        && tcph->dest == htons ( sctx->src_port ) )
    {
        /* Format message and log to file */
        format_peer ( saddr.sin_addr, message, sizeof ( message ) );
        write ( sctx->listfd, message, strlen ( message ) );

        /* Increment ACKs counters */
        sctx->nack++;
        sctx->recv_tot++;
    }
}

/**
 * \brief               Packets scanner task
 *
 * \param sctx          Scanner context
 *
 * \return              On success 0, otherwise -1
 */

int scanner_task ( struct scanner_ctx *sctx )
{
    int sock;
    ssize_t len;
    unsigned char buffer[65536];

    /* Allocate raw socket */
    if ( ( sock = socket ( AF_INET, SOCK_RAW, IPPROTO_TCP ) ) < 0 )
    {
        perror ( "socket" );
        return -1;
    }

    /* Receive and analyse incoming packets */
    while ( !sctx->exit_flag )
    {
        /* Receive packet from raw socket */
        if ( ( len = recv ( sock, buffer, sizeof ( buffer ), 0 ) ) < 0 )
        {
            perror ( "recv" );
            close ( sock );
            return -1;
        }

        /* Analyze received packet */
        analyse_packet ( sctx, buffer, len );
    }

    /* Close raw socket */
    close ( sock );
    return 0;
}
