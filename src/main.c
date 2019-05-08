/* ------------------------------------------------------------------
 * N Scan - Main Source File
 * ------------------------------------------------------------------ */

#include "nscan.h"


/**
 * \brief               Show application usage message
 *
 */

static void show_usage ( void )
{
    printf ( "N Scan - Fast IP/TCP Scanner v1.0.19\n"
        "\n"
        "usage: nscan iface b-ip e-ip port list\n"
        "\n"
        "       iface  source network interface\n"
        "       b-ip   address range begin\n"
        "       e-ip   address range end\n"
        "       port   destination port number\n"
        "       list   responsive peers list\n" "\n" );
}

/**
 * \brief               Format IPv4 address to string
 *
 * \param in            IPv4 address
 * \param buffer        String buffer
 * \param size          String buffer size
 *
 */

void inet_ntoa_s ( unsigned int in, char *buffer, size_t size )
{
    snprintf ( buffer, size, "%d.%d.%d.%d",
        ( ( unsigned char * ) &in )[0],
        ( ( unsigned char * ) &in )[1],
        ( ( unsigned char * ) &in )[2], ( ( unsigned char * ) &in )[3] );
}

/**
 * \brief               Get IP address assigned to interface
 *
 * \param iface         Interface name
 * \param addr          Address result
 *
 * \return              On success 0, otherwise -1
 */

static int get_ip_from_iface ( const char *iface, unsigned int *addr )
{
    int sock;
    struct ifreq req;

    if ( ( sock = socket ( PF_INET, SOCK_DGRAM, 0 ) ) < 0 )
    {
        perror ( "socket" );
        return -1;
    }

    memset ( &req, 0, sizeof ( req ) );
    strncpy ( req.ifr_name, iface, IF_NAMESIZE - 1 );

    if ( ioctl ( sock, SIOCGIFADDR, &req ) < 0 )
    {
        perror ( "ioctl" );
        close ( sock );
        return -1;
    }

    *addr = ( ( struct sockaddr_in * ) &req.ifr_addr )->sin_addr.s_addr;
    close ( sock );
    return 0;
}

/**
 * \brief               Static scanner context
 *
 */

static struct scanner_ctx SCTX;

/**
 * \brief               Program entry point
 *
 * \param argc          Arguments count
 * \param argv          Arguments vector
 *
 * \return              On success 0, otherwise error code
 */

int main ( int argc, char *argv[] )
{
    long scanner_pref;
    unsigned int port_l;
    unsigned int addr_begin;
    unsigned int addr_end;
    char addr_str[32];

    /* Validate arguments count */
    if ( argc != 6 )
    {
        show_usage (  );
        return 1;
    }

    /* Reset scanner context, just to be safe */
    memset ( &SCTX, '\0', sizeof ( SCTX ) );

    /* Setup pseudo-random generator */
    srand ( time ( NULL ) );

    /* Obtain source address from network interface */
    if ( get_ip_from_iface ( argv[1], &SCTX.src_addr ) < 0 )
    {
        return 1;
    }

    /* Show found source address */
    inet_ntoa_s ( SCTX.src_addr, addr_str, sizeof ( addr_str ) );
    printf ( "* Source address is %s\n", addr_str );

    /* Randomize source packets port */
    SCTX.src_port = ( rand (  ) % 16384 ) + 49152;

    /* Parse packets dest port */
    if ( sscanf ( argv[4], "%u", &port_l ) <= 0 )
    {
        show_usage (  );
        return 1;
    }

    /* Assign value to port variable */
    SCTX.dest_port = port_l;

    /* Parse scan begin address */
    if ( inet_pton ( AF_INET, argv[2], &addr_begin ) <= 0 )
    {
        show_usage (  );
        return 1;
    }

    /* Parse scan end address */
    if ( inet_pton ( AF_INET, argv[3], &addr_end ) <= 0 )
    {
        show_usage (  );
        return 1;
    }

    /* End address must be greater or equal to begin address */
    if (ntohl(addr_end) < ntohl(addr_begin))
    {
        show_usage (  );
        return 1;
    }

    /* Setup packet forge socket */
    if ( forge_setup ( &SCTX ) < 0 )
    {
        return 1;
    }

    /* Open list file */
    if ( ( SCTX.listfd = open ( argv[5], O_CREAT | O_TRUNC | O_WRONLY, 0644 ) ) < 0 )
    {
        perror ( argv[5] );
        return 1;
    }

    /* Start scanner task asynchronously */
    if ( pthread_create ( ( pthread_t * ) & scanner_pref, 0, scanner_entry_point, &SCTX ) != 0 )
    {
        perror ( "pthread_create" );
        close ( SCTX.listfd );
        return errno;
    }

    /* Start packet forge task */
    if ( forge_task ( &SCTX, addr_begin, ntohl(addr_end) - ntohl(addr_begin)) < 0 )
    {
        SCTX.exit_flag = 1;
        close ( SCTX.listfd );
        return errno;
    }

    /* enable stop flag */
    SCTX.exit_flag = 1;

    /* Close list file */
    close ( SCTX.listfd );

    /* Show packet stats */
    printf ( "* Sent %lu pkts, received %lu pkts\n", SCTX.send_tot, SCTX.recv_tot );

    /* Show success message */
    printf ( "* Network scan complete!\n" );

    return 0;
}
