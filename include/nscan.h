/* ------------------------------------------------------------------
 * N Scan - Shared Project Header
 * ------------------------------------------------------------------ */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#ifndef NSCAN_H
#define NSCAN_H

#define IPHSIZE sizeof(struct iphdr)
#define TCPHSIZE sizeof(struct tcphdr)
#define PSEUDOTCPHSIZE sizeof(struct pseudo_tcp)

/**
 * \brief               The tcp packet structure
 *
 * \param saddr         source ip address
 * \param daddr         dest ip address
 * \param mbz           flag (set to 0)
 * \param ptcl          protocol number (6 for tcp)
 * \param tcpl          tcp + payload length (at least 20)
 * \param tcp           tcp header
 *
 */

#pragma pack(push, 1)
struct pseudo_tcp
{
    unsigned int saddr;
    unsigned int daddr;
    unsigned char mbz;
    unsigned char ptcl;
    unsigned short tcpl;

    struct tcphdr tcp;
};
#pragma pack(pop)

/**
 * \brief               The tcp packet structure
 *
 * \param ip            ip header
 * \param tcp           tcp header
 * \param payload       payload buffer
 *
 */

#pragma pack(push, 1)
struct packet
{
    struct iphdr ip;
    struct tcphdr tcp;
};
#pragma pack(pop)

/**
 * \brief               IP/TCP scanner context
 *
 * \param src_addr      Packets source address
 * \param src_port      Packets source port
 * \param dest_port     Packets destination port
 * \param nacks         Number of received SYN, ACK packets
 * \param send_tot      Number of sent packets
 * \param recv_tot      Number of received packets
 * \param fsock         Packet forge socket
 * \param fsin          Packet forge socket address
 * \param listfd        List file descriptor
 * \param exit_flag     Exit flag
 * \param p             IP/TCP SYN packet base
 *
 */

struct scanner_ctx
{
    unsigned int src_addr;
    unsigned short src_port;
    unsigned short dest_port;

    unsigned int nack;
    unsigned long send_tot;
    unsigned long recv_tot;

    int fsock;
    struct sockaddr_in fsin;
    int listfd;
    int exit_flag;
    
    struct packet p;
};

/**
 * \brief               Packets scanner task entry point
 *
 * \param args          Arguments passed to task
 *
 * \return              NULL
 */

extern void *scanner_entry_point ( void *args );

/**
 * \brief               Packets scanner task
 *
 * \param sctx          Scanner context
 *
 * \return              On success 0, otherwise -1
 */

extern int scanner_task ( struct scanner_ctx *sctx );

/**
 * \brief               Setup packet forge socket
 *
 * \param sctx          Scanner context
 *
 * \return              On success 0, otherwise -1
 */

extern int forge_setup ( struct scanner_ctx *sctx );

/**
 * \brief               Packets forge task
 *
 * \param sctx          Scanner context
 * \param addr          First address of block
 * \param size          Block address count
 *
 * \return              On success 0, otherwise -1
 */

extern int forge_task ( struct scanner_ctx *sctx, unsigned int addr, unsigned int size );

/**
 * \brief               Format IPv4 address to string
 *
 * \param in            IPv4 address
 * \param buffer        String buffer
 * \param size          String buffer size
 *
 */

extern void inet_ntoa_s ( unsigned int in, char *buffer, size_t size );

/**
 * \brief               Program entry point
 *
 * \param argc          Arguments count
 * \param argv          Arguments vector
 *
 * \return              On success 0, otherwise error code
 */

extern int main ( int argc, char *argv[] );


#endif
