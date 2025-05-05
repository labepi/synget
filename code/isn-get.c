/**
 * Copyright (C) 2008 Joao Paulo de Souza Medeiros.
 *
 * Author(s): João Paulo de Souza Medeiros <ignotus21@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <libnet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/types.h>

#define USAGE   "\nUsage: %s -s -t [-f -p] [-a] [-d] [-i]\n"\
                "\t-d device (default eth0)\n"\
                "\t-s source (ip:port - 192.168.21.2:20)\n"\
                "\t-t target (ip:port - 192.168.21.1:21)\n"\
                "\t-a number of packets set to send (default 100000)\n"\
                "\t-i packet sending interval (microseconds, default 10000)\n"

#define SLL_ADDR_SIZE   8
#define SNAP_LEN        1518
#define SIZE_ETHERNET   14
#define SIZE_SLL        16
#define MAX_PORT_VALUE  65535

typedef u_int32_t tcp_seq;

struct s_linux_sll
{
    u_short packet_type;            /* packet type */
    u_short arphrd;                 /* linux ARPHRD_ value */
    u_short length;                 /* length of the sender address */
    u_char  address[SLL_ADDR_SIZE]; /* first 8-byte sender address */
    u_short ether_type;             /* IP? ARP? RARP? etc */
};

struct s_ethernet
{
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct s_ip
{
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF       0x8000          /* reserved fragment flag */
#define IP_DF       0x4000          /* dont fragment flag */
#define IP_MF       0x2000          /* more fragments flag */
#define IP_OFFMASK  0x1fff          /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)   (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)    (((ip)->ip_vhl) >> 4)

struct s_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN      0x01
#define TH_SYN      0x02
#define TH_RST      0x04
#define TH_PUSH     0x08
#define TH_ACK      0x10
#define TH_URG      0x20
#define TH_ECE      0x40
#define TH_CWR      0x80
#define TH_FLAGS    (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

/*
 * Pcap filter format and size
 * +10 - two maximum port string size
 * +32 - two maximum address string size
 *  -8 - subtract format type strings
 *  +1 - add '\0' to string
 */
#define FILTER_FORMAT   "(tcp[13] & 0x02 = 2) and "\
                        "(src port %d) and (dst port %d) and "\
                        "(src host %s) and (dst host %s)"
#define FILTER_SIZE     (strlen(FILTER_FORMAT) + 10 + 32 - 8 + 1)

unsigned int *count, datalink;

void usage(char* name)
{
    fprintf(stderr, USAGE, name);
}

void send_packets(libnet_t *lnet_handle,
                  u_int32_t src,
                  u_int32_t dst,
                  u_short src_port,
                  u_short dst_port,
                  unsigned int amount,
                  useconds_t interval)
{
    libnet_ptag_t tcp = LIBNET_PTAG_INITIALIZER,
                  ip = LIBNET_PTAG_INITIALIZER;

    while (*count < amount)
    {
        tcp = libnet_build_tcp(
                    src_port,
                    dst_port,
                    0,
                    0,
                    TH_SYN,
                    1024,
                    0,
                    0,
                    LIBNET_TCP_H,
                    NULL,
                    0,
                    lnet_handle,
                    tcp);

        ip = libnet_build_ipv4(
                LIBNET_TCP_H + LIBNET_IPV4_H,   /* length */
                0,                              /* TOS */
                0,                              /* IP ID */
                0,                              /* IP Frag */
                64,                             /* TTL */
                IPPROTO_TCP,                    /* protocol */
                0,                              /* checksum */
                src,                            /* source IP */
                dst,                            /* destination IP */
                NULL,                           /* payload */
                0,                              /* payload size */
                lnet_handle,                    /* libnet context */
                ip);                            /* ptag */

        if (ip == -1)
        {
            fprintf(stderr,
                    "Can't build IP: %s.\n",
                    libnet_geterror(lnet_handle));

            exit(EXIT_FAILURE);
        }

        int res = libnet_write(lnet_handle);

        if (res == -1)
        {
            fprintf(stderr,
                    "libnet_write: %s.\n",
                    libnet_geterror(lnet_handle));

            exit(EXIT_FAILURE);
        }

        usleep(interval);
    }
}

void
get_tcp_isn(u_char *args,
            const struct pcap_pkthdr *header,
            const u_char *packet)
{
    /*
     * The comments on this function are due to unused variables.
     */
    //const struct s_ip *ip;
    const struct s_tcp *tcp;
    //const unsigned char *payload;

    int size_link;
    int size_ip;
    //int size_tcp;
    //int size_payload;

    u_int32_t seq;

    switch (datalink)
    {
        case DLT_EN10MB:
            size_link = SIZE_ETHERNET;
            break;
        case DLT_LINUX_SLL:
            size_link = SIZE_SLL;
            break;
        default:
            fprintf(stderr, "Unsuported datalink.\n");
            exit(EXIT_FAILURE);
    }

    //ip = (struct s_ip*)(packet + size_link);

    size_ip = IP_HL((struct s_ip *) (packet + size_link)) * 4;
    //size_tcp = TH_OFF((struct s_tcp *) (packet + size_link + size_ip)) * 4;
    //size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    tcp = (struct s_tcp*)(packet + size_link + size_ip);
    //payload = (u_char *)(packet + size_link + size_ip + size_tcp);

    seq = ntohl(tcp->th_seq);

    printf("%u\n", seq);

    *count += 1;
}

int main(int argc, char **argv)
{
    /**
     *
     */
    int shmid;
    key_t key = rand();

    libnet_t *lnet_handle = NULL;
    pcap_t *pcap_handle;

    char lnet_errbuf[LIBNET_ERRBUF_SIZE];
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    char *cp, *filter, *dst_str, *src_str, *device = "eth0";
    struct bpf_program fp;
    u_int32_t dst, src;
    u_short dst_port, src_port;
    pid_t pid;
    unsigned int c,
                 amount = 10000;    /* 10000 packets sent by default */
    useconds_t interval = 10000;    /* 10 miliseconds by default */

    if (argc < 5)
    {
        usage(argv[0]);

        exit(EXIT_FAILURE);
    }

    /**
     * Getting arguments
     */
    while ((c = getopt(argc, argv, "d:s:t:a:i:")) != EOF)
    {
        switch(c)
        {
            case 'd':
                device = malloc(sizeof(char) * strlen(optarg));
                strcpy(device, optarg);
                break;

            case 's':
                if (!(cp = strrchr(optarg, ':')))
                {
                    usage(argv[0]);

                    exit(EXIT_FAILURE);
                }

                *cp++ = 0;
                src_port = (u_short)atoi(cp);

                src = libnet_name2addr4(lnet_handle, optarg, LIBNET_RESOLVE);
                src_str = malloc(sizeof(char) * (strlen(optarg) + 1));
                strcpy(src_str, optarg);

                if (src == -1)
                {
                    fprintf(stderr,
                            "Bad source (%s).\n",
                            libnet_geterror(lnet_handle));

                    exit(EXIT_FAILURE);
                }

                break;

            case 't':
                if (!(cp = strrchr(optarg, ':')))
                {
                    usage(argv[0]);

                    exit(EXIT_FAILURE);
                }

                *cp++ = 0;
                dst_port = (u_short)atoi(cp);

                dst = libnet_name2addr4(lnet_handle, optarg, LIBNET_RESOLVE);
                dst_str = malloc(sizeof(char) * (strlen(optarg) + 1));
                strcpy(dst_str, optarg);

                if (dst == -1)
                {
                    fprintf(stderr,
                            "Bad target (%s).\n",
                            libnet_geterror(lnet_handle));

                    exit(EXIT_FAILURE);
                }

                break;

            case 'i':
                interval = atoi(optarg);
                break;

            case 'a':
                amount = atoi(optarg);
                break;
        }
    }


    /**
     * Initialize libnet
     */
    lnet_handle = libnet_init(LIBNET_RAW4, device, lnet_errbuf);

    if (lnet_handle == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s.\n", lnet_errbuf);

        exit(EXIT_FAILURE);
    }

    /**
     * Initialize libpcap
     */
    pcap_handle = pcap_open_live(device, SNAP_LEN, 1, 1000, pcap_errbuf);

    if (pcap_handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s.\n", device, pcap_errbuf);

        exit(EXIT_FAILURE);
    }

    datalink = pcap_datalink(pcap_handle);

    if (datalink != DLT_EN10MB && datalink != DLT_LINUX_SLL)
    {
        fprintf(stderr, "%s (%d) is not an Ethernet.\n", device, datalink);

        exit(EXIT_FAILURE);
    }

    filter = (char*) malloc(FILTER_SIZE);

    sprintf(filter,
            FILTER_FORMAT,
            dst_port,
            src_port,
            dst_str,
            src_str);

    if (pcap_compile(pcap_handle, &fp, filter, 0, 0) == -1)
    {
        fprintf(stderr,
                "Couldn't parse filter '%s': %s.\n",
                filter,
                pcap_geterr(pcap_handle));

        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(pcap_handle, &fp) == -1)
    {
        fprintf(stderr,
                "Couldn't install filter %s: %s.\n",
                filter, pcap_geterr(pcap_handle));

        exit(EXIT_FAILURE);
    }

    /**
     *
     */
    if ((shmid = shmget(key, sizeof(unsigned int), IPC_CREAT | 0666)) < 0)
    {
        perror("shmget");

        exit(1);
    }

    if ((count = shmat(shmid, NULL, 0)) == (unsigned int *) -1)
    {
        perror("shmat");

        exit(1);
    }

    *count = 0;

    pid = fork();

    if (pid == 0)
    {
        pcap_loop(pcap_handle, amount, get_tcp_isn, NULL);

        fflush(stdout);

        pcap_freecode(&fp);
        pcap_close(pcap_handle);
    }
    else
    {
        send_packets(lnet_handle,
                     src,
                     dst,
                     src_port,
                     dst_port,
                     amount,
                     interval);

        libnet_destroy(lnet_handle);
    }

    exit(EXIT_SUCCESS);
}
