#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

#include "list.h"

#define SNOOP_INTERFACE    "br-lan"
#define SNOOP_RECORD_FILE  "/tmp/dhcpsnoop"
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((unsigned char*)(x))[0],((unsigned char*)(x))[1],((unsigned char*)(x))[2],((unsigned char*)(x))[3],((unsigned char*)(x))[4],((unsigned char*)(x))[5]

/* BOOTP (rfc951) message types */
#define BOOTREQUEST     1
#define BOOTREPLY       2

#define OPTIONFIELD     0
#define FILEFIELD       1
#define SNAMEFIELD      2

/* Magic cookie validating dhcp options field (and bootp vendor
   extensions field). */
#define DHCP_OPTIONS_COOKIE "\143\202\123\143"

/* DHCP message types. */
#define DHCP_DISCOVER   1
#define DHCP_OFFER      2
#define DHCP_REQUEST    3
#define DHCP_DECLINE    4
#define DHCP_ACK        5
#define DHCP_NAK        6
#define DHCP_RELEASE    7
#define DHCP_INFORM     8

/* Options from RFC2132 */
#define DHCP_OPTION_PAD                 0
#define DHCP_OPTION_HOST_NAME           12
#define DHCP_OPTION_BOOT_SIZE           13
#define DHCP_OPTION_REQ_IP              50
#define DHCP_OPTION_LEASE_TIME          51
#define DHCP_OPTION_OVERLOAD            52
#define DHCP_OPTION_MESSAGE_TYPE        53
#define DHCP_OPTION_CLIENT_MAC          61
#define DHCP_OPTION_END                 255

struct dhcp_packet {
    unsigned char   op;         /* 0: Message opcode/type */
    unsigned char   htype;      /* 1: Hardware addr type (net/if_types.h) */
    unsigned char   hlen;       /* 2: Hardware addr length */
    unsigned char   hops;       /* 3: Number of relay agent hops from client */
    unsigned int    xid;        /* 4: Transaction ID */
    unsigned short  secs;       /* 8: Seconds since client started looking */
    unsigned short  flags;      /* 10: Flag bits */
    unsigned int    ciaddr;     /* 12: Client IP address (if already in use) */
    unsigned int    yiaddr;     /* 16: Client IP address */
    unsigned int    siaddr;     /* 18: IP address of next server to talk to */
    unsigned int    giaddr;     /* 20: DHCP relay agent IP address */
    unsigned char   chaddr [16];/* 24: Client hardware address */
    char            sname [64]; /* 40: Server name */
    char            file [128]; /* 104: Boot filename */
    unsigned int    cookie;     /* 212: cookie */
    unsigned char   options [308];
                                /* 216: Optional parameters
                                (actual length dependent on MTU). */
};

/* TR069 Hosts sturt */
struct hosts {
    unsigned char   hostname [32];
    unsigned char   macaddr [18];
    unsigned char   req_ipaddr [16];
    unsigned char   ipaddr [16];
    unsigned int    leasetime;
    unsigned char   active;
    struct list_head list;
};

struct hosts hosts_header; 
struct list_head *pos, *next; 

static unsigned char *get_option(struct dhcp_packet *packet, int optlen, int code, int *len)
{
    int   i, maxlen;
    unsigned char  *option;
    int   over = 0, done = 0, curr = OPTIONFIELD;

    option = packet->options;
    i = 0;
    maxlen = optlen;

    while (!done) {
        if (i >= maxlen)
        {

            printf("bogus packet, option fields too long.\n");
            return NULL;
        }
        if (option[i] == code) 
        {
            if (i + 1 + option[i + 1] >= maxlen) 
            {
                printf("bogus packet, option fields too long.\n");
                return NULL;
            }

            if (len != NULL) 
            {

                /* option len */
                *len = (int) option[i + 1];
            }
            return option + i + 2;
        }
        
        switch (option[i]) 
        {

        case DHCP_OPTION_PAD:
            i++;
            break;
        case DHCP_OPTION_OVERLOAD:
            if (i + 1 + option[i + 1] >= maxlen) {
                printf("bogus packet, option fields too long.\n");
                return NULL;
            }
            over = option[i + 3];
            i += option[i + 1] + 2;
            break;
        case DHCP_OPTION_END:
            if (curr == OPTIONFIELD && over & FILEFIELD) {

                option = (unsigned char *) packet->file;
                i = 0;
                maxlen = 128;
                curr = FILEFIELD;
            } else if (curr == FILEFIELD && over & SNAMEFIELD) {

                option = (unsigned char *) packet->sname;
                i = 0;
                maxlen = 64;
                curr = SNAMEFIELD;
            } else {

                done = 1;
            }
            break;
        default:
            i += option[i + 1] + 2;
        }
    }
    return NULL;
}


void dhcp_protocol_callback(unsigned char *argument, const struct pcap_pkthdr *packet_heaher, const unsigned char *packet_content)
{  
    unsigned short ethernet_type;
    struct iphdr *iph;
    struct udphdr *udph;
    struct dhcp_packet *dhcp;
    unsigned char  *option;
    int dhcplen, optlen, len;
    struct hosts *phtx_hosts, *plist_htx_hosts;

    unsigned char tmp[256] = {0};
    struct in_addr cli_addr;
    FILE *snoopfp;

    udph = (struct udphdr *)(packet_content + sizeof(struct iphdr) + sizeof(struct ether_header));
    dhcp = (struct dhcp_packet *)(packet_content + sizeof(struct ether_header) +sizeof(struct iphdr) + sizeof(struct udphdr));
    dhcplen = ntohs(udph->len) - sizeof(struct udphdr);
    optlen = dhcplen - (sizeof(struct dhcp_packet) - sizeof(dhcp->options));

    phtx_hosts = (struct hosts *)malloc(sizeof(struct hosts));
    memset(phtx_hosts, 0, sizeof(struct hosts));

    if((snoopfp = fopen(SNOOP_RECORD_FILE, "w")) == NULL)
        perror("Open snooping file filed!\n");
    /* If it is a DHCP request, we need recode client MAC, request IP, Host name */
    if (dhcp->op == BOOTREQUEST)
    {        
        sprintf(tmp, MAC_FMT, MAC_ARG(dhcp->chaddr));
        strncpy(phtx_hosts->macaddr, tmp, strlen(tmp));

        option = get_option(dhcp, optlen, DHCP_OPTION_HOST_NAME, &len);
        strncpy(phtx_hosts->hostname, option, len);

        option = get_option(dhcp, optlen, DHCP_OPTION_REQ_IP, &len);
        if(len == 4)
        {
            memcpy(&cli_addr, option, 4);
            strncpy(phtx_hosts->req_ipaddr, inet_ntoa(cli_addr), strlen(inet_ntoa(cli_addr)));
        }

        phtx_hosts->active = 1;
    }
    else
    /* If it is a DHCP ACK, we need recode client MAC, your clent IP, Host name, Lease time */
    if (dhcp->op == BOOTREPLY)
    {
        sprintf(tmp, MAC_FMT, MAC_ARG(dhcp->chaddr));
        strncpy(phtx_hosts->macaddr, tmp, strlen(tmp));
        
        option = get_option(dhcp, optlen, DHCP_OPTION_HOST_NAME, &len);
        strncpy(phtx_hosts->hostname, option, len);


        memcpy(&cli_addr, &dhcp->yiaddr, 4);
        strncpy(phtx_hosts->ipaddr, inet_ntoa(cli_addr), strlen(inet_ntoa(cli_addr)));

        option = get_option(dhcp, optlen, DHCP_OPTION_LEASE_TIME, &len);
        phtx_hosts->leasetime = ntohl(*((int*)option));

        phtx_hosts->active = 1;

    }
    else
    {
        free(phtx_hosts);
        return;
    }

    list_for_each(pos, &hosts_header.list)
    {
        plist_htx_hosts = list_entry(pos, struct hosts, list);
        if(strcmp(plist_htx_hosts->macaddr,phtx_hosts->macaddr) == 0)
        {
            if((strlen(phtx_hosts->hostname) != 0))
                strcpy(plist_htx_hosts->hostname, phtx_hosts->hostname);

            if((strlen(phtx_hosts->req_ipaddr) != 0))
                strcpy(plist_htx_hosts->req_ipaddr, phtx_hosts->req_ipaddr);

            if((strlen(phtx_hosts->ipaddr) != 0))
                strcpy(plist_htx_hosts->ipaddr, phtx_hosts->ipaddr);

            if((phtx_hosts->leasetime != 0))
                plist_htx_hosts->leasetime = phtx_hosts->leasetime;

            plist_htx_hosts->active = 1;
            
            free(phtx_hosts);
            fseek(snoopfp, 0, SEEK_SET);
            fprintf(snoopfp, "---------------------------DHCP snooping table---------------------------------\n");
            list_for_each(pos, &hosts_header.list)
            {
                plist_htx_hosts = list_entry(pos, struct hosts, list);
                fprintf(snoopfp,"%s | %s | %s | %s | %d | %d\n",
                    plist_htx_hosts->macaddr,
                    plist_htx_hosts->hostname, 
                    plist_htx_hosts->req_ipaddr, 
                    plist_htx_hosts->ipaddr, 
                    plist_htx_hosts->leasetime,
                    plist_htx_hosts->active);
            }
            fclose(snoopfp);
            return;
        }
    }
    
    list_add_tail(&(phtx_hosts->list), &(hosts_header.list));
    fseek(snoopfp, 0, SEEK_SET);
    fprintf(snoopfp, "---------------------------DHCP snooping table---------------------------------\n");
    list_for_each(pos, &hosts_header.list)
    {
        plist_htx_hosts = list_entry(pos, struct hosts, list);
        fprintf(snoopfp, "%s | %s | %s | %s | %d | %d\n",
            plist_htx_hosts->macaddr,
            plist_htx_hosts->hostname, 
            plist_htx_hosts->req_ipaddr, 
            plist_htx_hosts->ipaddr, 
            plist_htx_hosts->leasetime,
            plist_htx_hosts->active);
    }
    fclose(snoopfp);
    return;
    
}

int main(int argc, char *argv[])
{

    pcap_t *handle;
    /* Error string */
    char errbuf[PCAP_ERRBUF_SIZE];
    /* The compiled filter */
    struct bpf_program fp;
    /* The filter: DHCP packets */
    char filter_exp[] = "( udp and ( port 67 or port 68 ) )";
    bpf_u_int32 mask;
    bpf_u_int32 net;

    /* Init list */
    INIT_LIST_HEAD(&hosts_header.list);
        
    /* Find the properties for the device */
    if (pcap_lookupnet(SNOOP_INTERFACE, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", SNOOP_INTERFACE, errbuf);
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(SNOOP_INTERFACE, 1024, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", SNOOP_INTERFACE, errbuf);
        return(2);
    }

    /* Compile and apply the filter */  
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    
    if(pcap_loop(handle, -1, dhcp_protocol_callback, NULL) < 0)
    {
        perror("pcap_loop");
    } 
    
    pcap_close(handle);
    return(0);
}
