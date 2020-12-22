//每個封包一行
//封包時間 來源目標MAC Ethertype
//IP的話 來源目標IP位置
//TCP UDP port
//ARP ICMP

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>

//ip_total bonus
int ip_total = 0;
int ip6_total = 0;
//int len = 0;



struct ip_pair
{
    char src[50];
    char dst[50];
    int cnt;
};

void print_time(struct pcap_pkthdr *header)
{
    struct tm *ltime;
    char timestr[21];
    memset(timestr,0,sizeof(timestr));
    //localtime轉本地時區
    ltime = localtime(&header->ts.tv_sec);
    strftime(timestr, sizeof timestr, "%Y-%m-%e:%H:%M:%S", ltime);
    printf("| Time: %s\n",timestr);
}

void print_macaddr(unsigned char *mac_addr){
    // 6*2
    int i;
    for(i=0 ; i<6 ; i++){
        printf("%02x ", *(mac_addr + i));
        //if(i!=5) printf(":");
    }
    printf("\n");
}

void dump_udp(u_int32_t length,const u_char *content){
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
    u_int16_t sur_port = ntohs(udp->uh_sport);
    u_int16_t des_port = ntohs(udp->uh_dport);
    printf("|- Sour. Port: %d\n",sur_port);
    printf("|- Dest. Port: %d\n",des_port);

}

void dump_tcp(u_int32_t length,const u_char *content){
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
    u_int16_t sur_port = ntohs(tcp->th_sport);
    u_int16_t des_port = ntohs(tcp->th_dport);
    printf("|- Sour. Port: %d\n",sur_port);
    printf("|- Dest. Port: %d\n",des_port);
}

void dump_ip(u_int32_t length,const u_char *content,struct ip_pair arr[]){
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    //u_int version = ip->ip_v;
    //u_int header_len = ip->ip_hl << 2;
    //u_char tos = ip->ip_tos;
    //u_int16_t total_len = ntohs(ip->ip_len);
    //u_int16_t id = ntohs(ip->ip_id);
    //u_int16_t offset = ntohs(ip->ip_off);
    //u_char ttl = ip->ip_ttl;
    //u_int16_t checksum = ntohs(ip->ip_sum);
    u_char protocol = ip->ip_p;

    // IP 來源 目標
    printf("|- Sour. IP Addr: ");
    static char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->ip_src, str, sizeof(str));
    printf("%s\n",str);
    /*
    char *src;
    src = print_ip(&ip->ip_src);
    static char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, i, str, sizeof(str));
    printf("%s\n",str);
    return str;
    */
    printf("|- Dest. IP Addr: ");
    static char str1[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->ip_dst, str1, sizeof(str));
    printf("%s\n",str1);

    ip_total++;
    //check_ip
    switch (protocol) 
    {
        case IPPROTO_UDP:
            //printf("!!!!here!!!!!\n");
            printf("| UDP packet:\n");
            dump_udp(length, content);
            break;

        case IPPROTO_TCP:
            printf("| TCP packet:\n");
            dump_tcp(length, content);
            break;
    }

}
//ipv6做起來感覺怪怪的 查不太到

void dump_ipv6(u_int32_t length,const u_char *content,struct ip_pair arr[]){

    //char addrstr[INET6_ADDRSTRLEN];
    char sourIP6[INET6_ADDRSTRLEN];
    char destIP6[INET6_ADDRSTRLEN];
    struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(content + ETHER_HDR_LEN);
   
    inet_ntop(AF_INET6, &(ipv6_header->ip6_src), sourIP6, INET6_ADDRSTRLEN);
    printf("|- Sour. IP Addr: %s\n", sourIP6);

    inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), destIP6, INET6_ADDRSTRLEN);
    printf("|- Dest. IP Addr: %s\n", destIP6);
    
    
    ip6_total++;
    int nextheader = ipv6_header->ip6_nxt;
   

    switch (nextheader) 
    {
        case IPPROTO_UDP:
            printf("| UDP packet:\n");
            dump_udp(length, content);
            break;

        case IPPROTO_TCP:
            printf("| TCP packet:\n");
            dump_tcp(length, content);
            break;
        case IPPROTO_ICMP:
            printf("| ICMP packet:\n");
            break;
    }
    
}


int main(int argc , char *argv[]){
    pcap_t *handler = NULL;
    struct ip_pair arr[1000];
    char errbuf[PCAP_ERRBUF_SIZE];
    int num = 1;
    int flag = 0;
    int lenflag = 0;

    //offline 既有的錄好pcap檔
    handler = pcap_open_offline(argv[1], errbuf);
    if(!handler)
    {
        fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
        exit(1);
    }

    while(num){
        struct pcap_pkthdr *header = NULL;
        const u_char *content = NULL;
        //ret == -2 結束
        int ret = pcap_next_ex(handler, &header, &content);
        
        if(ret == 1){
            u_int16_t type;
            unsigned short ethernet_type = 0;
            struct ether_header *ethernet = (struct ether_header *)content;
            printf("--------------------\n");

            //print time
            print_time(header);

            // print mac 來源 目標
            unsigned char *mac_addr = NULL;
            mac_addr = (unsigned char *)ethernet -> ether_shost;
            printf("| Mac Sour. Addr: ");
            print_macaddr(mac_addr);
            mac_addr = (unsigned char *)ethernet -> ether_dhost;
            printf("| Mac Dest. Addr: ");
            print_macaddr(mac_addr);

            //print type
            ethernet_type = ntohs(ethernet->ether_type);
            printf("| Ether type : ");
            //*** bit 跟網路上剛好相反？
            printf("%2x\n",ethernet->ether_type);
            switch(ethernet_type)
            {
	            case ETHERTYPE_IP:
                    //packet 是IP(IPv4)
                    printf("| IP:\n");
                    //printf("cap %d\n",header->caplen);
                    dump_ip(header->caplen,content,arr);
                    break;
                case ETHERTYPE_IPV6:
                    printf("| IPv6\n");
                    //char addrstr[INET6_ADDRSTRLEN];
                    //printf("cap %d\n",header->caplen);
                    dump_ipv6(header->caplen,content,arr);
                    /*
                    struct ip6_hdr *header1 = header;
                    inet_ntop(AF_INET6, &header1->ip6_src, addrstr, sizeof(addrstr));
                    printf("|- Sour. IP Addr: %s\n", addrstr);

                    char addrstr1[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &header1->ip6_dst, addrstr1, sizeof(addrstr1));
                    printf("|- Dest. IP Addr: %s\n", addrstr1);
                    */
                    break;
                    case ETHERTYPE_ARP :
                        printf("ARP\n");
                        break;
            }
            //print len (bonus)
            printf("| Length: %d bytes\n", header->len);
            printf("--------------------\n");
        }
        //ret == -1 pcap err
        else if(ret == -1) fprintf(stderr, "pcap_next_ex(): %s\n", pcap_geterr(handler));
        else if(ret == -2) break;

        if(flag) num--;
    }

    printf("IP Package: %d\n",ip_total);
    pcap_close(handler);
    return 0;
}
