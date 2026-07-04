#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "myheader.h"


// Mac주소 출력
void print_mac(const u_char *mac){
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}


// Http 메시지 출력
void print_http_message(const u_char *payload, int payload_len){
    int i;

    printf("\n[HTTP Message]\n");

    for (i = 0; i < payload_len; i++) {
        if (isprint((unsigned char)payload[i]) || payload[i] == '\r' || payload[i] == '\n' || payload[i] == '\t') {
            putchar(payload[i]);
        }
        else {
            putchar('.');
        }
    }

    printf("\n");
}


// callback 함수 : 패킷을 캡처할때마다 호출됨
void got_packet(u_char *args,
                const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth;
    struct ipheader  *ip;
    struct tcpheader *tcp;

    int ethernet_header_len;
    int ip_header_len;
    int tcp_header_len;

    int ip_total_len;
    int payload_len;

    const u_char *payload;

    // 이더넷 헤더
    ethernet_header_len = sizeof(struct ethheader);
    eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }

    // IP 헤더
    ip = (struct ipheader *)
         (packet + ethernet_header_len);

    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    // IP헤더 길이
    ip_header_len = ip->iph_ihl * 4;

    //TCP헤더
    tcp = (struct tcpheader *)
          (packet
           + ethernet_header_len
           + ip_header_len);


    // TCP헤더 길이 계산
    tcp_header_len = TH_OFF(tcp) * 4;


    // Application Layer Data 위치 계산
    payload = packet
              + ethernet_header_len
              + ip_header_len
              + tcp_header_len;


    // Payload 길이 계산
    ip_total_len = ntohs(ip->iph_len);

    payload_len = ip_total_len
                  - ip_header_len
                  - tcp_header_len;

    {
        int captured_payload_len;

        captured_payload_len =
            (int)header->caplen
            - ethernet_header_len
            - ip_header_len
            - tcp_header_len;

        if (captured_payload_len < 0) {
            return;
        }

        if (payload_len > captured_payload_len) {
            payload_len = captured_payload_len;
        }
    }


    //패킷 정보 출력
    printf("----------------------------------\n");


    // 이더넷 헤더 정보 출력
    printf("\n[Ethernet Header]\n");

    printf("Source MAC      : ");
    print_mac(eth->ether_shost);
    printf("\n");

    printf("Destination MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n");


    // IP 헤더 정보 출력
    printf("\n[IP Header]\n");

    printf("Source IP       : %s\n",
           inet_ntoa(ip->iph_sourceip));

    printf("Destination IP  : %s\n",
           inet_ntoa(ip->iph_destip));

    printf("IP Header Length: %d bytes\n",
           ip_header_len);


    // TCP 헤더 정보 출력
    printf("\n[TCP Header]\n");

    printf("Source Port     : %u\n",
           ntohs(tcp->tcp_sport));

    printf("Destination Port: %u\n",
           ntohs(tcp->tcp_dport));

    printf("TCP Header Length: %d bytes\n",
           tcp_header_len);


    // HTTP 메시지 출력 
    if (payload_len > 0) {

        printf("Payload Length  : %d bytes\n",
               payload_len);

        print_http_message(payload, payload_len);
    }
    else {
        printf("\n[HTTP Message]\n");
        printf("No Application Data\n");
    }


    printf("----------------------------------\n");
}



int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;
    char *dev;


    //네트워크 인터페이스 설정
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        printf("Example: sudo %s enp0s3\n", argv[0]);
        return 1;
    }

    dev = argv[1];


    // live pcap session
    handle = pcap_open_live(
        dev,        /* network interface */
        BUFSIZ,     /* snapshot length */
        1,          /* promiscuous mode */
        1000,       /* timeout: 1000 ms */
        errbuf
    );



    // BPF 필터 컴파일
    if (pcap_compile(
            handle,
            &fp,
            filter_exp,
            0,
            net) == -1) {

        fprintf(stderr,
                "pcap_compile() failed: %s\n",
                pcap_geterr(handle));

        pcap_close(handle);
        return 1;
    }


    // BPF 필터 
    if (pcap_setfilter(handle, &fp) == -1) {

        fprintf(stderr,
                "pcap_setfilter() failed: %s\n",
                pcap_geterr(handle));

        pcap_freecode(&fp);
        pcap_close(handle);

        return 1;
    }


    printf("========================================\n");
    printf("Packet Sniffer Started\n");
    printf("Interface : %s\n", dev);
    printf("Filter    : %s\n", filter_exp);
    printf("========================================\n");


    pcap_loop(
        handle,
        -1,
        got_packet,
        NULL
    );

    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}