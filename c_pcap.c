#include <pcap.h> 
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h> 
//ip header 구조체

#include <netinet/tcp.h> 
//tcp header 구조체

#include <netinet/if_ether.h> 
//ethernet header 구조체

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr *eth = (struct ethhdr *) packet; //ethernet header 구조체 선언
    struct iphdr *iph = (struct iphdr *) (packet + ETH_HLEN); //ip header 구조체 선언
    struct tcphdr *tcph = (struct tcphdr *) (packet + ETH_HLEN + iph->ihl*4); //tcp header 구조체 선언

    printf("[Ethernet Header]\n");
    printf("  SRC MAC : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2],eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("  DST MAC : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0],eth->h_dest[1],eth->h_dest[3],eth->h_dest[3] ,eth -> h_dest [ 4 ] ,eth -> h_dest [ 5 ]);
    
    printf("[IP Header]\n");
    struct in_addr src_addr;
    src_addr.s_addr = iph->saddr;
    printf("  SRC IP : %s\n", inet_ntoa(src_addr));

    struct in_addr dest_addr;
    dest_addr.s_addr = iph->daddr;
    printf("  DST IP : %s\n", inet_ntoa(dest_addr));
   
  
    printf("[TCP Header]\n");
    printf("  SRC Port : %u\n" , ntohs(tcph -> source));
    printf("  DST Port : %u\n" , ntohs(tcph -> dest));

    printf("[Message]\n  Message : ");
    int data_size = ntohs(iph->tot_len) - (iph->ihl*4) - (tcph->doff*4);

    if(data_size > 0) {
        char *data = (char *)(packet + ETH_HLEN + iph->ihl*4 + tcph->doff*4);
        
        for(int i=0; i<10 && i<data_size; i++) { //data는 10자리까지만 보여주기!
            printf("%02X ", data[i]);
        }
        printf("");
   }
    printf("\n\n\n");
 }

int main() {
   pcap_t *handle; //패킷 캡처 세션 관리
   char errbuf [ PCAP_ERRBUF_SIZE ]; //오류 메세지 저장
   char* devname;
   
   pcap_if_t *alldevs; //모든 네트워크 장치 검색 후 장치 목록을 alldevvs에 저장
   
   if(pcap_findalldevs(&alldevs, errbuf) == -1) //장치 검색에 실패 했을 시 예외처리
   {
       fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
       exit(1);
   }

   devname = alldevs->name; //네트워크 장치에서 신호캡쳐 핸들(pcap_t*) 가져오기

   
   handle = pcap_open_live(devname , BUFSIZ , 1 , -1 , errbuf); //네트워크 장치 열어서 패킷 캡처 세션 시작

   if(handle == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s" , devname, errbuf);
      return(1);
   }

  
  if(pcap_loop(handle, -1, process_packet, NULL)<0) { //세션 여는거 실패 시 예외처리
       fprintf(stderr,"pcap_loop() function failed due to error: %s", pcap_geterr(handle));
       return 1;
   }

   pcap_close(handle); //캡쳐 완료 시 handle 닫기 (free resource)
   pcap_freealldevs(alldevs); //alldevs (네트워크 장치 목록) 메모리 할당 해제 (free resource)
   
   return(0);
}