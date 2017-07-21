/*
DNS Packet sniffer using libpcap library
Simple IPV4, no support for Ethernet VLAN tagging.
Depends on BPF filtering of 'UDP port 53'.
Logs each response record to stdout:

Usage:  dnssniffer <ifname>

Example Usage:  dnssniffer en0

Example output:

 Packets truncated at 300 bytes
 Opening device en0 for sniffing ... Device en0 opened
 BPF filter: udp port 53

 74.121.142.165   sync.mathtag.com||pixel-origin.mathtag.com
 74.121.138.87    sync.mathtag.com||pixel-origin.mathtag.com
 54.245.252.2     imp2.ads.linkedin.com||fanboy-web-linkedin-prod-719098781.us-west-2.elb.amazonaws.com
 54.244.253.81    imp2.ads.linkedin.com||fanboy-web-linkedin-prod-719098781.us-west-2.elb.amazonaws.com
 130.211.15.187   api.olark.com
 72.21.81.200     azurecomcdn.azureedge.net||azurecomcdn.ec.azureedge.net||cs9.wpc.v0cdn.net
 131.253.14.38    c1.microsoft.com||c.msn.com||c.msn.com.nsatc.net
 204.79.197.200   c.bing.com||c-bing-com.a-0001.a-msedge.net||.a-0001.a-msedge.net
 13.107.21.200    c.bing.com||c-bing-com.a-0001.a-msedge.net||.a-0001.a-msedge.net

*/
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include "../dnsparser/include/dnsparser.h"

#include "nethdrs.h"
#include <arpa/inet.h>  // ntop

std::string addr2text ( const in_addr& Addr );
std::string addr2text ( const in6_addr& Addr );

DnsParser *gDnsParser=0L;
int snaplen = 300;  // want to test for partial payloads

//----------------------------------------------------------------------------
// implementation of DnsParserListener, so we can receive callbacks
//----------------------------------------------------------------------------
class MyDnsParserListener : public DnsParserListener
{
public:
  //----------------------------------------------------------------------------
  // Received IPv4 DNS response record
  //----------------------------------------------------------------------------
  virtual void onDnsRec(in_addr addr, std::string name, std::string path)
  {
    std::string addrStr = addr2text(addr);
    printf("%-20s %s\n", addrStr.c_str(), path.c_str()); // name is first part of path
  }

  //----------------------------------------------------------------------------
  // Received IPv6 DNS response record
  //----------------------------------------------------------------------------
  virtual void onDnsRec(in6_addr addr, std::string name, std::string path) {
    std::string addrStr = addr2text(addr);
    printf("%-20s %s\n", addrStr.c_str(), path.c_str()); // name is first part of path
  }
};

//----------------------------------------------------------------------------
// handle a UDP packet
// Assumes payload is DNS, main() should be using BPF filter 'udp port 53'
//----------------------------------------------------------------------------
void process_udp_packet(const uint8_t *Buffer , int Size)
{
  struct ip *iph = (struct ip *)(Buffer +  sizeof(struct ether_header));
  unsigned short iphdrlen = IP_HL(iph)*4;

  if (iphdrlen < sizeof(struct ip)) return; // sanity check

  struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ether_header));

  int udpHeaderSize =  sizeof(struct ether_header) + iphdrlen + sizeof udph;
  int udpPayloadSize = Size - udpHeaderSize;

  //printf("UDP packet %d bytes payload:%d bytes\n", Size, payload_size);

  // give payload to UDP parser.
  // If it parses DNS response, MyDnsParserListener.onDnsRec() will be called

  if (0L != gDnsParser && udpPayloadSize > 4)
    gDnsParser->parse((char*)Buffer + udpHeaderSize, udpPayloadSize);
}

//----------------------------------------------------------------------------
// process_packet - called by libpcap loop for each packet matching BPF filter
//----------------------------------------------------------------------------
void process_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *buffer)
{
  if (header->caplen < header->len) printf("=== Truncated packet %d -> %d bytes\n", header->len, header->caplen);

  //Get the IP Header part of this packet , excluding the ethernet header (won't work for VLAN tagged packets)
  struct ip *iph = (struct ip*)(buffer + sizeof(struct ether_header));
  switch (iph->ip_p) //Check the Protocol and do accordingly...
  {
    case 17: //UDP Protocol
    process_udp_packet(buffer , header->caplen);
    break;
    default: //Some Other Protocol like ARP etc.
    break;
  }
}

//----------------------------------------------------------------------------
// main
//----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  MyDnsParserListener *dnsRecPrinter = new MyDnsParserListener();
  gDnsParser = DnsParserNew(dnsRecPrinter);
  pcap_t *handle; //Handle of the device that shall be sniffed
  struct bpf_program fp;
  char filter_exp[] = "udp port 53";
  char devname[128]="en0";
  char errbuf[100];

  // pull devname from command-line arg if present

  if (argc > 1 && strlen(argv[1]) < sizeof(devname)) strcpy(devname, argv[1]);

  printf("Packets truncated at %d bytes\n", snaplen);

  //Open the device for sniffing
  printf("Opening device %s for sniffing .." , devname);
  handle = pcap_open_live(devname , snaplen , 0 /* not promisc */ , 10 /* millis timeout */ , errbuf);

  if (handle == NULL)
  {
    fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
    if (argc <=1 ) printf("Hint: Specify network device (e.g. 'eth1') in first command-line argument.\n\n");
    exit(1);
  }

  printf(".. success\n");

  // Compile BPF filter

  if ((pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN)) == -1)
  {
    printf("compile error block entered\n");
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
    pcap_geterr(handle));
    return (2);
  }

  // Attached to open handle

  if (pcap_setfilter(handle, &fp) == -1)
  {
    fprintf(stderr, "couldn't install filter %s: %s\n", filter_exp,
    pcap_geterr(handle));
    return (2);
  }

  printf("BPF filter: %s\n", filter_exp);
  printf("\n");

  // loop

  pcap_loop(handle , -1 , process_packet , NULL);

  return 0;
}

//----------------------------------------------------------------------------
// returns readable string format of ipv4 address
//----------------------------------------------------------------------------
std::string addr2text ( const in_addr& Addr )
{
  std::string strPropText="errIPv4";
  char IPv4AddressAsString[INET_ADDRSTRLEN];      //buffer needs 16 characters min
  if ( NULL != inet_ntop ( AF_INET, &Addr, IPv4AddressAsString, sizeof(IPv4AddressAsString) ) )
  strPropText = IPv4AddressAsString;
  return strPropText;
}

std::string addr2text ( const in6_addr& Addr )
{
 std::string strPropText="errIPV6";
 char IPv6AddressAsString[INET6_ADDRSTRLEN];	//buffer needs 46 characters min
 if ( NULL != inet_ntop ( AF_INET6, &Addr, IPv6AddressAsString, sizeof(IPv6AddressAsString) ) )
   strPropText = IPv6AddressAsString;
 return strPropText;
}
