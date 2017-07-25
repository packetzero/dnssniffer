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

#include <unistd.h> // write
#include <fcntl.h> // open

#include <getopt.h> // command-line args - not on windows

std::string addr2text ( const in_addr& Addr );
std::string addr2text ( const in6_addr& Addr );

DnsParser *gDnsParser=0L;
int snaplen = 500;  // want to test for partial payloads

int gIsPathEnabled=1;
int gIgnoreCnames=0;
int gNoV4=0;
int gNoV6=0;

// Option to save packets to file for viewing by wireshark, tcpdump:

int gIsPcapOutEnabled=0; // set to true to have pcap file for comparison

const unsigned char GENERIC_PCAP_FILE_HEADER_BYTES[]={
  0xd4,0xc3,0xb2,0xa1,0x02,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x48,0x00,0x00,0x00,0x01,0x00,0x00,0x00
};
const char *PCAP_OUT_FILENAME="dnssniff.pcap";
int gPcapOutfile=0;

// command-line argument definitions
static struct option long_options[] =
  {
    /* These options set a flag. */
    {"nopath",   no_argument,       &gIsPathEnabled, 0},
    {"nocnames", no_argument,       &gIgnoreCnames, 1},
    {"capture",   no_argument,       &gIsPcapOutEnabled, 2},
    {"no6", no_argument, &gNoV6, 3},
    {"no4", no_argument, &gNoV4, 4},
    {"help", no_argument, NULL,'h'},
    {"trunc", 1, NULL, 't'},
    {0, 0, 0, 0}
  };

  #define NUM_OPTIONS 7

void usage()
{
  const char *str=
"usage dnssniffer <options> <ifname>\n\n"
"options:\n"
" --nopath    Do not keep track of CNAME path\n"
" --nocnames  Skip CNAME parsing altogether\n"
" --capture   Capture packets\n"
" --no6       Do not print ANSWER records containing IPV6 addresses\n"
" --no4       Do not print ANSWER records containing IPV4 addresses\n"
" --trunc <N> Truncate packets to N bytes, Where 60 < N < 1500. Defaults to 500\n";
;
  printf("%s\n", str);
}

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
    if (gNoV4) return;
    std::string addrStr = addr2text(addr);
    printf("%-20s %s\n", addrStr.c_str(), path.length() == 0 ? name.c_str() : path.c_str()); // name is first part of path
  }

  //----------------------------------------------------------------------------
  // Received IPv6 DNS response record
  //----------------------------------------------------------------------------
  virtual void onDnsRec(in6_addr addr, std::string name, std::string path) {
    if (gNoV6) return;
    std::string addrStr = addr2text(addr);
    printf("%-20s %s\n", addrStr.c_str(), path.length() == 0 ? name.c_str() : path.c_str()); // name is first part of path
  }
};

//----------------------------------------------------------------------------
// write packet and header to pcap file
//----------------------------------------------------------------------------
void save_packet(int fd, const struct pcap_pkthdr *header, const uint8_t *buffer)
{
  // can't just write header, as runtime timestamps are usually larger than
  // standard 4-byte ints.
  write(fd, &header->ts.tv_sec, 4);
  write(fd, &header->ts.tv_usec, 4);
  write(fd, &header->len, 4);
  write(fd, &header->caplen, 4);
  write(fd, buffer, header->caplen);
}

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
      if (gPcapOutfile > 0) save_packet(gPcapOutfile, header, buffer);
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
  char devname[128]="";
  int optchar, option_index = 0;

  if (argc == 1) { usage(); exit(0); }

  // command-line args

  while ( (optchar = getopt_long (argc, argv, "ht:", long_options, &option_index) != -1)) {
    if (option_index >= 0 && option_index < NUM_OPTIONS) {
      if (option_index == 5) { usage(); exit(0); }
      if (option_index == 6) {
        int n = atoi(optarg);
        if (n < 60 || n > 1500) { printf("Invalid trunc argument '%s'\n", optarg); exit(2); }
        snaplen = n;
      }
    } else {
      switch (optchar) {
        case 'h':
          usage(); exit(0);
        default:
          exit(1);
      }
    }
  }

  // look for non-options, first of which will be network interface name

  if (optind < argc)
      strcpy(devname, argv[argc-1]);

  if (strlen(devname) == 0) { usage(); exit(0); }


  // create parser and listener

  MyDnsParserListener *dnsRecPrinter = new MyDnsParserListener();
  gDnsParser = DnsParserNew(dnsRecPrinter, gIsPathEnabled, gIgnoreCnames);
  pcap_t *handle; //Handle of the device that shall be sniffed
  struct bpf_program fp;
  char filter_exp[] = "udp port 53";
  char errbuf[100];

  printf("Packets truncated at %d bytes\n", snaplen);
  if (gIgnoreCnames) printf("--nocnames option used, will ignore CNAME records\n");
  if (0 == gIsPathEnabled) printf("--nopath option used, CNAME paths omitted\n");

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

  if (gIsPcapOutEnabled)
  {
    gPcapOutfile = open(PCAP_OUT_FILENAME, O_CREAT | O_TRUNC | O_RDWR);
    if (gPcapOutfile > 0) {
      printf("Saving packets to file '%s'\n", PCAP_OUT_FILENAME);
      write(gPcapOutfile, GENERIC_PCAP_FILE_HEADER_BYTES, sizeof(GENERIC_PCAP_FILE_HEADER_BYTES));
    } else {
      printf("ERROR: unable to open PCAP outfile for writing '%s'\n", PCAP_OUT_FILENAME);
    }
  }


  // loop

  pcap_loop(handle , -1 , process_packet , NULL);

  // TODO: capture sigint/sigkill, cleanly close capture file and pcap handle

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
