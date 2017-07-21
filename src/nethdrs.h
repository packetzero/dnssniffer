#ifndef _NETHDRS_H_
#define _NETHDRS_H_

#define	ETHER_ADDR_LEN		6 // e.g. MAC address

typedef struct	ether_header {
  uint8_t	ether_dhost[ETHER_ADDR_LEN];
  uint8_t	ether_shost[ETHER_ADDR_LEN];
  uint16_t	ether_type;
}
ether_hdr_t;

typedef struct ip {
  u_int8_t	ip_vhl;		/* header length, version */
  #define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
  #define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
  u_int8_t	ip_tos;		/* type of service */
  u_int16_t	ip_len;		/* total length */
  u_int16_t	ip_id;		/* identification */
  u_int16_t	ip_off;		/* fragment offset field */
  #define	IP_DF 0x4000			/* dont fragment flag */
  #define	IP_MF 0x2000			/* more fragments flag */
  #define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
  u_int8_t	ip_ttl;		/* time to live */
  u_int8_t	ip_p;		/* protocol */
  u_int16_t	ip_sum;		/* checksum */
  uint32_t ip_src,ip_dst;	/* source and dest address */
}
ip_hdr_t;

typedef struct udphdr {
    u_int16_t   uh_sport;       /* source port */
    u_int16_t   uh_dport;       /* destination port */
    u_int16_t   uh_ulen;        /* udp length */
    u_int16_t   uh_sum;         /* udp checksum */
} udp_hdr_t;

#endif // _NETHDRS_H_
