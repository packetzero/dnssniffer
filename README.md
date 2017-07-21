# dnssniffer - Simple DNS payload parser in C++
This is an example program to demonstrate use of [dnsparser](https://github.com/packetzero/dnsparser/) library.
Uses libpcap, and runs on MacOS and Linux.  This is not designed to be run on a DNS server.

The executable takes a single argument: device name, such as eth1, en0, etc.  By default, truncates packets to 300 bytes, to keep load low.  This limit will be hit when DNS response records are large (12 IPv4 addresses + 1 cname) or IPV6 response.  You can bump this up to 500 if you want to be more inclusive.  I was testing dnsparser's ability to handle partial records.

# Build Linux/MacOS

```sh build.sh```

# Build debug version Linux/MacOS

```CONFIG=Debug sh build.sh```

# Run from command-line

```./platform/*/Release/dnssniffer eth0```

# MacOS: Running/Debugging using XCode

First run command-line build.sh, then open the .xcodeproj in platform/*/

# Example output

```157.240.17.35        www.facebook.com||star-mini.c10r.facebook.com
2a03:2880:f113:183:face:b00c::25de www.facebook.com||star-mini.c10r.facebook.com
66.135.202.233       pulsar.ebay.com||pulsar.g.ebay.com
104.244.46.199       abs.twimg.com||wildcard.twimg.com
104.244.46.135       abs.twimg.com||wildcard.twimg.com
13.107.6.152         b-0002.b-msedge.net
2620:1ec:a92::152    b-0002.b-msedge.net
52.218.192.34        arlos3-prod-z2.s3.amazonaws.com||s3-us-west-2-w.amazonaws.com
50.18.192.251        duckduckgo.com
=== Truncated packet 388 -> 300 bytes
129.146.14.96        stags.bluekai.com||tags.phx.bluekai.com
129.146.14.97        stags.bluekai.com||tags.phx.bluekai.com
```


