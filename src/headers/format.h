//
// Created by rinlang on 4/1/23.
//
//数据单元头结构体

#ifndef WIREWHALE_FORMAT_H
#define WIREWHALE_FORMAT_H

/*
 * u_char 1 byte
 * u_short 2 bytes
 * u_int 4 bytes
 * u_long 4 bytes
 * */
#include <cstdlib>

#define ARP  "ARP"                 //
#define TCP  "TCP"                 //
#define UDP  "UDP"                 //
#define ICMP "ICMP"                //
#define DNS  "DNS"                 //
#define TLS  "TLS"                 //
#define SSL  "SSL"                 //

/*Ethernet protocol format
+-------------------+-----------------+---------------------+
|       6 byte                  |     6 byte             |2 byte|
+-------------------+-----------------+---------------------+
|destination address|  source address | type |
+-------------------+-----------------+---------------------+
*/

typedef struct EPHeader {
    u_char des_mac[6];//Destination MAC
    u_char src_mac[6];//Source MAC
    u_short type;//标识数据字段中包含的高层协议,0x0800 代表 IP 协议帧；0x0806 代表 ARP 协议帧。
}EP_HEADER;


// Ipv4 header
/*
+-------+-----------+---------------+-------------------------+
| 4 bit     |   4 bit          |    8 bit               |          16 bit             |
+-------+-----------+---------------+-------------------------+
|version|head length|  TOS/DS_byte  |        total length     |
+-------------------+--+---+---+----+-+-+-+-------------------+
|          identification                                 |R|D|M|    offset    |
+-------------------+---------------+-+-+-+-------------------+
|       ttl                           |     protocol       |         checksum      |
+-------------------+---------------+-------------------------+
|                   source ip address                                                   |
+-------------------------------------------------------------+
|                 destination ip address                                              |
+-------------------------------------------------------------+
*/

typedef struct IPv4Header{
    u_char version_and_header_length;
    u_char TOS;
    u_short  total_length;
    u_short identification;
    u_short RDM_and_offset;
    u_char ttl;
    u_char protocol;//在传输层所使用的协议
    u_short checksum;
    u_int src_addr;
    u_int des_addr;
}IP_V4_HEADER;

// Tcp header
/*
+----------------------+---------------------+
|         16 bit                |       16 bit             |
+----------------------+---------------------+
|      source port        |  destination port|
+----------------------+---------------------+
|              sequence number                     |
+----------------------+---------------------+
|                 ack number                             |
+----+---------+-------+---------------------+
|head|reserve|flags|     window size    |
+----+---------+-------+---------------------+
|     checksum             |   urgent device   |
+----------------------+---------------------+
*/

typedef struct TCPHeader{
    u_short src_port;
    u_short des_port;
    u_int sequence_num;
    u_int ack_num;
    u_char header_length;//4bit
    u_char flags;//6bit
    u_short window_size;
    u_short checksum;
    u_short urgent_pointer;
}TCP_HEADER;

// Udp header
/*
+---------------------+---------------------+
|        16 bit                    |        16 bit                 |
+---------------------+---------------------+
|    source port              |   destination port  |
+---------------------+---------------------+
| data package length |       checksum      |
+---------------------+---------------------+
*/
typedef struct UDPHeader{
    u_short src_port;
    u_short des_port;
    u_short datagram_length;
    u_short checksum;
}UDP_HEADER;

// Icmp header
/*
+---------------------+---------------------+
|  1 byte  |  1 byte  |        2 byte       |
+---------------------+---------------------+
|   type   |   code   |       checksum      |
+---------------------+---------------------+
|    identification   |       sequence      |
+---------------------+---------------------+
|                  option                   |
+-------------------------------------------+
*/
typedef struct ICMPHeader{
    u_char type;//ICMP type
    u_char code;//Subtype to the given type.
    u_short checksum;
    u_short identification;
    u_short sequence;
}ICMP_HEADER;

//Arp
/*
|<--------  ARP header  ------------>|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
|2 byte| 2 byte |1byte| 1byte|2 byte |  6 byte  | 4 byte  |     6 byte    |     4 byte   |
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
| type |protocol|e_len|ip_len|op_type|source mac|source ip|destination mac|destination ip|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
*/

typedef struct ARPHeader{
    u_short hardware_type;
    u_short protocol;
    u_char mac_length;
    u_char ip_length;
    u_short op_type;
    u_char src_mac[6];
    u_char src_ip[4];
    u_char des_mac[6];
    u_char des_ip[4];
}ARP_HEADER;

// dns
/*
+--------------------------+---------------------------+
|           16 bit         |1b|4bit|1b|1b|1b|1b|3b|4bit|
+--------------------------+--+----+--+--+--+--+--+----+
|      identification      |QR| OP |AA|TC|RD|RA|..|Resp|
+--------------------------+--+----+--+--+--+--+--+----+
|         Question         |       Answer RRs          |
+--------------------------+---------------------------+
|     Authority RRs        |      Additional RRs       |
+--------------------------+---------------------------+
*/
typedef struct dns_header{  // 12 byte
    u_short identification; // Identification [2 byte]
    u_short flags;          // Flags [total 2 byte]
    u_short question;       // Question Number [2 byte]
    u_short answer;         // Answer RRs [2 byte]
    u_short authority;      // Authority RRs [2 byte]
    u_short additional;     // Additional RRs [2 byte]
}DNS_HEADER;

// dns question
typedef struct dns_question{
    // char* name;          // Non-fixed
    u_short query_type;     // 2 byte
    u_short query_class;    // 2 byte
}DNS_QUESITON;

typedef struct dns_answer{
    // char* name          // Non-fixed
    u_short answer_type;   // 2 byte
    u_short answer_class;  // 2 byte
    u_int TTL;             // 4 byte
    u_short dataLength;    // 2 byte
    //char* name           // Non-fixed
}DNS_ANSWER;

#endif //WIREWHALE_FORMAT_H
