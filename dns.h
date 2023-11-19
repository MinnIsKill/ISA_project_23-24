/** @file:   dns.h
 *  @brief:  Project for ISA (network applications and management) VUTBR FIT 2023/24
 *  @author: Vojtěch Kališ (xkalis03)
 *  @last_edit: 18th November 2023  
**/

#ifndef DNS_H
#define DNS_H

#include <unistd.h> //gethostname(), sethostname()

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <regex.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h> //working with threads
#include <sys/time.h> //struct timeval
#include <net/if.h> //if_nametoindex
#include <ctype.h> //tolower()

/* DNS Qcodes and DNS header structure based on:
https://0x00sec.org/t/dns-header-for-c/618 */

/* DNS QTYPES */
#define DNS_QTYPE_A         1
#define DNS_QTYPE_NS		2
#define DNS_QTYPE_CNAME		5
#define DNS_QTYPE_SOA		6
#define DNS_QTYPE_PTR       12
#define DNS_QTYPE_MX		15
#define DNS_QTYPE_AAAA		28

/* DNS QCLASS */
#define DNS_QCLASS_RESERVED	0
#define DNS_QCLASS_IN		1
#define DNS_QCLASS_CH		3
#define DNS_QCLASS_HS		4
#define DNS_QCLASS_NONE		254
#define DNS_QCLASS_ANY		255

//OBSOLETE!!
//2D array of first 5 DNS servers found in /etc/resolv.conf file
//char dns_list[5][50];

/**
 * @struct: structure for program's input parameters
*/
struct params{
    bool recursion; /* [-r] (not received = recursion,
                            received = no recursion) */
    bool reverse;   /* [-x] (not received = direct request (we know hostname and want IP of host), 
                            received = reverse request (we know IP of host and want hostname) */
    unsigned int Qtype; /* [-6] (not received = request of type A (IPv4),
                                received = request of type AAAA (IPv6)) */
    char server[128];  /* -s server (IP address or domain name of server to which requests will be sent) */
    uint16_t port; /* [-p port] (not received = set to 53 by default,
                                    received = set to number specified on input (from 0 to 65353)) */
    char address[128]; /* address (address that is the object of query(request)) */
};
//global params struct declaration
struct params par = {.recursion = false, .reverse = false, .Qtype = DNS_QTYPE_A, .server = "", .port = 53, .address = ""}; //create struct var

/**
 * @struct: DNS header structure
 * 
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      ID                       |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    QDCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    ANCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    NSCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    ARCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct dns_header_t{
    uint16_t id;     /* Randomly chosen identifier */

    unsigned char rd :1;        /* Recursion Desired 
                                   this bit directs the name server to pursue the query recursively */
    unsigned char tc :1;        /* TrunCation
                                   specifies that this message was truncated */
    unsigned char aa :1;        /* Authoritative Answer 
                                   this bit is only meaningful in responses, and specifies that the 
                                   responding name server is an authority for the domain name in 
                                   question section */
    unsigned char opcode :4;    /* Message purpose 
                                   A four bit field that specifies the kind of query in this message */
    unsigned char qr :1;        /* Query/Response flag 
                                   A one bit field that specifies whether this message is a query (0), 
                                   or a response (1) */

    unsigned char rcode :4;     /* Response Code 
                                   0 = No error condition
                                   1 = Format error - The name server was unable to interpret the query
                                   2 = Server failure - The name server was unable to process this query 
                                       due to a problem with the name server
                                   3 = Name Error - Meaningful only for responses from an authoritative 
                                       name server, this code signifies that the domain name referenced 
                                       in the query does not exist
                                   4 = Not Implemented - The name server does not support the requested 
                                       kind of query
                                   5 = Refused - The name server refuses to perform the specified 
                                       operation for policy reasons */
    unsigned char cd :1;        /* Checking Disabled */
    unsigned char ad :1;        /* Authenticated Data */
    unsigned char z :1;         /* Reserved (has to be set to 0!) */
    unsigned char ra :1;        /* Recursion Available 
                                   set or cleared in a response, and denotes whether recursive query 
                                   support is available in the name server */

    uint16_t qdcount;  /* Number of questions */
    uint16_t ancount;  /* Number of answers */
    uint16_t nscount;  /* Number of authority records */
    uint16_t arcount;  /* Number of additional records */
};

/**
 * @struct: DNS question structure
*/
struct dns_question_t{
    uint16_t q_type;     /* The QTYPE (1 = A) */
    uint16_t q_class;    /* The QCLASS (1 = IN) */
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct record_data
{
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t data_len;
};
#pragma pack(pop)

/**
 * @struct: Resource record structure
*/
struct dns_record_a_t{

	unsigned char *name;
    //uint16_t type;
    //uint16_t class;
    //uint32_t ttl;
    //uint16_t length;
    struct record_data *resource;
	unsigned char *rdata;
};

/**
 * @struct: DNS replies structure
*/
struct dns_replies{
    struct dns_record_a_t answers[50];
    struct dns_record_a_t auth[50];
    struct dns_record_a_t addit[50];
};


/*************************************************
 *           AUXILIARY PRINT FUNCTIONS           *
*************************************************/
/** 
 * @function: helpmsg
 * @brief message printed when input arguments are invalid
 */
void helpmsg();

/**
 * @function: list_args
 * @brief auxiliary function for listing all arguments saved after 'parse_args' function was run
 *
 * @param[in] s: a params structure
 */
void list_args(struct params s);

/**
 * @function: dns_header_fullprint
 * @brief auxiliary dns header contents print function
 *
 * @param[in] dns: a dns header structure
 */
void dns_header_fullprint(struct dns_header_t *dns);

/**
 * @function: project_print
 * @brief prints received packet specifically in the format the assignment desires
 *
 * @param[in] dns:      pointer to start of dns header structure within packet buffer
 * @param[in] question: a question structure
 * @param[in] dns_rep:  a response record structure containing all (answer, authority, additional) records
 * @param[in] qname:    pointer to query name section of received packet
 */
void project_print(struct dns_header_t *dns, struct dns_question_t *question, 
                   struct dns_replies *dns_rep, unsigned char *qname);

/*************************************************
 *           AUXILIARY TASK FUNCTIONS            *
*************************************************/
/** 
 * @function: string_firstnchars_remove
 * @brief string chopper
 * 
 * @param[in] addr: string to be chopped
 * @param[in] num:  number of chars to remove
 * @return new string with removed chars
 */
char* string_firstnchars_remove( char *string, size_t num);

/** 
 * @function: is_it_IPv4
 * @brief function for checking if string corresponds to IPv4 format
 * 
 * @param[in] addr: string to be checked
 * @return 'true' if valid IPv4, 'false' if not
 */
bool is_it_IPv4(char *addr);

/** 
 * @function: is_it_IPv6
 * @brief function for checking if string corresponds to IPv6 format
 * 
 * @param[in] addr: string to be checked
 * @return 'true' if valid IPv6, 'false' if not
 */
bool is_it_IPv6(char *addr);

/** 
 * @function: is_it_hostname
 * @brief function for checking hostname validity
 * 
 * @param[in] host: string to be checked
 * @return 'true' if valid hostname, 'false' if not
 */
bool is_it_hostname(char *host);

/** 
 * @function: is_it_valid_port
 * @brief function for checking port validity
 * 
 * @param[in] port: port number to be checked
 * @return 'true' if valid port, 'false' if not
 */
bool is_it_valid_port(long port);

/**
 * @function: hostname_to_DNSname
 * @brief converts hostname to DNSname (www.google.com --> 3www6google3com0)
 * 
 * @param[in] host: hostname string to be converted
 * @param[in] dns:  string to save resulting DNSname into
 */
void hostname_to_DNSname(unsigned char *host, unsigned char *dns);

/**
 * @function: DNSname_to_hostname
 * @brief converts DNSname to hostname (3www6google3com0 --> www.google.com)
 * 
 * @param[in] str: string to convert
 */
void DNSname_to_hostname(unsigned char *str);

/**
 * @function: DNS_Qtype_tostr
 * @brief Qtype short to string converter
 * 
 * @param[in] Qtype: short value of query type
 * @return string version of query type
 */
char* DNS_Qtype_tostr(uint16_t Qtype);

/**
 * @function: DNS_Qclass_tostr
 * @brief Qclass short to string converter
 * 
 * @param[in] Qclass: short value of query class
 * @return string version of query class
 */
char* DNS_Qclass_tostr(uint16_t Qclass);

/**
 * @function: dec_to_hex_IPv6
 * @brief function that takes IPv6 in decimal form and transforms it into an actual IPv6 (hexa)
 * 
 * @param[in] input_string:  string containing the decimal form of an IPv6
 * @param[in] output_string: string to save the hexa form of an IPv6 into
 * @param[in] length:        length of @param input_string
 * @return hexa form of IPv6 saved in @param output_string
 */
char* dec_to_hex_IPv6(unsigned char *input_string, char* output, int length);

/**
 * @function: read_compressed_name
 * @brief read compressed name from a dns record
 * 
 * @param[in] reader: pointer to where compressed name is in @param buffer
 * @param[in] buffer: buffer string containing the whole packet reply
 * @param[in] count:  jump counter
 * 
 * @return string containing the decompressed name
 */
unsigned char* read_compressed_name(unsigned char* reader, unsigned char* buffer, int* count);

/**
 * @function: switch_bytes
 * @brief switch: first 4 bits of byte #1 with last 4 bits of byte #2
 *           and  last 4 bits of byte #1 with first 4 bits of byte #2
 * 
 * @param[in] first_field:  pointer to first byte
 * @param[in] second_field: pointer to second byte
 */
void switch_bytes(uint8_t *first_field, uint8_t *second_field);

/**
 * @function: clean_exit
 * @brief free all memory allocated during program run
 * 
 * @param[in] dns:     pointer to start of dns header structure within packet buffer
 * @param[in] dns_rep: pointer to dns replies structure
 */
void clean_exit(struct dns_header_t *dns, struct dns_replies *dns_rep);


/*************************************************
 *          INTERNAL PROGRAM FUNCTIONS           *
*************************************************/
/** 
 * @function: parse_args
 * function for parsing input aguments
 * 
 * @param[in] argc: arguments counter
 * @param[in] argv: arguments pointer
 * 
 * @return 0 if successful, 1 if error occured
 */
int parse_args(int argc, char *argv[]);

/**
 * @function: list_args
 * @brief auxiliary function for opening the '/etc/resolv.conf' file 
 * and load all found DNS servers into the pre-prepared
 * 'dns_list' 2D array
 */
void dns_servers_get();

//function for socket preparation
/**
 * @function: sock_prep
 * @brief function for socket preparation
 * 
 * @param[in] sockfd: pointer to socket
 * @param[in] dest:   IPv4 socket address structure (for if we're working with IPv4)
 * @param[in] dest6:  IPv6 socket address structure (for if we're working with IPv4)
*/
void sock_prep(int *sockfd, struct sockaddr_in *dest, struct sockaddr_in6 *dest6);

/**
 * @function: dns_pack_prep
 * @brief function for dns packet preparation
 * 
 * @param[in] dns: pointer to start of dns header structure withing packet buffer
*/
void dns_pack_prep(struct dns_header_t *dns);

/**
 * @function: dns_qname_insert
 * @brief resolves query hostname into DNSname and saves it into buffer. Also handles reverse DNS query
 * 
 * @param[in] qname: query hostname to be resolved/converted
*/
void dns_qname_insert(unsigned char *qname);

/**
 * @function: dns_qinfo_prep
 * @brief prepares query info
 * 
 * @param[in] qinfo:  pointer to query info structure (within packet buffer)
 * @param[in] qtype:  query type to set
 * @param[in] qclass: query class to set
*/
void dns_qinfo_prep(struct dns_question_t *qinfo, uint32_t qtype, uint32_t qclass);

/**
 * @function: dns_reply_load
 * @brief fills pre-prepared reply arrays with received data
 * 
 * @param[in] buf:     buffer holding whole packet reply
 * @param[in] reader:  pointer to where answer data starts in @param buf
 * @param[in] dns:     pointer to where dns header structure starts in @param buf
 * @param[in] dns_rep: pointer to where dns replies structure starts in @param buf
*/
void dns_reply_load(unsigned char *buf, unsigned char *reader, struct dns_header_t *dns, struct dns_replies *dns_rep);

#endif