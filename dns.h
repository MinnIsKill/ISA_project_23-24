#ifndef DNS_H
#define DNS_H

//#define _DEFAULT_SOURCE //beacause running -std=c99 prevents features.h (implicitly included in <unistd.h>) from defining _DEFAULT_SOURCE
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

//2D array of first 5 DNS servers found in /etc/resolv.conf file
char dns_list[5][50];

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

/**
 * @struct: Resource record structure
*/
struct dns_record_a_t{

	unsigned char *name;
    //uint16_t type;
    //uint16_t class;
    //uint32_t ttl;
    //uint16_t length;
    struct R_DATA_old *resource;
	unsigned char *rdata;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA_old
{
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t data_len;
};
#pragma pack(pop)

unsigned char* ReadName_old(unsigned char* reader,unsigned char* buffer,int* count);
void ChangetoDnsNameFormat_old(unsigned char* dns, unsigned char* host);


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
 * @function: parse_args
 * function for parsing input aguments
 * 
 * @param[in] argc: arguments counter
 * @param[in] argv: arguments pointer
 */
void parse_args(int argc, char *argv[]);

/**
 * @function: list_args
 * @brief auxiliary function for opening the '/etc/resolv.conf' file 
 * and load all found DNS servers into the pre-prepared
 * 'dns_list' 2D array
 */
void dns_servers_get();

/**
 * @function: DNS_Qtype_tostr
 * @brief Qtype integer to string converter
 * 
 * @param[in] Qtype: integer value of query type
 * @return string version of query type
 */
char* DNS_Qtype_tostr(uint16_t Qtype);

/**
 * @function: DNS_Qclass_tostr
 * @brief Qclass integer to string converter
 * 
 * @param[in] Qclass: integer value of query class
 * @return string version of query class
 */
char* DNS_Qclass_tostr(uint16_t Qclass);

/**
 * @function: list_args
 * @brief auxiliary function for listing all arguments saved after 'parse_args' function was run
 *
 * @param[in] s: a params structure
 */
void list_args(struct params s);

/**
 * @function: list_args
 * @brief auxiliary dns header contents print function
 *
 * @param[in] dns: a dns header structure
 */
void dns_header_fullprint(struct dns_header_t *dns);

/**
 * @function: list_args
 * @brief auxiliary dns header contents print function
 *
 * @param[in] dns: a dns header structure
 * @param[in] question: a question structure
 * @param[in] answers: a response record structure containing answer records
 * @param[in] auth: a response record structure containing authority records
 * @param[in] addit: a response record structure containing additional records
 */
void project_print(struct dns_header_t *dns, struct dns_question_t *question, struct dns_record_a_t *answers, struct dns_record_a_t *auth, struct dns_record_a_t *addit);

#endif