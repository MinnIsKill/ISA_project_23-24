#ifndef DNS_H
#define DNS_H

#define _DEFAULT_SOURCE //beacause running -std=c99 prevents features.h (implicitly included in <unistd.h>) from defining _DEFAULT_SOURCE
#include <unistd.h> //gethostname(), sethostname()

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h> //working with threads

/**
 * @struct: structure for program's input parameters
*/
struct params{
    bool recursion; // [-r] (not received = recursion,
                    //       received = no recursion)
    bool reverse;   // [-x] (not received = direct request (we know hostname and want IP of host), 
                    //       received = reverse request (we know IP of host and want hostname)
    char IPversion[8]; // [-6] (not received = request of type A (IPv4),
                    //          received = request of type AAAA (IPv6))
    char server[128];  // -s server (IP address or hostname of server to which requests will be sent)
    unsigned int port; // [-p port] (not received = set to 53 by default,
                       //            received = set to number specified on input (from 0 to 65353))
    char address[128]; // address (address that is the object of query(request))
};
//global params struct declaration
struct params p = {.recursion = false, .reverse = false, .IPversion = "A", .server = "", .port = 53, .address = ""}; //create struct var


/** 
 * @function: string_firstnchars_remove
 * string chopper (currently no longer used)
 * 
 * @param addr: string to be chopped
 * @param num:  number of chars to remove
 */
char* string_firstnchars_remove( char *string, size_t num);

/** 
 * @function: is_it_IPv4
 * function for checking if string corresponds to IPv4 format
 * 
 * @param addr: string to be checked
 */
bool is_it_IPv4(char *addr);

/** 
 * @function: is_it_IPv6
 * function for checking if string corresponds to IPv6 format
 * 
 * @param addr: string to be checked
 */
bool is_it_IPv6(char *addr);

/** 
 * @function: is_it_hostname
 * function for checking hostname validity
 * 
 * @param host: string to be checked
 */
bool is_it_hostname(char *host);

/** 
 * @function: is_it_valid_port
 * function for checking port validity
 * 
 * @param port: port number to be checked
 */
bool is_it_valid_port(long port);

/** 
 * @function: parse_args
 * function for parsing input aguments
 * 
 * @param argc: arguments counter
 * @param argv: arguments pointer
 */
void parse_args(int argc, char *argv[]);

/**
 * @function: list_args
 * auxiliary function for listing all arguments saved after 'parse_args' function was run
 *
 * @param s: a params structure
 */
void list_args(struct params s);

#endif