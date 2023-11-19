/** @file:   dns.c
 *  @brief:  Project for ISA (network applications and management) VUTBR FIT 2023/24
 *  @author: Vojtěch Kališ (xkalis03)
 *  @last_edit: 18th November 2023  
**/

#include "dns.h"

/*************************************************
 *           AUXILIARY PRINT FUNCTIONS           *
*************************************************/
//helpmsg function
void helpmsg(){
    fprintf(stdout, 
    "--- dns.c ---\r\n"
    "usage:  dns [-r] [-x] [-6] -s server [-p port] address\r\n"
    "where:  [-r] = recursion desired\r\n"
    "        [-x] = make reverse request instead of direct request\r\n"
    "               (reverse request requires 'server' to be an address)\r\n"
    "               (incompatible with '-6')\r\n"
    "        [-6] = make request of type AAAA instead of default A\r\n"
    "               (inpompatible with '-x')\r\n"
    "         -s server = IP or hostname of server to which request will be sent\r\n"
    "        [-p port]  = port number to use\r\n"
    "                     (set to 53 by default)\r\n"
    "         address   = address that is the object of query(request)\r\n");
}

//auxiliary param print function
void list_args(struct params s){
    fprintf(stdout, "recursion: %d\r\n", s.recursion);
    fprintf(stdout, "reverse:   %d\r\n", s.reverse);
    fprintf(stdout, "Qtype:     %d\r\n", s.Qtype);
    fprintf(stdout, "server:    %s\r\n", s.server);
    fprintf(stdout, "port:      %d\r\n", s.port);
    fprintf(stdout, "address:   %s\r\n", s.address);
}

//auxiliary dns header contents print function
void dns_header_fullprint(struct dns_header_t *dns){
    fprintf(stdout,"\n\r===========================================\n\r");
    fprintf(stdout,"Full content print of a dns_header_t struct\n\r");

    fprintf(stdout,"\n\r ID:                 %d\n\r", ntohs(dns->id)); //randomly generated id

    fprintf(stdout," Query=0|Response=1: %d\n\r", dns->qr); //0 = query, 1 = answer
    fprintf(stdout," Query opcode(type): %d\n\r", dns->opcode); //0 = standard query
    fprintf(stdout," Authoritative ans:  %d\n\r", dns->aa); //0 = authoritative
    fprintf(stdout," Message Truncated:  %d\n\r", dns->tc); //0 = not truncated
    fprintf(stdout," Recursion Desired:  %d\n\r", dns->rd); //1 = recursion desired

    fprintf(stdout," Response code:      %d\n\r", dns->rcode);
    //fprintf(stdout," dns->z:         %d\n\r", dns->z); //reserved
    fprintf(stdout," Recursion available:%d\n\r", dns->ra); //1 = recursion available

    if (dns->qr == 1){ //if this is a response
        fprintf(stdout,"\n\rThis response contains:\n\r");
        fprintf(stdout," %d Questions\n\r",ntohs(dns->qdcount));
        fprintf(stdout," %d Answers\n\r",ntohs(dns->ancount));
        fprintf(stdout," %d Authoritative Servers\n\r",ntohs(dns->nscount));
        fprintf(stdout," %d Additional Records\n\r",ntohs(dns->arcount));
        fprintf(stdout,"===========================================\n\r");
    }
}

//prints received packet specifically in the format the assignment desires
void project_print(struct dns_header_t *dns, struct dns_question_t *question, 
                   struct dns_replies *dns_rep, unsigned char *qname){
  //first line
    fprintf(stdout, "Authoritative: ");
    (dns->aa == 0) ? fprintf(stdout, "No, ") : fprintf(stdout, "Yes, ");
    fprintf(stdout, "Recursive: ");
    (dns->ra == 1 && par.recursion == 1) ? fprintf(stdout, "Yes, ") : fprintf(stdout, "No, ");
    fprintf(stdout, "Truncated: ");
    (dns->tc) == 0 ? fprintf(stdout, "No\n\r") : fprintf(stdout, "Yes\n\r");
  //question section
    fprintf(stdout, "Question Section(%d)\n\r", ntohs(dns->qdcount));
    for (uint16_t i = ntohs(dns->qdcount); i > 0; i--){
        fprintf(stdout, " %s., %s, %s\n\r", qname, DNS_Qtype_tostr(ntohs(question->q_type)), DNS_Qclass_tostr(ntohs(question->q_class)));
    }

  //prep for rest of sections
    long *p;
    char ipaddr[128];
    //char a6string[INET6_ADDRSTRLEN];
    struct sockaddr_in a;
    //struct sockaddr_in6 a6;
    
  //answer section
    fprintf(stdout, "Answer Section(%d)\n\r", ntohs(dns->ancount));
    for (uint16_t i = 0; i < ntohs(dns->ancount); i++){
        fprintf(stdout, " %s., %s, %s, %u", dns_rep->answers[i].name, 
                                     DNS_Qtype_tostr(ntohs(dns_rep->answers[i].resource->type)), 
                                     DNS_Qclass_tostr(ntohs(dns_rep->answers[i].resource->class)), 
                                     htonl(dns_rep->answers[i].resource->ttl));
        // A
        if (strcmp(DNS_Qtype_tostr(ntohs(dns_rep->answers[i].resource->type)), "A") == 0){
            p=(long*)dns_rep->answers[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            fprintf(stdout, ", %s\n\r",inet_ntoa(a.sin_addr));
        // AAAA
        } else if (strcmp(DNS_Qtype_tostr(ntohs(dns_rep->answers[i].resource->type)), "AAAA") == 0){
            dec_to_hex_IPv6(dns_rep->answers[i].rdata, ipaddr, (int)ntohs(dns_rep->answers[i].resource->data_len));
            fprintf(stdout, ", %s\n\r", ipaddr);
        // CNAME
        } else if (strcmp(DNS_Qtype_tostr(ntohs(dns_rep->answers[i].resource->type)), "CNAME") == 0){
            fprintf(stdout, ", %s\n\r",dns_rep->answers[i].rdata);
        // ELSE
        } else {
            fprintf(stdout, ", %s\n\r",dns_rep->answers[i].rdata);
        }
    }
  //authority section
    fprintf(stdout, "Authority Section(%d)\n\r", ntohs(dns->nscount));
    for (uint16_t i = 0; i < ntohs(dns->nscount); i++){
        fprintf(stdout, " %s., %s, %s, %u", dns_rep->auth[i].name, 
                                     DNS_Qtype_tostr(ntohs(dns_rep->auth[i].resource->type)), 
                                     DNS_Qclass_tostr(ntohs(dns_rep->auth[i].resource->class)), 
                                     htonl(dns_rep->auth[i].resource->ttl));
        // A
        if (strcmp(DNS_Qtype_tostr(ntohs(dns_rep->auth[i].resource->type)), "A") == 0){
            p=(long*)dns_rep->auth[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            fprintf(stdout, ", %s\n\r",inet_ntoa(a.sin_addr));
        // AAAA
        } else if (strcmp(DNS_Qtype_tostr(ntohs(dns_rep->auth[i].resource->type)), "AAAA") == 0){
            dec_to_hex_IPv6(dns_rep->auth[i].rdata, ipaddr, (int)ntohs(dns_rep->auth[i].resource->data_len));
            fprintf(stdout, ", %s\n\r", ipaddr);
        // CNAME
        } else if (strcmp(DNS_Qtype_tostr(ntohs(dns_rep->auth[i].resource->type)), "CNAME") == 0){
            fprintf(stdout, ", %s\n\r",dns_rep->auth[i].rdata);
        // ELSE
        } else {
            fprintf(stdout, ", %s\n\r",dns_rep->auth[i].rdata);
        }
    }
  //additional section
    fprintf(stdout, "Additional Section(%d)\n\r", ntohs(dns->arcount));
    for (uint16_t i = 0; i < ntohs(dns->arcount); i++){
        fprintf(stdout, " %s., %s, %s, %u", dns_rep->addit[i].name, 
                                     DNS_Qtype_tostr(ntohs(dns_rep->addit[i].resource->type)), 
                                     DNS_Qclass_tostr(ntohs(dns_rep->addit[i].resource->class)), 
                                     htonl(dns_rep->addit[i].resource->ttl));
        // A
        if (strcmp(DNS_Qtype_tostr(ntohs(dns_rep->addit[i].resource->type)), "A") == 0){
            p=(long*)dns_rep->addit[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            fprintf(stdout, ", %s\n\r",inet_ntoa(a.sin_addr));
        // AAAA
        } else if (strcmp(DNS_Qtype_tostr(ntohs(dns_rep->addit[i].resource->type)), "AAAA") == 0){
            dec_to_hex_IPv6(dns_rep->addit[i].rdata, ipaddr, (int)ntohs(dns_rep->addit[i].resource->data_len));
            fprintf(stdout, ", %s\n\r", ipaddr);
        // CNAME
        } else if (strcmp(DNS_Qtype_tostr(ntohs(dns_rep->addit[i].resource->type)), "CNAME") == 0){
            fprintf(stdout, ", %s\n\r",dns_rep->addit[i].rdata);
        // ELSE
        } else {
            fprintf(stdout, ", %s\n\r",dns_rep->addit[i].rdata);
        }
    }
}

/*************************************************
 *           AUXILIARY TASK FUNCTIONS            *
*************************************************/
//string chopper (no longer used)
char* string_firstnchars_remove( char *string, size_t num){
    char *src = string;

    if (num <= strlen(string)){
        while (*src && num){
            ++src;
            --num;
        }
        for (char *dst = string; (*dst++ = *src++); ){}
    }

    return string;
}

//IPv4 validity checker
bool is_it_IPv4(char *addr){
    struct sockaddr_in tmp;
    int result;
    if ((result = inet_pton(AF_INET, addr, &(tmp.sin_addr))) == 1){
        return true;
    } else {
        return false;
    }
}

//IPv6 validity checker
bool is_it_IPv6(char *addr){
    struct sockaddr_in6 tmp;
    int result;
    if ((result = inet_pton(AF_INET6, addr, &(tmp.sin6_addr))) > 0){
        return true;
    } else {
        return false;
    }
}

//host validity checker
bool is_it_hostname(char *host){
    regex_t reg;
    if ((regcomp(&reg, "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$", REG_EXTENDED)) != 0){
        fprintf(stderr, "INTERNAL ERROR: regcomp() failure\r\n");
        exit(1);
    } else {
        if (regexec(&reg, host, 0, NULL, 0) != 0){
            regfree(&reg);
            return false;
        } else {
            regfree(&reg);
            return true;
        }
    }
}

//port validity checker
bool is_it_valid_port(long port){
    if ((port >= 0) && (port <= 65535)){
        return true;
    } else {
        return false;
    }
}

//convert hostname to DNSname (www.google.com --> 3www6google3com0)
void hostname_to_DNSname(unsigned char *host, unsigned char *dns){
	int pos = 0;
	int len = 0;

	strcat((char *)host, ".");

	for(int i = 0; i < (int)strlen((char *)host); i++){
		if(host[i] == '.'){
			dns[pos] = i - len;
			++pos;
            while (len < i){
				dns[pos] = host[len];
				++pos;
                ++len;
            }
			++len;
		}
	}
	dns[pos] = '\0';
}

//convert DNSname to hostname (3www6google3com0 --> www.google.com)
void DNSname_to_hostname(unsigned char *str){
    int i, j;

	for(i = 0; i < (int)strlen((const char*)str); i++){
		int len = (int)str[i]; //get the number
		for(j = 0; j < len; j++){ //move everything to the left
			str[i] = str[i + 1];
			i++;
		}
		str[i] = '.';
	}
	str[i - 1] = '\0';
}

//Qtype integer to string converter
char* DNS_Qtype_tostr(uint16_t Qtype){
    switch (Qtype){
        case (DNS_QTYPE_A):
            return "A";
        case (DNS_QTYPE_AAAA):
            return "AAAA";
        case (DNS_QTYPE_CNAME):
            return "CNAME";
        case (DNS_QTYPE_SOA):
            return "SOA";
        case (DNS_QTYPE_NS):
            return "NS";
        case (DNS_QTYPE_MX):
            return "MX";
        case (DNS_QTYPE_PTR):
            return "PTR";
        default:
            return "UNKNOWN";
    }
}

//Qclass integer to string converter
char* DNS_Qclass_tostr(uint16_t Qclass){
    switch (Qclass){
        case (DNS_QCLASS_RESERVED):
            return "RESERVED";
        case (DNS_QCLASS_IN):
            return "IN";
        case (DNS_QCLASS_CH):
            return "CH";
        case (DNS_QCLASS_HS):
            return "HS";
        case (DNS_QCLASS_NONE):
            return "NONE";
        case (DNS_QCLASS_ANY):
            return "ANY";
        default:
            return "UNKNOWN";
    }
}

//function that takes IPv6 in decimal form and transforms it into an actual IPv6 (hexa)
char* dec_to_hex_IPv6(unsigned char *input_string, char* output, int length){
    char save[3];
    output[0] = '\0';
    bool doubledot = false;
    int pos = 0;
    for (int i = 0; i < length; ++i){
        sprintf(save, "%02X", (uint16_t)(input_string[i]));
        strcat(output, save);
        pos += 2;
        if (doubledot == true && length-i != 1){ 
            strcat(output, ":"); 
            doubledot=false; 
            pos += 1;
        } else { 
            doubledot=true; 
        }
    }
    //now convert it to shortened IPv6
    struct in6_addr addr;
    inet_pton(AF_INET6, (const char *)output, &addr);
    inet_ntop(AF_INET6, &addr, output, strlen(output));
    return output;
}

//read compressed name from a dns record
unsigned char* read_compressed_name(unsigned char* reader, unsigned char* buffer, int* count){
	unsigned char *name = (unsigned char*)malloc(256);
    unsigned int offset;
    bool jumped = false;

	*count = 1;

    int length = 0;
    //this next part deals with dns compression - http://www.tcpipguide.com/free/t_DNSNameNotationandMessageCompressionTechnique-2.htm
    //in the Name field of the answer record, we would instead put two "1" bits, followed by the number 47 encoded in binary
    //so:   11000000 00101111
	while (*reader != 0){
		if (*reader < 192){ //(192)dec = (11000000)bin
			name[length++] = *reader;
		} else {
			offset = (*reader)*256 + *(reader+1); //calculate where to jump to the new location
            //now get rid of MSBs
            offset -= 49152; //(49152)dec = (11000000 00000000)bin
            //now jump to the new location
			reader = buffer + offset - 1;
			jumped = true; //we have jumped to another location
		}

		reader += 1;

		if(jumped == false){
			*count = *count + 1; //if we havent jumped to another location then we can count up
		}
	}
	if(jumped == true){
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}

	name[length] = '\0'; //string complete

	//we have a DNSname, now convert it into hostname
    DNSname_to_hostname(name);

	return name;
}

//switch: first 4 bits of byte #1 with last 4 bits of byte #2
//   and  last 4 bits of byte #1 with first 4 bits of byte #2
void switch_bytes(uint8_t *first_field, uint8_t *second_field){
    uint8_t tmp = 0;

    //switch first 4 and last 4 bits of bytes
    *first_field = ((*first_field & 0xf0) >> 4) | ((*first_field & 0x0f) << 4);
    *second_field = ((*second_field & 0xf0) >> 4) | ((*second_field & 0x0f) << 4);

    tmp = (*first_field & 0xff); //save first byte

    //now switch the bytes
    *first_field = (*second_field & 0xff); //copy second byte to first byte
    *second_field = (tmp & 0xff); //copy tmp to second byte
}

//free all memory allocated during program run
void clean_exit(struct dns_header_t *dns, struct dns_replies *dns_rep){
    //free answers
	for(int i = 0; i < ntohs(dns->ancount); i++){
        free(dns_rep->answers[i].name);
        free(dns_rep->answers[i].rdata);
	}

	//free authorities
	for(int i = 0; i < ntohs(dns->nscount); i++){
        free(dns_rep->auth[i].name);
        free(dns_rep->auth[i].rdata);
	}

	//free additional
	for(int i = 0; i < ntohs(dns->arcount); i++){
        free(dns_rep->addit[i].name);
        free(dns_rep->addit[i].rdata);
	}
}


/*************************************************
 *          INTERNAL PROGRAM FUNCTIONS           *
*************************************************/
//arguments parser
int parse_args(int argc, char *argv[]){
    if (argc < 4){
        fprintf(stderr,"ERROR: insufficient amount of arguments received\r\n");
        helpmsg();
        return 1;
    } else if (argc > 9){
        fprintf(stderr,"ERROR: too many arguments received\r\n");
        helpmsg();
        return 1;
    }

    int c;
    long num;
    while((c = getopt(argc, argv, ":rx6s:p:")) != -1){
        switch(c){
            case 'r':
                par.recursion = true;
                break;
            case 'x':
                par.reverse = true;
                break;
            case '6':
                par.Qtype = DNS_QTYPE_AAAA;
                break;
            case 's':
                if (is_it_hostname(optarg) || is_it_IPv4(optarg) || is_it_IPv6(optarg)){
                    strcpy(par.server, optarg);
                    break;             
                } else {
                    fprintf(stderr, "ERROR: invalid hostname received: %s\r\n", optarg);
                    return 1;
                }
            case 'p':
                num = strtol(optarg, NULL, 0);
                if (is_it_valid_port(num)){
                    par.port = (uint16_t)num;
                    break;
                } else {
                    fprintf(stderr, "ERROR: invalid port number: %s\r\n", optarg);
                    return 1;
                }
            case ':': //-s or -p without operand
                fprintf(stderr, "ERROR: option -%c requires an operand\r\n", optopt);
                helpmsg();
                return 1;
            case '?':
                fprintf(stderr, "ERROR: unknown argument found: %c\r\n", optopt);
                helpmsg();
                return 1;
        }
    }

    //getopt won't find 'address', so we have to do that manually
    for (int i = 1; i < argc; i++){
        if (strncmp(argv[i], "-", 1) == 0){ //find only arguments which begin with '-' and skip those
            if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "-p") == 0){ //in case of '-s' and '-p', skip their operand as well
                i++;
            }
        } else { //we found potential address
            if (strcmp(par.address, "") == 0){ //if address is still empty
                if (is_it_IPv4(argv[i]) || is_it_IPv6(argv[i]) || is_it_hostname(argv[i])){ //is it an actual address?
                    strcpy(par.address, argv[i]);
                } else {
                    fprintf(stderr, "ERROR: found unknown argument or invalid address: %s\r\n", argv[i]);
                    helpmsg();
                    return 1;
                }
            } else {
                fprintf(stderr, "ERROR: unknown argument found: %s\r\n", argv[i]);
                helpmsg();
                return 1;
            }
        }
    }

    //if either 'server' or 'address' is missing
    if (strcmp(par.address, "") == 0 || strcmp(par.server, "") == 0){
        fprintf(stderr, "ERROR: the 'server' and 'address' parameters are required\r\n");
        helpmsg();
        return 1;
    }

    //if '-x' and '-6' are set ('-x' expects to send a packet of type 'PTR', but '-6' demands a packet of type 'AAAA' is sent - those are directly contradictory)
    if (par.Qtype == DNS_QTYPE_AAAA && par.reverse == true){
        fprintf(stderr, "ERROR: '-x' and '-6' parameters are incompatible - the former requires query type 'PTR', while the latter 'AAAA'\r\n");
        helpmsg();
        return 1;
    }

    //if reverse DNS lookup wanted, check 'address' is IPv4 or IPv6 
    //(because reverse DNS lookup doesn't make sense to do for hostname)
    if (is_it_IPv4(par.address) == false && is_it_IPv6(par.address) == false && par.reverse == true){
        fprintf(stderr, "WARNING: nonsensical argument combination detected: attempt at reverse DNS lookup using hostname; the program will do nothing\r\n");
        helpmsg();
        return 1;
    }

    return 0;
}

//OBSOLETE!!
//DNS servers loader (no longer used)
/**void dns_servers_get(){
    FILE *fp;
    char line_buff[100];
    uint16_t DNS_cnt = 0;
    bool DNS_found_flag = 0;

    if ((fp = fopen("/etc/resolv.conf", "r")) == NULL){
        fprintf(stderr,"ERROR:  /etc/resolv.conf couldn't be opened\r\n");
        exit(1);
    } else {
        while(fgets(line_buff, 100, fp)){
            if (strncmp(line_buff, "nameserver", 10) == 0){
                if (DNS_found_flag == 0){
                    DNS_found_flag = 1;
                }
                string_firstnchars_remove(line_buff, 11); //remove 'nameserver' from start of line
                line_buff[strlen(line_buff)-1] = '\0'; //remove 'newline' from end of line
                strcpy(dns_list[DNS_cnt], line_buff);
                DNS_cnt++;
            }
            if (DNS_cnt == 5){ //5 DNS servers should be enough
                return;
            }
        }
        if (DNS_found_flag == 0){
            fprintf(stderr,"ERROR:   /etc/resolv.conf contains no DNS servers\r\n");
            exit(1);
        }
    }
}**/

//function for socket preparation
void sock_prep(int *sockfd, struct sockaddr_in *dest, struct sockaddr_in6 *dest6){
  //prepare socket
    struct timeval timeout; //for setting socket 'recvfrom' timeout
    timeout.tv_sec  = 10; //set timeout to 10 seconds
    timeout.tv_usec = 0;

    if (is_it_IPv6(par.server)){ //IPv6
	    *sockfd = socket(PF_INET6, SOCK_DGRAM, 0); //UDP packet for DNS queries
    } else {
        *sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //UDP packet for DNS queries
    }

    if (setsockopt (*sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0){ //set sendto timeout
        perror("ERROR: setsockopt failure");
        exit(1);
    }
    if (setsockopt (*sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0){ //set recvfrom timeout
        perror("ERROR: setsockopt failure");
        exit(1);
    }

  //prepare IPv4 or IPv6 address
    if (is_it_IPv6(par.server)){ //IPv6
        dest6->sin6_family = AF_INET6;
	    dest6->sin6_port = htons(par.port);
        dest6->sin6_flowinfo = 0;

        struct in6_addr addr;
        inet_pton(AF_INET6, (const char *)par.server, &addr);
        struct hostent *hp = gethostbyaddr(&addr, sizeof(addr), AF_INET6);
        if (hp == NULL){ //if gethostname() wasn't successful in retrieving server info
            fprintf(stderr, "ERROR: couldn't resolve 'server' hostname, make sure it is accessible and written correctly\r\n");
            exit(1);
        }
        unsigned char tmp[1024];
        hostname_to_DNSname((unsigned char *)hp->h_name, tmp);
        dest6->sin6_scope_id = if_nametoindex((const char *)tmp);

        inet_pton(AF_INET6, par.server, &(dest6->sin6_addr));
    } else { //IPv4 or hostname
        dest->sin_family = AF_INET;
	    dest->sin_port = htons(par.port);
        if (is_it_IPv4(par.server)){ //IPv4
            inet_pton(AF_INET, par.server, &(dest->sin_addr));
        } else {
            struct hostent *hp = gethostbyname(par.server);
            if (hp == NULL){ //if gethostname() wasn't successful in retrieving server info
                fprintf(stderr, "ERROR: couldn't resolve 'server' hostname, make sure it is accessible and written correctly\r\n");
                exit(1);
            }
            memcpy(&dest->sin_addr, hp->h_addr_list[0], hp->h_length);
        }
    }
}

//function for dns packet preparation
void dns_pack_prep(struct dns_header_t *dns){
	dns->id = (unsigned short) htons(getpid());

	dns->qr = 0;     //query
	dns->opcode = 0; //standard query
	dns->aa = 0;     //not Authoritative
	dns->tc = 0;     //not Truncated
    dns->rd = 0;     //no Recursion Desired

	dns->ra = 0;     //no Recursion Available
	dns->z = 0;      //reserved
    dns->ad = 0;
    dns->cd = 0;
	dns->rcode = 0;  //this isn't a response (so no response code) 

	dns->qdcount = htons(1); //one question
	dns->ancount = 0; //no answer records yet
	dns->nscount = 0; //no authoritative records yet
	dns->arcount = 0; //no additional records yet
}

//resolves query hostname into DNSname and saves it into buffer
void dns_qname_insert(unsigned char *qname){
  //if reverse DNS lookup
    if (par.reverse){ //transform name into reverse lookup format instead
        //(e.g.:  147.229.8.12  -->  12.8.229.147.in-addr.arpa,
        //        2001:67c:1220:809::93e5:917  -->  7.1.9.0.5.e.3.9.0.0.0.0.0.0.0.0.9.0.8.0.0.2.2.1.c.7.6.0.1.0.0.2.ip6.arpa,
        //        www.fit.vutbr.cz  -->  23.9.229.147.in-addr.arpa)

        if (is_it_IPv4(par.address)){ //147.229.8.12  -->  12.8.229.147.in-addr.arpa
            struct in_addr addr;
            char reversed_ip[32]; //an IP is a 32-bit unsigned integer
            inet_pton(AF_INET, (const char *)par.address, &addr);
            //revert the bytes
            addr.s_addr = ((addr.s_addr & 0xff000000) >> 24) | 
                          ((addr.s_addr & 0x00ff0000) >>  8) | 
                          ((addr.s_addr & 0x0000ff00) <<  8) |
                          ((addr.s_addr & 0x000000ff) << 24);
            inet_ntop(AF_INET, &addr, reversed_ip, sizeof(reversed_ip));
            strcat(reversed_ip, ".in-addr.arpa"); //add .in-addr.arpa
            hostname_to_DNSname((unsigned char *)reversed_ip, qname);
        } else if (is_it_IPv6(par.address)){ //2001:67c:1220:809::93e5:917  -->  7.1.9.0.5.e.3.9.0.0.0.0.0.0.0.0.9.0.8.0.0.2.2.1.c.7.6.0.1.0.0.2.ip6.arpa
            struct in6_addr addr;
            char reversed_ip6[128];
            reversed_ip6[0] = '\0';

            inet_pton(AF_INET6, (const char *)par.address, &addr);
            //revert the bytes
            for (int i = 0; i < 8; i++){
                switch_bytes(&addr.s6_addr[i], &addr.s6_addr[15-i]);
            }
            //save 'XX.XX.XX.XX...' as 'C.C.C.C.C.C.C.C...'
            char save[3];
            char save2[3];
            for (int i = 0; i < 16; i++){
                //XY -> X.Y.
                //X.
                sprintf(save, "%02X", addr.s6_addr[i]);
                save[1] = '.';
                strcat(reversed_ip6, save);
                //Y.
                sprintf(save2, "%02X", addr.s6_addr[i]);
                string_firstnchars_remove(save2, 1);
                strcat(save2, ".");
                strcat(reversed_ip6, save2);
            }
            //set string to lowercase
            for(int i = 0; reversed_ip6[i]; i++){
                reversed_ip6[i] = tolower(reversed_ip6[i]);
            }
            //add ".ip6.arpa"
            strcat(reversed_ip6, "ip6.arpa"); //add .in-addr.arpa

            hostname_to_DNSname((unsigned char *)reversed_ip6, qname);
        }
        return;
    }

  //else
    if (is_it_IPv4(par.address)){
        struct in_addr addr;
        inet_aton((const char *)par.address, &addr);
        struct hostent *hp = gethostbyaddr(&addr, sizeof(addr), AF_INET);
        if (hp == NULL){ //if gethostname() wasn't successful in retrieving server info
            fprintf(stderr, "ERROR: couldn't resolve 'address' hostname, make sure it is accessible and written correctly\r\n");
            exit(1);
        }
        hostname_to_DNSname((unsigned char *)hp->h_name, qname); //segfault
    } else if (is_it_IPv6(par.address)){
        struct in6_addr addr;
        inet_pton(AF_INET6, (const char *)par.address, &addr);
        struct hostent *hp = gethostbyaddr(&addr, sizeof(addr), AF_INET6);
        if (hp == NULL){ //if gethostname() wasn't successful in retrieving server info
            fprintf(stderr, "ERROR: couldn't resolve 'address' hostname, make sure it is accessible and written correctly\r\n");
            exit(1);
        }
        hostname_to_DNSname((unsigned char *)hp->h_name, qname);
    } else if (is_it_hostname(par.address)){
        struct hostent *hp = gethostbyname((const char *)par.address);
        if (hp == NULL){ //if gethostname() wasn't successful in retrieving address info
            fprintf(stderr, "ERROR: couldn't resolve 'address' hostname, make sure it is accessible and written correctly\r\n");
            exit(1);
        }
        hostname_to_DNSname((unsigned char *)par.address, qname);
    } else { //shouldn't happen; we've already checked in function 'parse_args'
        fprintf(stderr, "ERROR:  the 'address' parameter has to be a hostname or an IP address\n\r");
        exit(1);
    }
}

//prepares query info
void dns_qinfo_prep(struct dns_question_t *qinfo, uint32_t qtype, uint32_t qclass){
	qinfo->q_type = htons((int)qtype);   //qtype (A, AAAA, CNAME,...)
	qinfo->q_class = htons((int)qclass); //qclass (IN, CH, HS,...)
}

//fills pre-prepared reply arrays with received data
void dns_reply_load(unsigned char *buf, unsigned char *reader, struct dns_header_t *dns, struct dns_replies *dns_rep){
	int stop = 0;

    //start reading answers
	for(int i = 0; i < ntohs(dns->ancount); i++){
		dns_rep->answers[i].name = read_compressed_name(reader, buf, &stop);
		reader = reader + stop;

		dns_rep->answers[i].resource = (struct record_data*)(reader);
		reader = reader + sizeof(struct record_data);

		if (strcmp(DNS_Qtype_tostr(ntohs(dns_rep->answers[i].resource->type)), "A") == 0 ||    //if it's an ipv4
            strcmp(DNS_Qtype_tostr(ntohs(dns_rep->answers[i].resource->type)), "AAAA") == 0){  //or ipv6 address
			dns_rep->answers[i].rdata = (unsigned char*)malloc(ntohs(dns_rep->answers[i].resource->data_len+1));

			for(int j = 0; j < ntohs(dns_rep->answers[i].resource->data_len); j++){
				dns_rep->answers[i].rdata[j]=reader[j];
			}

			dns_rep->answers[i].rdata[ntohs(dns_rep->answers[i].resource->data_len)] = '\0';

			reader = reader + ntohs(dns_rep->answers[i].resource->data_len);
		} else {
			dns_rep->answers[i].rdata = read_compressed_name(reader, buf, &stop);
			reader = reader + stop;
		}
	}

    //read authorities
	for(int i = 0; i < ntohs(dns->nscount); i++){
		dns_rep->auth[i].name = read_compressed_name(reader, buf, &stop);
		reader+=stop;

		dns_rep->auth[i].resource=(struct record_data*)(reader);
		reader+=sizeof(struct record_data);

		dns_rep->auth[i].rdata = read_compressed_name(reader, buf, &stop);
		reader += stop;
	}

    //read additional
	for(int i = 0; i < ntohs(dns->arcount); i++){
		dns_rep->addit[i].name = read_compressed_name(reader, buf, &stop);
		reader+=stop;

		dns_rep->addit[i].resource=(struct record_data*)(reader);
		reader+=sizeof(struct record_data);

		if (strcmp(DNS_Qtype_tostr(ntohs(dns_rep->addit[i].resource->type)), "A") == 0 ||    //if it's an ipv4
            strcmp(DNS_Qtype_tostr(ntohs(dns_rep->addit[i].resource->type)), "AAAA") == 0){  //or ipv6 address
			dns_rep->addit[i].rdata = (unsigned char*)malloc(ntohs(dns_rep->addit[i].resource->data_len+1));

			for(int j = 0; j < ntohs(dns_rep->addit[i].resource->data_len); j++){
                dns_rep->addit[i].rdata[j]=reader[j];
            }

			dns_rep->addit[i].rdata[ntohs(dns_rep->addit[i].resource->data_len)] = '\0';

			reader = reader + ntohs(dns_rep->addit[i].resource->data_len);
		} else {
			dns_rep->addit[i].rdata = read_compressed_name(reader, buf, &stop);
			reader += stop;
		}
	}
}

/*************************************************
 *                     MAIN
*************************************************/
int main (int argc, char *argv[]){
//parse input arguments
    if (parse_args(argc, argv)){
        exit (1);
    }
    //list_args(par);

//OBSOLETE!!!
//get DNS servers from /etc/resolv.conf
    //dns_servers_get();

//prepare packet message buffer
	unsigned char buf[65536]; //packet buffer

//prepare socket and its necessities
    int sockfd; //socket
    struct sockaddr_in dest;   //IPv4 address
	struct sockaddr_in6 dest6; //IPv6 address
    sock_prep(&sockfd, &dest, &dest6);

//prepare packet DNS header and DNS reply structures
	struct dns_header_t *dns = (struct dns_header_t *)&buf; //point header structure to packet header portion
    dns_pack_prep(dns);
    //the above function sets the header to defaults (standard query), we need to modify some bits/flags)
	dns->rd = par.recursion; //set Recursion Desired

//prepare empty dns query structure and insert qname into packet
    unsigned char *qname; //query name string
	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct dns_header_t)]; //buffer: [{dns header}{qname}{...}]
    dns_qname_insert(qname);
	struct dns_question_t *qinfo = NULL;
    //point after qname
	qinfo =(struct dns_question_t*)&buf[sizeof(struct dns_header_t) + (strlen((const char*)qname) + 1)];
    if (par.reverse){
        dns_qinfo_prep(qinfo, DNS_QTYPE_PTR, DNS_QCLASS_IN); //PTR for reverse DNS lookup
    } else {
        dns_qinfo_prep(qinfo, par.Qtype, DNS_QCLASS_IN); //class IN = internet
    }


//send packet
    if (is_it_IPv6(par.server)){
        if(sendto(sockfd,(char*)buf,sizeof(struct dns_header_t) + (strlen((const char*)qname)+1) + sizeof(struct dns_question_t),0,(struct sockaddr*)&dest6,sizeof(dest6)) < 0){
            perror("ERROR: sendto failure");
            exit(1);
        }
    } else {
        if(sendto(sockfd,(char*)buf,sizeof(struct dns_header_t) + (strlen((const char*)qname)+1) + sizeof(struct dns_question_t),0,(struct sockaddr*)&dest,sizeof(dest)) < 0){
            perror("ERROR: sendto failure");
            exit(1);
        }
    }

//receive the answer
    if (is_it_IPv6(par.server)){
        int i = sizeof dest6;
        if(recvfrom (sockfd,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest6 , (socklen_t*)&i ) < 0){
            perror("ERROR: recvfrom failure");
            exit(1);
        }
    } else {
        int i = sizeof dest;
        if(recvfrom (sockfd,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0){
            perror("ERROR: recvfrom failure");
            exit(1);
        }
    }

//load answers into pre-prepared records string arrays
	struct dns_replies dns_rep; //structure for the DNS reply
    //we need to read data which is saved past the dns header and query fields, 
    //so we need to create a pointer which we will then point ahead of them
    unsigned char *reader;
	reader = &buf[sizeof(struct dns_header_t) +    //move past dns header
                  (strlen((const char*)qname)+1) + //move past qname
                   sizeof(struct dns_question_t)]; //move past qinfo
    //buffer: [{dns header}{qname}{qinfo} *reader--> {...}]
    dns_reply_load(buf, reader, dns, &dns_rep);

//print results
    DNSname_to_hostname(qname); //convert qname into printable format for qol
    project_print(dns, qinfo, &dns_rep, qname);

//free allocated memory (program only ever allocates memory for the 'dns_replies' structure 
//inside 'dns_reply_load' function (and by extension 'read_compressed_name' function))
    clean_exit(dns, &dns_rep);

	return 0;
}