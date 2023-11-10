/** @file:   dns.c
 *  @brief:  Project for ISA (network applications and management) VUTBR FIT 2023/24
 *  @author: Vojtěch Kališ (xkalis03)
 *  @last_edit: 2nd October 2023  
**/

/**
 * TODO: - tests
*/

#include "dns.h"

void helpmsg(){
    fprintf(stderr, 
    "--- dns.c ---\r\n"
    "usage:  dns [-r] [-x] [-6] -s server [-p port] address\r\n"
    "where:  [-r] = recursion desired\r\n"
    "        [-x] = make reverse request instead of direct request\r\n"
    "        [-6] = make request of type AAAA instead of default A\r\n"
    "         -s server = IP or hostname of server to which request will be sent\r\n"
    "        [-p port]  = port number to use (default 53)\r\n"
    "         address   = address that is the object of query(request)\r\n");
}

/*************************************************
 *                    MY FUNCS
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
    if ((result = inet_pton(AF_INET6, addr, &(tmp.sin6_addr))) == 1){
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

//arguments parser
void parse_args(int argc, char *argv[]){
    if (argc < 3){
        fprintf(stderr,"ERROR: insufficient amount of arguments received\r\n");
        helpmsg();
        exit(1);
    } else if (argc > 9){
        fprintf(stderr,"ERROR: too many arguments received\r\n");
        helpmsg();
        exit(1);
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
                if (is_it_hostname(optarg)){
                    strcpy(par.server, optarg);
                    break;
                } else {
                    fprintf(stderr, "ERROR: invalid hostname received: %s\r\n", optarg);
                    exit(1);
                }
            case 'p':
                num = strtol(optarg, NULL, 0);
                if (is_it_valid_port(num)){
                    par.port = (uint16_t)num;
                    break;
                } else {
                    fprintf(stderr, "ERROR: invalid port number: %s\r\n", optarg);
                    exit(1);
                }
            case ':': //-s or -p without operand
                fprintf(stderr, "Option -%c requires an operand\r\n", optopt);
                helpmsg();
                exit(1);
            case '?':
                fprintf(stderr, "ERROR: unknown argument found: %c\r\n", optopt);
                helpmsg();
                exit(1);
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
                    exit(1);
                }
            } else {
                fprintf(stderr, "ERROR: unknown argument found: %s\r\n", argv[i]);
                helpmsg();
                exit(1);
            }
        }
    }
}

//DNS servers loader
void dns_servers_get(){
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
    //fprintf(stdout,"DNS #1: [%s]\r\nDNS #2: [%s]\r\nDNS #3: [%s]\r\nDNS #4: [%s]\r\nDNS #5: [%s]\r\n", dns_list[0], dns_list[1], dns_list[2], dns_list[3], dns_list[4]);
}

//Qtype integer to string converter
char* DNS_Qtype_tostr(uint16_t Qtype){
    //fprintf(stdout, "Resolving Qtype: %d\n\r", Qtype);
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
    //fprintf(stdout, "Resolving Qclass: %d\n\r", Qclass);
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

char* dec_to_hex_ipv6(unsigned char *input_string, char* output, int length, const char* type){
    char save[3];
    output[0] = '\0';
    bool doubledot = false;
    int pos = 0;
    for (int i = 0; i < length; ++i){
        //fprintf(stdout, "uiiiii[%d]\n\r", i);
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
    if (strcmp(type, "short") == 0){ //convert to shortened IPv6
        int steps = 0;
        bool zeros = true;
        char output_short[strlen(output)];
        for (int i = 0; i < strlen(output); i++){ //first, remove all ':0000:' fields (make them '::')
            if (strcmp(output[i], "0") == 0){
                continue;
            } else {
                zeros = false;
            }
            steps++;
            if (steps == )
        }
        return output;
    }
    //fprintf(stdout, "\n\rdec_to_hex_ipv6 output: %s\n\r\n\r", output);
    return output;
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

    fprintf(stdout,"\n\r ID:                 %d\n\r", dns->id); //randomly generated id

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

//print specifically in the format the assignment desires
void project_print(struct dns_header_t *dns, struct dns_question_t *question, struct dns_record_a_t *answers, struct dns_record_a_t *auth, struct dns_record_a_t *addit){
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
        fprintf(stdout, " %s, %s, %s\n\r", par.address, DNS_Qtype_tostr(ntohs(question->q_type)), DNS_Qclass_tostr(ntohs(question->q_class)));
    }
    //missing TTL and data?
  //answer section
    long *p;
    char ipaddr[128];
    //char a6string[INET6_ADDRSTRLEN];
    struct sockaddr_in a;
    //struct sockaddr_in6 a6;
    fprintf(stdout, "Answer Section(%d)\n\r", ntohs(dns->ancount));
    for (uint16_t i = 0; i < ntohs(dns->ancount); i++){
        fprintf(stdout, " %s, %s, %s, %u", answers[i].name, 
                                     DNS_Qtype_tostr(ntohs(answers[i].resource->type)), 
                                     DNS_Qclass_tostr(ntohs(answers[i].resource->class)), 
                                     htonl(answers[i].resource->ttl));
        // A
        if (strcmp(DNS_Qtype_tostr(ntohs(answers[i].resource->type)), "A") == 0){
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            fprintf(stdout, ", %s\n\r",inet_ntoa(a.sin_addr));
        // AAAA
        } else if (strcmp(DNS_Qtype_tostr(ntohs(answers[i].resource->type)), "AAAA") == 0){
            //fprintf(stdout, "AAAA not working yet\n\r");
            dec_to_hex_ipv6(answers[i].rdata, ipaddr, (int)ntohs(answers[i].resource->data_len), "short");
            fprintf(stdout, ", %s\n\r", ipaddr);
        // CNAME
        } else if (strcmp(DNS_Qtype_tostr(ntohs(answers[i].resource->type)), "CNAME") == 0){
            fprintf(stdout, ", %s\n\r",answers[i].rdata);
        } else {
            fprintf(stdout, "\n\r");
        }
    }
    fprintf(stdout, "Authority Section(%d)\n\r", ntohs(dns->nscount));
    for (uint16_t i = 0; i < ntohs(dns->nscount); i++){
        fprintf(stdout, " %s, %s, %s, %u, \n\r", auth[i].name, 
                                     DNS_Qtype_tostr(ntohs(auth[i].resource->type)), 
                                     DNS_Qclass_tostr(ntohs(auth[i].resource->class)), 
                                     htonl(auth[i].resource->ttl));
    }
    fprintf(stdout, "Additional Section(%d)\n\r", ntohs(dns->arcount));
    for (uint16_t i = 0; i < ntohs(dns->arcount); i++){
        fprintf(stdout, " %s, %s, %s, %u, %s\n\r", addit[i].name, 
                                     DNS_Qtype_tostr(ntohs(addit[i].resource->type)), 
                                     DNS_Qclass_tostr(ntohs(addit[i].resource->class)), 
                                     htonl(addit[i].resource->ttl), 
                                     addit[i].rdata);
    }
}


/*
 * Perform a DNS query by sending a packet
 * */
void ngethostbyname(unsigned char *host , unsigned int query_type)
{
	unsigned char buf[65536],*qname,*reader;
	int i , j , stop , s;

	struct sockaddr_in a;

	struct dns_record_a_t answers[20],auth[20],addit[20]; //the replies from the DNS server
	struct sockaddr_in dest;

	struct dns_header_t *dns = NULL;
	struct dns_question_t *qinfo = NULL;

	printf("Resolving %s" , host);

	s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

	dest.sin_family = AF_INET;
	dest.sin_port = htons(par.port);
	dest.sin_addr.s_addr = inet_addr(dns_list[0]); //dns servers

	//Set the DNS structure to standard queries
	dns = (struct dns_header_t *)&buf;

	dns->id = (unsigned short) htons(getpid());

	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
    //par.recursion = 1 ? dns->rd = 1 : dns->rd = 0;
	dns->rd = par.recursion; //Recursion Desired
	dns->ra = 0;
	dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
	dns->rcode = 0;

	dns->qdcount = htons(1); //we have only 1 question
	dns->ancount = 0;
	dns->nscount = 0;
	dns->arcount = 0;

	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct dns_header_t)];

	ChangetoDnsNameFormat_old(qname , host);
	qinfo =(struct dns_question_t*)&buf[sizeof(struct dns_header_t) + (strlen((const char*)qname) + 1)]; //fill it

	qinfo->q_type = htons( (int)query_type ); //type of the query , A , MX , CNAME , NS etc
	qinfo->q_class = htons(1); //its internet (lol)

	fprintf(stdout, "\n\rSending Packet...");
	if( sendto(s,(char*)buf,sizeof(struct dns_header_t) + (strlen((const char*)qname)+1) + sizeof(struct dns_question_t),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
	{
		perror("sendto failed");
	}
	printf("Done");


    dns_header_fullprint(dns);



	//Receive the answer
	i = sizeof dest;
	fprintf(stdout, "\n\rReceiving answer...");
	if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
	{
		perror("recvfrom failed");
	}
	printf("Done");



    dns_header_fullprint(dns);



	dns = (struct dns_header_t*) buf;

    dns_header_fullprint(dns);

	//move ahead of the dns header and the query field
	reader = &buf[sizeof(struct dns_header_t) + (strlen((const char*)qname)+1) + sizeof(struct dns_question_t)];

	//Start reading answers
	stop=0;

	for(i=0;i<ntohs(dns->ancount);i++)
	{
		answers[i].name=ReadName_old(reader,buf,&stop);
		reader = reader + stop;

		answers[i].resource = (struct R_DATA_old*)(reader);
        fprintf(stdout, "ANSWER #[%d]\n\r  name: %s, ", i+1, answers[i].name);
        fprintf(stdout, "type: %s, ", DNS_Qtype_tostr(htons(answers[i].resource->type)));
        fprintf(stdout, "class: %s, ", DNS_Qclass_tostr(htons(answers[i].resource->class)));
        fprintf(stdout, "ttl: %d, ", ntohl(answers[i].resource->ttl));
        fprintf(stdout, "data_len: %d, ", htons(answers[i].resource->data_len));
		reader = reader + sizeof(struct R_DATA_old);

		if (strcmp(DNS_Qtype_tostr(ntohs(answers[i].resource->type)), "A") == 0 ||    //if it's an ipv4
            strcmp(DNS_Qtype_tostr(ntohs(answers[i].resource->type)), "AAAA") == 0){  //or ipv6 address
			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

			for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
			{
				answers[i].rdata[j]=reader[j];
			}

			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

			reader = reader + ntohs(answers[i].resource->data_len);
		} else {
			answers[i].rdata = ReadName_old(reader,buf,&stop);
			reader = reader + stop;
		}
	}

	//read authorities
	for(i=0;i<ntohs(dns->nscount);i++)
	{
		auth[i].name=ReadName_old(reader,buf,&stop);
		reader+=stop;

		auth[i].resource=(struct R_DATA_old*)(reader);
		reader+=sizeof(struct R_DATA_old);

		auth[i].rdata=ReadName_old(reader,buf,&stop);
		reader+=stop;
	}

	//read additional
	for(i=0;i<ntohs(dns->arcount);i++)
	{
		addit[i].name=ReadName_old(reader,buf,&stop);
		reader+=stop;

		addit[i].resource=(struct R_DATA_old*)(reader);
		reader+=sizeof(struct R_DATA_old);

		if(ntohs(addit[i].resource->type)==1)
		{
			addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
			for(j=0;j<ntohs(addit[i].resource->data_len);j++)
			addit[i].rdata[j]=reader[j];

			addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
			reader+=ntohs(addit[i].resource->data_len);
		}
		else
		{
			addit[i].rdata=ReadName_old(reader,buf,&stop);
			reader+=stop;
		}
	}

	//print answers
	for(i=0 ; i < ntohs(dns->ancount) ; i++)
	{
		printf("Name : %s ",answers[i].name);

		if( ntohs(answers[i].resource->type) == 1) //1 = answer of type A (IPv4 address)
		{
			long *p;
			p=(long*)answers[i].rdata;
			a.sin_addr.s_addr=(*p); //working without ntohl
			printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
		}
		
		if(ntohs(answers[i].resource->type)==5)  //5 = answer of type CNAME
		{
			//Canonical name for an alias
			printf("has alias name : %s",answers[i].rdata);
		}

		printf("\n");
	}

	//print authorities
	printf("\nAuthoritive Records : %d \n" , ntohs(dns->nscount) );
	for( i=0 ; i < ntohs(dns->nscount) ; i++)
	{
		
		printf("Name : %s ",auth[i].name);
		if(ntohs(auth[i].resource->type)==2)
		{
			printf("has nameserver : %s",auth[i].rdata);
		}
		printf("\n");
	}

	//print additional resource records
	printf("\nAdditional Records : %d \n" , ntohs(dns->arcount) );
	for(i=0; i < ntohs(dns->arcount) ; i++)
	{
		printf("Name : %s ",addit[i].name);
		if(ntohs(addit[i].resource->type)==1)
		{
			long *p;
			p=(long*)addit[i].rdata;
			a.sin_addr.s_addr=(*p);
			printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
		}
		printf("\n");
	}

    project_print(dns, qinfo, answers, auth, addit);
	return;
}

/*
 * 
 * */
unsigned char* ReadName_old(unsigned char* reader,unsigned char* buffer,int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;

	*count = 1;
	name = (unsigned char*)malloc(256);

	name[0]='\0';

	//read the names in 3www6google3com format
	while(*reader!=0)
	{
		if(*reader>=192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
		}
		else
		{
			name[p++]=*reader;
		}

		reader = reader+1;

		if(jumped==0)
		{
			*count = *count + 1; //if we havent jumped to another location then we can count up
		}
	}

	name[p]='\0'; //string complete
    fprintf(stdout, "\n\r\n\rname: %s\n\r\n\r", name);
	if(jumped==1)
	{
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}

	//now convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++) 
	{
		p=name[i];
		for(j=0;j<(int)p;j++) 
		{
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	name[i-1]='\0'; //remove the last dot
    fprintf(stdout, "ReadName name: %s\n\r", name);
	return name;
}


/*
 * This will convert www.google.com to 3www6google3com 
 * got it :)
 * */
void ChangetoDnsNameFormat_old(unsigned char* dns,unsigned char* host) 
{
	int lock = 0 , i;
	strcat((char*)host,".");
	
	for(i = 0 ; i < (int)strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			*dns++ = i-lock;
			for(;lock<i;lock++) 
			{
				*dns++=host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++='\0';
}

/* The function converts the dot-based hostname into the DNS format (i.e.
www.apple.com into 3www5apple3com0) */
void change_to_dns_format(char *src, unsigned char *dest) {
	int pos = 0;
	int len = 0;
	int i;
	strcat(src, ".");
	for(i = 0; i < (int)strlen(src); ++i) {
		if(src[i] == '.') {
			dest[pos] = i - len;
			++pos;
			for(; len < i; ++len) {
				dest[pos] = src[len];
				++pos;
			}
			len++;
		}
	}
	dest[pos] = '\0';
}

/* This function converts a DNS-based hostname into dot-based format (i.e.
3www5apple3com0 into www.apple.com) */
void change_to_dot_format(unsigned char *str) {
	int i, j;
	for(i = 0; i < (int)strlen((const char*)str); ++i) {
		int len = str[i];
		for(j = 0; j < len; ++j) {
			str[i] = str[i + 1];
			++i;
		}
		str[i] = '.';
	}
	str[i - 1] = '\0';
}


/*************************************************
 *                     MAIN
*************************************************/
int main (int argc, char *argv[]){
//parse input arguments
    parse_args(argc, argv);
    //list_args(par);

//get DNS servers from /etc/resolv.conf
    dns_servers_get();

//prepare DNS structure
    ngethostbyname((unsigned char*)par.address, par.Qtype);


	return 0;
}