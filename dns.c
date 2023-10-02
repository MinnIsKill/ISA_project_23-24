/** @file:   dns.c
 *  @brief:  Project for ISA (network applications and management) VUTBR FIT 2023/24
 *  @author: Vojtěch Kališ (xkalis03)
 *  @last_edit: 2nd October 2023  
**/

/**
 * TODO: - hostname checker
 *       - "help" message in case of errors
 *       - tests
*/

#include "dns.h"

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
    printf("host: %s\r\n",host);
    return true;
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
        fprintf(stderr,"ERR: insufficient amount of arguments received\r\n");
        exit(1);
    } else if (argc > 9){
        fprintf(stderr,"ERR: too many arguments received\r\n");
        exit(1);
    }

    int c;
    long num;
    while((c = getopt(argc, argv, ":rx6s:p:")) != -1){
        switch(c){
            case 'r':
                p.recursion = true;
                break;
            case 'x':
                p.reverse = true;
                break;
            case '6':
                strcpy(p.IPversion, "AAAA");
                break;
            case 's':
                if (is_it_hostname(optarg)){
                    strcpy(p.server, optarg);
                    break;
                } else {
                    fprintf(stderr, "ERR: invalid hostname received: %s\r\n", optarg);
                    exit(1);
                }
            case 'p':
                num = strtol(optarg, NULL, 0);
                if (is_it_valid_port(num)){
                    p.port = (int)num;
                    break;
                } else {
                    fprintf(stderr, "ERR: invalid port number: %s\r\n", optarg);
                    exit(1);
                }
            case ':': //-s or -p without operand
                fprintf(stderr, "Option -%c requires an operand\r\n", optopt);
                exit(1);
            case '?':
                fprintf(stderr, "ERR: unknown argument found: %c\r\n", optopt);
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
            if (strcmp(p.address, "") == 0){ //if address is still empty
                if (is_it_IPv4(argv[i]) || is_it_IPv6(argv[i]) || is_it_hostname(argv[i])){ //is it an actual address?
                    strcpy(p.address, argv[i]);
                } else {
                    fprintf(stderr, "ERR: found unknown argument or invalid address: %s\r\n", argv[i]);
                    exit(1);
                }
            } else {
                fprintf(stderr, "ERR: unknown argument found: %s\r\n", argv[i]);
                exit(1);
            }
        }
    }
}

void list_args(struct params s){
    fprintf(stdout, "recursion: %d\r\n", s.recursion);
    fprintf(stdout, "reverse:   %d\r\n", s.reverse);
    fprintf(stdout, "IPversion: %s\r\n", s.IPversion);
    fprintf(stdout, "server:    %s\r\n", s.server);
    fprintf(stdout, "port:      %d\r\n", s.port);
    fprintf(stdout, "address:   %s\r\n", s.address);
}

/*************************************************
 *                     MAIN
*************************************************/
int main (int argc, char *argv[]){
//parse input arguments
    //list_args(p);
    parse_args(argc, argv);
    //list_args(p);

}