# Makefile for ISA project
# Author: Vojtěch Kališ, xkalis03@stud.fit.vutbr.cz

all: run_full
run_full: dns.c dns.h
		gcc -g -Wall -Wextra -Werror -pedantic -pthread dns.c -o dns
run_limited: dns.c dns.h
		gcc -g dns.c -o dns