# Makefile for ISA project
# Author: Vojtěch Kališ, xkalis03@stud.fit.vutbr.cz

default: run_full

run_full: dns.c dns.h
		gcc -g -Wall -Wextra -Werror -pedantic -pthread dns.c -o dns

.PHONY: test
test: dns.c dns.h
		gcc -g -Wall -Wextra -Werror -pedantic -pthread dns.c -o dns
		gcc -shared -o tests_run.so -fPIC dns.c
		python3 tests_run.py -v

.PHONY: run_limited
run_limited: dns.c dns.h
		gcc -g dns.c -o dns