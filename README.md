# DNS resolver
Project for ISA (network applications and management) VUTBR FIT 2023/24
### 
Author: Vojtěch Kališ \
Login: xkalis03 \
Date: 19.11.2023

## Introduction
The program is a C-based implementation of a Domain Name System (DNS) resolver. It implements a functional resolver capable of DNS queries creation in the form of UDP packets, establishing communication with given DNS server, successful sending of said packet, and subsequent retrieval and processing of the response information.

## Compilation
The program can be compiled using:
```bash
make
```
The program's unit tests can be compiled and run using:
```bash
make test
```

## Usage
The program receives these arguments as input (arguments not in square brackets are required)
```python
dns [-r] [-x] [-6] -s server [-p port] address
```
Where:
- [-r] = recursion desired
- [-x] = make reverse request instead of direct request (incompatible with '-6')
- [-6] = make request of type AAAA instead of default A (incompatible with '-x')
- -s server = IP or hostname of server to which request will be sent
- [-p port] = port number to use
- address = address that is the object of query(request)

## Contents

```
MAIN_FOLDER/
├── dns.c
├── dns.h
├── Makefile
├── manual.pdf
├── README.md
└── tests_run.py
```
Where:
- dns.c = main program file, contains DNS resolver implementation
- dns.h = main program header file, contains DNS resolver headers and definitions
- Makefile = handles compilation comfortability
- manual.pdf = program documentation
- README.md
- tests_run.py = file containing program tests