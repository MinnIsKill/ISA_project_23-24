#!/usr/bin/env python3

# File: tests_run.py
# Description: Unit Tests for Project for ISA (network applications and management) VUTBR FIT 2023/24
# Author: Vojtěch Kališ (xkalis03)
# Last Edited: 19th November 2023

import ctypes
import subprocess

#test cases with successful outcomes
tests_succ = {
    "Testing valid arguments: ./dns -r -s kazi.fit.vutbr.cz www.fit.vut.cz": [b'-r', b'-s', b'kazi.fit.vutbr.cz', b'www.fit.vut.cz'],
    "Testing valid arguments: ./dns -r -s kazi.fit.vutbr.cz 147.229.9.26": [b'-r', b'-s', b'kazi.fit.vutbr.cz', b'147.229.9.26'],
    "testing valid arguments: ./dns -r -s 147.229.8.12 147.229.9.26": [b'-r', b'-s', b'147.229.8.12', b'147.229.9.26'],
    "testing valid arguments: ./dns -r -s kazi.fit.vutbr.cz 2001:67c:1220:809::93e5:917": [b'-r', b'-s', b'kazi.fit.vutbr.cz', b'2001:67c:1220:809::93e5:917'],
    #add test cases here
}

#test cases with failed outcomes
tests_fails = {
    "Testing not enough arguments": [b'-r'],
    "Testing too many arguments": [b'-r'] * 10,
    "testing missing operand for '-s'": [b'-r', b'-x', b'-s'],
    "testing invalid operant for '-s'": [b'-r', b'-s', b'?!!'],
    "testing unknown argument": [b'-r', b'-x', b'-z'],
    "testing not passing required argument 'server'": [b'-x', b'-r', b'147.229.9.26'],
    "testing not passing required argument 'address'": [b'-r', b'-x', b'-s', b'kazi.fit.vutbr.cz'],
    "testing hostname passed to 'server' but reverse DNS lookup demanded as well": [b'-x', b'-s', b'kazi.fit.vutbr.cz', b'www.fit.vut.cz'],
    "testing nonexistent or unreachable 'address' address/hostname": [b'-r', b'-s', b'kazi.fit.vutbr.cz', b'idont.exist'],
    "testing nonexistent or unreachable 'server' address/hostname": [b'-r', b'-s', b'idont.exist', b'www.fit.vut.cz'],
    #add test cases here
}

#load shared library
dns_tests = ctypes.CDLL('./tests_run.so')

#function signatures for validation and conversion functions
dns_tests.is_it_IPv4.argtypes = [ctypes.c_char_p]
dns_tests.is_it_IPv4.restype = ctypes.c_bool
dns_tests.is_it_IPv6.argtypes = [ctypes.c_char_p]
dns_tests.is_it_IPv6.restype = ctypes.c_bool
dns_tests.is_it_hostname.argtypes = [ctypes.c_char_p]
dns_tests.is_it_hostname.restype = ctypes.c_bool
dns_tests.is_it_valid_port.argtypes = [ctypes.c_long]
dns_tests.is_it_valid_port.restype = ctypes.c_bool
dns_tests.hostname_to_DNSname.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
dns_tests.hostname_to_DNSname.restype = None
dns_tests.DNSname_to_hostname.argtypes = [ctypes.c_char_p]
dns_tests.DNSname_to_hostname.restype = None

### 
# IPv4/IPv6/hostname validation functions tests
###
class IP_host_port_validations:
    def __init__(self):
        self.total_tests = 6
        self.successful_tests = 0
        
    #sending valid IP to is_it_IPv4
    def test_valid_IPv4(self):
        print("is_it_IPv4: sending valid IPv4:  ", end="")
        if dns_tests.is_it_IPv4(b'192.168.1.1') == True:
            self.successful_tests += 1
            print("\t\t[OK]")
        else:
            print("\t\t[FAIL]")

    #sending invalid IP to is_it_IPv4
    def test_invalid_IPv4(self):
        print("is_it_IPv4: sending invalid IPv4:  ", end="")
        if dns_tests.is_it_IPv4(b'256.300.1.1') == False:
            self.successful_tests += 1
            print("\t\t[OK]")
        else:
            print("\t\t[FAIL]")

    #sending valid IP to is_it_IPv6
    def test_valid_IPv6(self):
        print("is_it_IPv6: sending valid IPv6:  ", end="")
        if dns_tests.is_it_IPv6(b'2001:0db8:85a3:0000:0000:8a2e:0370:7334') == True:
            self.successful_tests += 1
            print("\t\t[OK]")
        else:
            print("\t\t[FAIL]")

    #sending invalid IP to is_it_IPv6
    def test_invalid_IPv6(self):
        print("is_it_IPv6: sending invalid IPv6:  ", end="")
        if dns_tests.is_it_IPv6(b'192.168.1.1') == False:
            self.successful_tests += 1
            print("\t\t[OK]")
        else:
            print("\t\t[FAIL]")

    #sending valid hostname to is_it_hostname
    def test_valid_hostname(self):
        print("is_it_hostname: sending valid hostname:  ", end="")
        if dns_tests.is_it_hostname(b'example.com') == True:
            self.successful_tests += 1
            print("\t[OK]")
        else:
            print("\t[FAIL]")

    #sending invalid hostname to is_it_hostname
    def test_invalid_hostname(self):
        print("is_it_hostname: sending invalid hostname:  ", end="")
        if dns_tests.is_it_hostname(b'@invalid_host!') == False:
            self.successful_tests += 1
            print("\t[OK]")
        else:
            print("\t[FAIL]")

### 
# hostname<-->DNSname name conversions tests
###
class host_dns_nameconversions:
    def __init__(self):
        self.total_tests = 2
        self.successful_tests = 0
        
    #input: www.google.com
    #expected output: 3www6google3com0
    def test_hostname_to_DNSname(self):
        host = b"www.google.com"
        print(f"hostname_to_DNSname: \t{host}")
        expected_dns = b"\x03www\x06google\x03com\x00"
        dns = ctypes.create_string_buffer(len(expected_dns))
        dns_tests.hostname_to_DNSname(host, dns)
        print(f"\t\t --> \t{dns.raw}:", end="")
        if dns.raw == expected_dns:
            self.successful_tests += 1
            print("\t[OK]")
        else:
            print("\t[FAIL]")

    #input: 3www6google3com0
    #expected output: www.google.com (can be www.google.com00)
    def test_DNSname_to_hostname(self):
        dns = b"\x03www\x06google\x03com\x00"
        print(f"DNSname_to_hostname: \t{dns}")
        expected_host = b"www.google.com\x00\x00"
        dns_tests.DNSname_to_hostname(dns)
        print(f"\t\t --> \t{dns}:\t", end="")
        
        if dns == expected_host:
            self.successful_tests += 1
            print("\t[OK]")
        else:
            print("\t[FAIL]")

#########################################
#                 MAIN                  #
#########################################
if __name__ == '__main__':
    ### 
    # INVALID USER INPUT TESTING
    print("--------------------- invalid user input testing ---------------------")
    success_rate = 0
    tests_amount = 0
    
    #run each test case
    for test, args in tests_fails.items():
        #subprocess call
        process = subprocess.Popen(['./dns'] + args, stderr = subprocess.PIPE, stdout = subprocess.PIPE)
        #save stdout and stderr
        stdout, stderr = process.communicate()

        tests_amount += 1
        if process.returncode == 1:
            #program successfully threw an error
            print(f"{test}")
            print(f"{stderr.decode()}", end="")
            success_rate += 1
            print("[OK]\n\r----------")
        else:
            print(f"----------\n\r{stderr.decode()}", end="")
            print("[FAIL]\n\r----------")

    #run each test case     
    for test, args in tests_succ.items():
        #subprocess call
        process = subprocess.Popen(['./dns'] + args, stderr = subprocess.PIPE, stdout = subprocess.PIPE)
        #save stdout and stderr
        stdout, stderr = process.communicate()

        tests_amount += 1
        if process.returncode == 0:
            #program ran successfully
            print(f"{test}")
            print(f"{stdout.decode()}", end="")
            success_rate += 1
            print("[OK]\n\r----------")
        else:
            print(f"----------\n\r{stderr.decode()}", end="")
            print("[FAIL]\n\r----------")
    
    print(f"\n\r SUCCESS RATE:  [{success_rate}/{tests_amount}]\n\r")
    
    ### 
    # VALIDATION FUNCTIONS TESTING
    print("\n\r-------------------- validation functions testing --------------------")
    t2 = IP_host_port_validations()
    t2.test_valid_IPv4()
    t2.test_invalid_IPv4()
    t2.test_valid_IPv6()
    t2.test_invalid_IPv6()
    t2.test_valid_hostname()
    t2.test_invalid_hostname()
    print(f"\n\r SUCCESS RATE:  [{t2.successful_tests}/{t2.total_tests}]\n\r")

    ### 
    # NAME CONVERSION FUNCTIONS TESTING
    print("\n\r------------------ name conversion functions testing -----------------")
    t3 = host_dns_nameconversions()
    t3.test_hostname_to_DNSname()
    t3.test_DNSname_to_hostname()
    print(f"\n\r SUCCESS RATE:  [{t3.successful_tests}/{t3.total_tests}]\n\r")