#!/usr/bin/python 
import re
import sys

def usage():
    print '[!] Warning: output rule must be in the same working directory [!]'
    print 'Usage: '
    print '-i,  input (e.g modsecurity_crs_41_xss_attacks.conf)'
    print '-o,  output (e.g xss-rule.conf)'

if sys.argv != 2:
    usage()

file = open('xss-rule.conf','r')

for i in file:
    if i.find('ARGS') != -1:
        matches = re.findall(r'\"(.+?)\" ',i)
        a = " ".join(matches).strip("()")
        with open('xssrule.conf','a') as outfile:
            outfile.write(a+'\n')

