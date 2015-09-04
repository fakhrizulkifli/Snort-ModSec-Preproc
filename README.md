#### Modified Http Inspect Preprocessor to parse ModSec Core Rule Set
A Proof-of-Concept project started to turn ModSecurity into sniffer mode and with Snort Inline capability to drop packet once the packet matches with the attack signatures. Therefore, the payload should not be able to get to the target and reaching to the 5th layer and above. (Isn't it?)

###### Warning: Under active development, currently unstable version.

#### Installation
The installation procedure is the usual one:
```Bash
$ make
$ make install -- you may need sudo
$ sudo snort -c snort.lua -A fast -i <interface>
```

#### TODO:
1. Looking for collaboration
    - To port libmodsecurity into the preprocessor.
    - Trigger Snort Inline capability.

2. Documentations (?)
3. Any suggestions (?)

#### License

GPLv2 License. Copyright (c) 2015 Fakhri Zulkifli. See [License](https://github.com/d0lph1n98/Snort-ModSec-CRS-Parser/blob/master/LICENSE).

#### Contact

mohdfakhrizulkifli at gmail dot com
