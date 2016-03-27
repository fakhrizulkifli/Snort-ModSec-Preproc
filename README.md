#### Modsecurity Dynamic Preprocessor for Snort v2.x
A Proof-of-Concept project started to turn ModSecurity into sniffer mode and with Snort Inline capability to drop packet once the packet matches with the attack signatures.

###### Status: Discontinued, GSoC 2016. However, this repo can be use as boilerplate for simple Snort + Modsecurity preprocessor.

#### Installation
The installation procedure is the usual one:
```Bash
$ sudo snort -c snort.conf
```

#### TODO:
1. Utilize libmodsecurity (Modsecurity-Pcap Connector).
2. Logging (e.g /var/log/snort/modsecurity.log).

#### License

BSDv3 License. Copyright (c) 2016 Fakhri Zulkifli. See [License](https://github.com/d0lph1n98/Snort-ModSec-Preproc/blob/master/LICENSE).

#### Contact

mohdfakhrizulkifli at gmail dot com
