#### Modsecurity Dynamic Preprocessor for Snort v2.x
A Proof-of-Concept project started to turn ModSecurity into sniffer mode and with Snort Inline capability to drop packet once the packet matches with the attack signatures.

###### Status: Discontinued (temporarily) for GSoC 2016. However, this repo can be use as a boilerplate for simple Snort + Modsecurity preprocessor. I tried to directly port the Modsecurity into the HttpInspect preprocessor for Snort3 and basically it works (roughly), the code can be found in the commits history.

#### Installation
The installation procedure is the usual one:
```Bash
$ sudo snort -c snort.conf
```

#### TODO:
1. Utilize libmodsecurity ([Modsecurity-Pcap Connector](https://github.com/SpiderLabs/ModSecurity-pcap)).
2. Logging (e.g /var/log/snort/modsecurity.log).

#### License

BSDv3 License. Copyright (c) 2016 Fakhri Zulkifli. See [License](https://github.com/d0lph1n98/Snort-ModSec-Preproc/blob/master/LICENSE).

#### Contact

mohdfakhrizulkifli at gmail dot com
