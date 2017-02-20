## DHCPd Detector

Useful tool for sniffing DHCP Server on specified Interface

### How to use

    python dhcpd_detector.py [--config <filename>.cfg]

### Configure

Override your custom settings by config option(ini form), here
are the default values

    [detector]
    if_name = eth0
    timeout = 3
    mac     = 08002779d69c


### How to Test

    sudo dhcpd_detector -c /etc/sysconfig/dhcpd_detector.cfg

### How to Debug

    tcpdump -i eth2 -vvv -s 1500 '((port 67 or port 68) and (udp[38:4] = 0x2779d69c))'

## Runtime Requirement

1. only tested on GNU/Linux
2. Python 2.6+

