# cept

Building

requires: golang 1.7+ and libnetfilter-queue-dev>=1.0.0

Running

You will need to add the NFQUEUE rules using iptables:

> sudo iptables -A OUTPUT -p tcp --dport 3306 -j NFQUEUE --queue-num 0

> sudo iptables -A OUTPUT -p tcp --dport 11211 -j NFQUEUE --queue-num 1

Note: the queue numbers need to match the source code constants; currently `MYSQL_QUEUE_INDEX` = 0 and `MEMCACHED_QUEUE_INDEX` = 1.
