#!/bin/sh
 
# Flushing all rules.
# -F (flush) ; -X (delete policy chain)
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

 
# Setting default filter policy
# -P (policy, chain target)
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Allow all established connections
iptables -A INPUT -p TCP -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p TCP -m state --state ESTABLISHED,RELATED -j ACCEPT


# Allow ssh
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT

# Allow ftp
iptables -A INPUT -p tcp --dport 21 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 21 -j ACCEPT

iptables -A INPUT -p tcp --dport 20 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 20 -j ACCEPT

# Allow http
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT

iptables -A INPUT -p tcp --dport 81 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 81 -j ACCEPT

iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 8080 -j ACCEPT

#Allow DNS
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow UDP
iptables -A OUTPUT -p udp -j ACCEPT
iptables -A INPUT -p udp -j ACCEPT

# Nothing comes or goes out of this box.
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
