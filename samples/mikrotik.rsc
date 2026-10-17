# Sample MikroTik RouterOS configuration - fully sanitized, fake secrets only
# Vendor: MikroTik, OS: RouterOS 7.x
# RouterOS 7.14
/ip service disable telnet
/ip service enable ssh
/ip service set www disabled=yes
/ip service set www-ssl
/snmp set enabled=yes community=FAKE_COMMUNITY_2024
/system logging action set memory
/system ntp client set enabled=yes primary-ntp=10.0.0.1 secondary-ntp=10.0.0.2
/system clock set time-zone-name=UTC
/system note set show-at-login=yes
/user set admin password=FAKE_PASSWORD_2024
/ip firewall filter add chain=input action=accept
