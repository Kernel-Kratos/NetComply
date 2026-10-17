// Sanitized sample configs used by "Load samples". Secrets are fake.
window.NC_SAMPLES = [
  {
    filename: "core-sw.cfg",
    content: [
      "! NetComply sample config - sanitized",
      "! Model: Catalyst 9300-48P",
      "! Serial: FOC2231X0AB",
      "version 17.6",
      "hostname core-sw",
      "!",
      "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0",
      "no service password-encryption",
      "username admin privilege 15 password 0 Cisco123",
      "!",
      "ip ssh version 2",
      "ip http server",
      "ip http secure-server",
      "!",
      "snmp-server community public RO",
      "snmp-server location DC1-ROW4",
      "!",
      "ntp server 10.0.0.1",
      "!",
      "banner motd ^C Authorized access only ^C",
      "!",
      "interface GigabitEthernet1/0/1",
      " description uplink",
      " switchport mode trunk",
      "!",
      "line vty 0 4",
      " transport input telnet ssh",
      " exec-timeout 0 0",
      " login local",
      "!",
      "end"
    ].join("\n")
  },
  {
    filename: "edge-fw.conf",
    content: [
      "## NetComply sample config - sanitized",
      "## Model: SRX345",
      "## Serial: CX0219AF0042",
      "set version 21.4R3",
      "set system host-name edge-fw",
      "set system root-authentication encrypted-password \"$6$abc$KJHkjhs8d7f6g5h4j3k2l1\"",
      "set system login password minimum-length 12",
      "set system login message \"Authorized access only\"",
      "set system login class netops idle-timeout 10",
      "set system services ssh protocol-version v2",
      "set system services ssh root-login deny",
      "set system services web-management https interface ge-0/0/1.0",
      "set system services telnet",
      "set system syslog host 10.0.0.5 any any",
      "set system ntp server 10.0.0.1",
      "set snmp community s3cr3tRO authorization read-only",
      "set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.2/30"
    ].join("\n")
  },
  {
    filename: "branch-rtr.rsc",
    content: [
      "# NetComply sample config - sanitized",
      "# model = RB4011iGS+",
      "# serial number = HD7081AB12C",
      "# RouterOS 7.12",
      "/system identity set name=branch-rtr",
      "/ip service set telnet disabled=no",
      "/ip service set www disabled=no",
      "/ip service set ssh disabled=no port=22",
      "/snmp community set [ find default=yes ] name=public",
      "/system logging action add name=remote target=remote remote=10.0.0.5",
      "/system ntp client set enabled=yes servers=10.0.0.1",
      "/system note set note=\"Authorized access only\" show-at-login=yes",
      "/user set admin password=Adm1nPass",
      "/interface bridge add name=bridge1"
    ].join("\n")
  }
];
