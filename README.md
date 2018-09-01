# dhcpfingerprint
Identifiy Device type, vendor and OS using sniffed DHCP messages. Update NeDi nodes ...

Can be run as a service using systemctl ... copy script to /opt/scripts/dhcpfingerprint.py

Create a file ... vim /etc/systemd/system/dhcpfingerprint.service

[Unit]
Description=DHCP Fingerprint for NeDi
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/opt/scripts/dhcpfingerprint.py
User=root
#Restart=on-failure
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target

systemctl enable dhcpfingerprint
systemctl start dhcpfingerprint

done
