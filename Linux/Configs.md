
# UFW
```
...
```

# Samba
```
...
```

# screen

.screenrc:
```
# Отключаем приветствие
startup_message off
# Включаем utf8
defutf8 on
# Использовать визуальный сигнал (мигание экрана) вместо писка динамика
vbell off
# Размер буфера прокрутки
defscrollback 1000
# Производить отключение сессии при разрыве связи с терминалом
autodetach on
# Открывать Login-шелл
shell -$SHELL
# Активировать возможность прокрутки в xterm (и других эмуляторах терминала)
termcapinfo xterm* ti@:te@
# Волшебная строка
shelltitle '$ |sh'
# Строка состояния
#hardstatus alwayslastline "%{+b wk} %c $LOGNAME@%H %=[ %w ] "

#hardstatus on
#hardstatus alwayslastline
#hardstatus string "%{.1099} %-w%{.bg}%n %t%{-}%+w %=%H %c:%s "
#caption always "%3n %t%? @%u%?%? [%h]%?%=%c"

```


# fstab
```
...
```

# Wireguard

wg-quick ip wg0

/etc/wireguard/wg0.conf:
```
[Interface]
Address = 10.123.0.1/24
ListenPort = 13231
PrivateKey = yNMcwMsWp0Zv9TlwT/D0LH6nEjZERs3CC4G5KMuKy00=
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = opeGv3nK0d9sARRiDOVuhMw+MKySq6vZwKT1SAJznmg=
AllowedIPs = 192.168.88.0/24, 10.123.0.2/32

[Peer]
PublicKey = 8b5+nunufdQ3bfSWaObViVLLDeDKRLg/7nRg13nKzXA=
AllowedIPs = 10.123.0.3/32, 192.168.89.0/24

```

Mikrotik hAp AC2:
```

# feb/10/2023 04:35:03 by RouterOS 7.7
# software id = DFWM-KU0Q
#
# model = RBD52G-5HacD2HnD
# serial number = A97409D452E5
/interface bridge
add admin-mac=B8:69:F4:C0:19:6F auto-mac=no comment=defconf name=bridge
add name=dockers
/interface ethernet
set [ find default-name=ether4 ] disabled=yes
set [ find default-name=ether5 ] disabled=yes
/interface wireless
set [ find default-name=wlan1 ] band=2ghz-onlyn channel-width=20/40mhz-XX country=russia disabled=no distance=indoors frequency=auto installation=indoor mode=ap-bridge ssid=MikroArt-2 wireless-protocol=802.11
set [ find default-name=wlan2 ] band=5ghz-onlyac channel-width=20/40/80mhz-XXXX country=russia disabled=no distance=indoors frequency=auto installation=indoor mode=ap-bridge ssid=MikroArt-5 wireless-protocol=802.11
/interface veth
add address=172.17.0.2/24 gateway=172.17.0.1 name=veth1
/interface wireguard
add listen-port=13231 mtu=1420 name=vps-wireguard
/disk
set disk1 parent=usb1 partition-offset=512 partition-size="250 059 349 504" slot=disk1
/interface list
add comment=defconf name=WAN
add comment=defconf name=LAN
add name=Guest
/interface wireless security-profiles
set [ find default=yes ] authentication-types=wpa-psk,wpa2-psk mode=dynamic-keys supplicant-identity=MikroTik
add authentication-types=wpa-psk,wpa2-psk mode=dynamic-keys name=profile supplicant-identity=MikroTik
/interface wireless
add disabled=no mac-address=BA:69:F4:C0:19:74 master-interface=wlan2 name=wlan3 security-profile=profile ssid=GuestArt wps-mode=disabled
add disabled=no mac-address=BA:69:F4:C0:19:73 master-interface=wlan1 name=wlan4 security-profile=profile ssid=GuestArt wps-mode=disabled
/ip pool
add name=dhcp ranges=192.168.88.51-192.168.88.250
/ip dhcp-server
add address-pool=dhcp interface=bridge name=defconf
/user group
add name=homeassistant policy=read,test,api,!local,!telnet,!ssh,!ftp,!reboot,!write,!policy,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api
/zerotier
set zt1 comment="ZeroTier Central controller - https://my.zerotier.com/" identity="637d1e914f:0:a8c69cf8475be5a1dc9dc09704a2cd181e9d0a49b022d398788376e30a69d235fa5d1ab9bbc5e9c52804a446346d9f54ca6bc6f785ee91620a95c41d4249cbb3:21b89b5cf310781e71501291db74c751e03edbfef\
    86f498950c12955b1ec5d0920a2e79ac720085f3d082bc52df5037a4af3953a5ddb67b9e4fdfb329d9d4109" name=zt1 port=9993
/zerotier interface
add allow-default=no allow-global=no allow-managed=no disabled=yes instance=zt1 name=unlimited-power network=d5e5fb65373105f6
/interface bridge filter
add action=log chain=forward disabled=yes dst-address=192.168.88.236/32 in-interface-list=Guest log=yes mac-protocol=ip
add action=accept chain=forward disabled=yes dst-address=192.168.88.236/32 mac-protocol=ip
add action=accept chain=forward disabled=yes out-interface-list=Guest
add action=accept chain=forward disabled=yes ip-protocol=tcp mac-protocol=ip src-port=53
add action=accept chain=forward disabled=yes mac-protocol=ip src-address=192.168.88.236/32
add action=drop chain=forward dst-port=!53 in-interface-list=Guest ip-protocol=udp mac-protocol=ip
add action=drop chain=forward ip-protocol=udp mac-protocol=ip out-interface-list=Guest src-port=!53
add action=drop chain=forward disabled=yes in-interface-list=Guest
add action=drop chain=forward disabled=yes out-interface-list=Guest
/interface bridge port
add bridge=bridge comment=defconf interface=ether2
add bridge=bridge comment=defconf interface=ether3
add bridge=bridge comment=defconf interface=ether4
add bridge=bridge comment=defconf interface=ether5
add bridge=bridge comment=defconf interface=wlan1
add bridge=bridge comment=defconf interface=wlan2
add bridge=bridge interface=wlan3
add bridge=bridge interface=wlan4
add bridge=bridge ingress-filtering=no interface=unlimited-power
add bridge=dockers interface=veth1
/interface bridge settings
set use-ip-firewall=yes
/ip neighbor discovery-settings
set discover-interface-list=LAN
/interface list member
add comment=defconf interface=bridge list=LAN
add comment=defconf interface=ether1 list=WAN
add interface=wlan3 list=Guest
add interface=wlan4 list=Guest
add interface=vps-wireguard list=LAN
/interface ovpn-server server
set auth=sha1,md5
/interface wireguard peers
add allowed-address=10.123.0.0/24,192.168.89.0/24 endpoint-address=135.125.137.207 endpoint-port=13231 interface=vps-wireguard persistent-keepalive=20s public-key="/bpA8VvSAHyZ6ozg2M3NExAD0WP84NCoHGjmz8uALSk="
add allowed-address="0.0.0.0/5,8.0.0.0/7,11.0.0.0/8,12.0.0.0/6,16.0.0.0/4,32.0.0.0/3,64.0.0.0/2,128.0.0.0/3,160.0.0.0/5,168.0.0.0/6,172.0.0.0/12,172.32.0.0/11,172.64.0.0/10,172.128.0.0/9,173.0.0.0/8,174.0.0.0/7,176.0.0.0/4,192.0.0.0/9,192.128.0.0/11,192.160.0.0/13,1\
    92.169.0.0/16,192.170.0.0/15,192.172.0.0/14,192.176.0.0/12,192.192.0.0/10,193.0.0.0/8,194.0.0.0/7,196.0.0.0/6,200.0.0.0/5,208.0.0.0/4,::/0" disabled=yes endpoint-address=91.219.213.21 endpoint-port=1337 interface=*D persistent-keepalive=20s public-key=\
    "0T8Acv2BIA5sgXZJeOM4nvzxBBO4KTMBTLxBmJNIDSw="
/ip address
add address=192.168.88.1/24 comment=defconf interface=bridge network=192.168.88.0
add address=10.147.20.1/24 interface=unlimited-power network=10.147.20.0
add address=10.123.0.2/24 interface=vps-wireguard network=10.123.0.0
add address=172.17.0.1/24 interface=dockers network=172.17.0.0
/ip dhcp-client
add comment=defconf interface=ether1 use-peer-dns=no
/ip dhcp-server lease
add address=192.168.88.240 client-id=1:0:d8:61:58:6f:6c mac-address=00:D8:61:58:6F:6C server=defconf
add address=192.168.88.235 client-id=ff:32:b0:b9:54:0:1:0:1:29:13:15:b4:dc:a6:32:b0:b9:54 mac-address=DC:A6:32:B0:B9:54 server=defconf
add address=192.168.88.236 client-id=ff:32:b0:b9:54:0:1:0:1:29:13:15:a2:dc:a6:32:b0:b9:54 mac-address=DC:A6:32:B0:B9:54 server=defconf
add address=192.168.88.195 client-id=1:8:e9:f6:58:2e:62 mac-address=08:E9:F6:58:2E:62 server=defconf
add address=192.168.88.11 client-id=1:0:1e:6:49:7:d0 mac-address=00:1E:06:49:07:D0 server=defconf
/ip dhcp-server network
add address=192.168.88.0/24 comment=defconf dns-server=192.168.88.1 gateway=192.168.88.1
add address=192.168.89.0/24 dns-server=192.168.89.1 gateway=192.168.88.1
/ip dns
set allow-remote-requests=yes servers=1.1.1.2,1.0.0.2
/ip dns static
add address=192.168.88.1 comment=defconf name=router.lan
add address=192.168.89.1 name=router.da
add name=da ns=192.168.89.1 type=NS
add address=192.168.88.11 comment="Odroid NAS" name=nas.lan
/ip firewall filter
add action=accept chain=input comment="defconf: accept established,related,untracked" connection-state=established,related,untracked
add action=drop chain=input comment="defconf: drop invalid" connection-state=invalid
add action=accept chain=forward dst-address=10.123.0.0/24
add action=accept chain=forward src-address=10.123.0.0/24
add action=accept chain=input comment="defconf: accept ICMP" protocol=icmp
add action=accept chain=input comment="defconf: accept to local loopback (for CAPsMAN)" dst-address=127.0.0.1
add action=drop chain=input comment="defconf: drop all not coming from LAN" in-interface-list=!LAN
add action=accept chain=forward comment="defconf: accept in ipsec policy" ipsec-policy=in,ipsec
add action=accept chain=forward comment="defconf: accept out ipsec policy" ipsec-policy=out,ipsec
add action=fasttrack-connection chain=forward comment="defconf: fasttrack" connection-state=established,related hw-offload=yes
add action=accept chain=forward comment="defconf: accept established,related, untracked" connection-state=established,related,untracked
add action=drop chain=forward comment="defconf: drop invalid" connection-state=invalid
add action=drop chain=forward comment="defconf: drop all from WAN not DSTNATed" connection-nat-state=!dstnat connection-state=new in-interface-list=WAN
/ip firewall nat
add action=masquerade chain=srcnat comment="defconf: masquerade" ipsec-policy=out,none out-interface-list=WAN
add action=masquerade chain=srcnat src-address=172.17.0.0/24
/ip route
add disabled=no distance=1 dst-address=192.168.89.0/24 gateway=10.123.0.3 pref-src="" routing-table=main suppress-hw-offload=no
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www-ssl certificate=server disabled=no
set winbox disabled=yes
set api-ssl disabled=yes
/ip smb
set enabled=yes
/ip smb shares
add directory=/disk1 name=ShareMi
/ip smb users
add name=shares read-only=no
/ip upnp
set enabled=yes
/ip upnp interfaces
add interface=bridge type=internal
add interface=ether1 type=external
/ipv6 firewall address-list
add address=::/128 comment="defconf: unspecified address" list=bad_ipv6
add address=::1/128 comment="defconf: lo" list=bad_ipv6
add address=fec0::/10 comment="defconf: site-local" list=bad_ipv6
add address=::ffff:0.0.0.0/96 comment="defconf: ipv4-mapped" list=bad_ipv6
add address=::/96 comment="defconf: ipv4 compat" list=bad_ipv6
add address=100::/64 comment="defconf: discard only " list=bad_ipv6
add address=2001:db8::/32 comment="defconf: documentation" list=bad_ipv6
add address=2001:10::/28 comment="defconf: ORCHID" list=bad_ipv6
add address=3ffe::/16 comment="defconf: 6bone" list=bad_ipv6
/ipv6 firewall filter
add action=accept chain=input comment="defconf: accept established,related,untracked" connection-state=established,related,untracked
add action=drop chain=input comment="defconf: drop invalid" connection-state=invalid
add action=accept chain=input comment="defconf: accept ICMPv6" protocol=icmpv6
add action=accept chain=input comment="defconf: accept UDP traceroute" port=33434-33534 protocol=udp
add action=accept chain=input comment="defconf: accept DHCPv6-Client prefix delegation." dst-port=546 protocol=udp src-address=fe80::/10
add action=accept chain=input comment="defconf: accept IKE" dst-port=500,4500 protocol=udp
add action=accept chain=input comment="defconf: accept ipsec AH" protocol=ipsec-ah
add action=accept chain=input comment="defconf: accept ipsec ESP" protocol=ipsec-esp
add action=accept chain=input comment="defconf: accept all that matches ipsec policy" ipsec-policy=in,ipsec
add action=drop chain=input comment="defconf: drop everything else not coming from LAN" in-interface-list=!LAN
add action=accept chain=forward comment="defconf: accept established,related,untracked" connection-state=established,related,untracked
add action=drop chain=forward comment="defconf: drop invalid" connection-state=invalid
add action=drop chain=forward comment="defconf: drop packets with bad src ipv6" src-address-list=bad_ipv6
add action=drop chain=forward comment="defconf: drop packets with bad dst ipv6" dst-address-list=bad_ipv6
add action=drop chain=forward comment="defconf: rfc4890 drop hop-limit=1" hop-limit=equal:1 protocol=icmpv6
add action=accept chain=forward comment="defconf: accept ICMPv6" protocol=icmpv6
add action=accept chain=forward comment="defconf: accept HIP" protocol=139
add action=accept chain=forward comment="defconf: accept IKE" dst-port=500,4500 protocol=udp
add action=accept chain=forward comment="defconf: accept ipsec AH" protocol=ipsec-ah
add action=accept chain=forward comment="defconf: accept ipsec ESP" protocol=ipsec-esp
add action=accept chain=forward comment="defconf: accept all that matches ipsec policy" ipsec-policy=in,ipsec
add action=drop chain=forward comment="defconf: drop everything else not coming from LAN" in-interface-list=!LAN
/system clock
set time-zone-name=Europe/Moscow
/system routerboard settings
set auto-upgrade=yes
/system scheduler
add interval=10s name=schedule-pihole-monitor on-event=pihole-monitor policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=dec/11/2021 start-time=10:31:22
/system script
add dont-require-permissions=no name=pihole-monitor owner=admin policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source=":local currentDNS [/ip dns get server]\
    \n:local piholeDNS \"192.168.88.236\"\
    \n:local backupDNS \"1.1.1.2,1.0.0.2\"\
    \n:local testDomain \"www.google.com\"\
    \n\
    \n:if (\$currentDNS = \$piholeDNS) do={\
    \n    :do {\
    \n        :resolve \$testDomain server \$piholeDNS\
    \n    } on-error={\
    \n        :log error \"pihole DNS is inactive, changing DNS address ...\"\
    \n        /ip dns set servers=\$backupDNS\
    \n        /ip dhcp-server network set [find] dns-server=\$backupDNS;\
    \n    }\
    \n} else={\
    \n    :do {\
    \n        :resolve \$testDomain server \$piholeDNS\
    \n        :log warning \"pihole DNS connection restored\"\
    \n        /ip dns set servers=\$piholeDNS\
    \n        /ip dhcp-server network set [find] dns-server=\$piholeDNS;\
    \n    } on-error={}\
    \n}"
/tool mac-server
set allowed-interface-list=LAN
/tool mac-server mac-winbox
set allowed-interface-list=LAN
/tool sniffer
set filter-interface=vps-wireguard filter-ip-address=192.168.88.206/32

```


# NGINX
```
root@artemiev:/etc/nginx# cat nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        # multi_accept on;
}

http {

        ##
        # Basic Settings
        ##

        sendfile on;
        tcp_nopush on;
        types_hash_max_size 2048;
        server_tokens off;

        # server_names_hash_bucket_size 64;
        # server_name_in_redirect off;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        ##
        # SSL Settings
        ##

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
        ssl_prefer_server_ciphers on;
        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 10m;
        keepalive_timeout   70;

        ##
        # Logging Settings
        ##

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        ##
        # Gzip Settings
        ##

        gzip on;

        # gzip_vary on;
        # gzip_proxied any;
        # gzip_comp_level 6;
        # gzip_buffers 16 8k;
        # gzip_http_version 1.1;
        # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

        ##
        # Virtual Host Configs
        ##

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;

        server {
                server_name artemiev.ddns.net www.artemiev.ddns.net;
                location / {
                        proxy_set_header HOST $host;
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-Proto $scheme;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Host https://$server_name:433;

                        proxy_pass http://192.168.88.236:80;
                }

                listen 443 ssl; # managed by Certbot
                ssl_certificate /etc/letsencrypt/live/artemiev-ha.ddns.net/fullchain.pem; # managed by Certbot
                ssl_certificate_key /etc/letsencrypt/live/artemiev-ha.ddns.net/privkey.pem; # managed by Certbot
                include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
                ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

        }

        server {
                server_name artemiev.ml www.artemiev.ml;
                location / {
                        proxy_set_header HOST $host;
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-Proto $scheme;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Host https://$server_name:433;

                        proxy_pass http://192.168.88.236:80;
                }

                listen 443 ssl;
                ssl_certificate /etc/ssl/artemiev.ml.pem;
                ssl_certificate_key /etc/ssl/artemiev.ml.key;
        }

        server {
                server_name artemiev-mdb.ddns.net www.artemiev-mdb.ddns.net;
                location / {
                        proxy_set_header HOST $host;
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-Proto $scheme;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Host https://$server_name:433;

                        proxy_pass http://192.168.88.235:80;
                }

                listen 443 ssl; # managed by Certbot
                ssl_certificate /etc/letsencrypt/live/artemiev-ha.ddns.net/fullchain.pem; # managed by Certbot
                ssl_certificate_key /etc/letsencrypt/live/artemiev-ha.ddns.net/privkey.pem; # managed by Certbot
                include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
                ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

        }


        server {
                server_name mdb.artemiev.ml www.mdb.artemiev.ml;
                location / {
                        proxy_set_header HOST $host;
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-Proto $scheme;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Host https://$server_name:433;

                        proxy_pass http://192.168.88.235:80;
                }

                listen 443 ssl;
                ssl_certificate /etc/ssl/artemiev.ml.pem;
                ssl_certificate_key /etc/ssl/artemiev.ml.key;
        }

        server {
                server_name ha.artemiev.ml www.ha.artemiev.ml;
                location / {
                        proxy_set_header HOST $host;
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-Proto $scheme;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Host https://$server_name:433;
                        proxy_set_header    Upgrade     $http_upgrade;
                        proxy_set_header    Connection  "upgrade";

                        proxy_pass http://192.168.89.40:8123;
                }

                listen 443 ssl;
                ssl_certificate /etc/ssl/artemiev.ml.pem;
                ssl_certificate_key /etc/ssl/artemiev.ml.key;
        }

        server {
                if ($host = ha.artemiev.ml) {
                        return 301 https://$host$request_uri;
                } # managed by Certbot

                server_name ha.artemiev.ml www.ha.artemiev.ml;
                listen 80;
                return 404; # managed by Certbot
        }

        server {
                if ($host = artemiev.ml) {
                        return 301 https://$host$request_uri;
                } # managed by Certbot

                server_name artemiev.ml www.artemiev.ml;
                listen 80;
                return 404; # managed by Certbot
        }

        server {
                if ($host = mdb.artemiev.ml) {
                        return 301 https://$host$request_uri;
                } # managed by Certbot


                server_name mdb.artemiev.ml www.mdb.artemiev.ml;
                listen 80;
                return 404; # managed by Certbot
        }
}


#mail {
#       # See sample authentication script at:
#       # http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#       # auth_http localhost/auth.php;
#       # pop3_capabilities "TOP" "USER";
#       # imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#       server {
#               listen     localhost:110;
#               protocol   pop3;
#               proxy      on;
#       }
#
#       server {
#               listen     localhost:143;
#               protocol   imap;
#               proxy      on;
#       }
#}
```