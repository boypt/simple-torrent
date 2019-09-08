# SimpleTorrent [![Build Status](https://travis-ci.org/boypt/simple-torrent.svg?branch=master)](https://travis-ci.org/boypt/simple-torrent) 
![screenshot](https://user-images.githubusercontent.com/1033514/64239393-bdbb6480-cf32-11e9-9269-d8d10e7c0dc7.png)

**SimpleTorrent** is a a self-hosted remote torrent client, written in Go (golang). Started torrents remotely, download sets of files on the local disk of the server, which are then retrievable or streamable via HTTP.

# Features

This fork adds new features to the original cloud-torrent by `jpillora`.

* Run extrenal program on tasks completed: `DoneCmd`
* Stops task when seeding ratio reached: `SeedRatio`
* Download/Upload speed limiter: `UploadRate`/`DownloadRate`
* Detailed transfer stats in web UI.
* [Torrent Watcher](https://github.com/boypt/simple-torrent/wiki/Torrent-Watcher)
* K8s/docker health-check endpoint `/healthz`
* Extra trackers add from http source
* Protocol Handler to `magnet:`

And some development improvement:
* Go modules introduced and compatiable with go 1.12+
* Updated and compatiable with torrnet engine API from [anacrolix/torrent](https://github.com/anacrolix/torrent)

Also:
* Single binary
* Cross platform
* Embedded torrent search
* Real-time updates
* Mobile-friendly
* Fast [content server](http://golang.org/pkg/net/http/#ServeContent)
* IPv6 out of the box

# Install

## Binaries

See [the latest release](https://github.com/boypt/cloud-torrent/releases/latest) or use the oneline script to do a quick install on modern Linux.

```
bash <(wget -qO- https://raw.githubusercontent.com/boypt/simple-torrent/master/scripts/quickinstall.sh)
```

NOTE: [MUST read wiki page for further intructions: Auth And Security](https://github.com/boypt/simple-torrent/wiki/AuthSecurity)

## Docker [![Docker Pulls](https://img.shields.io/docker/pulls/boypt/cloud-torrent.svg)][dockerhub] [![Image Size](https://images.microbadger.com/badges/image/boypt/cloud-torrent.svg)][dockerhub]

[dockerhub]: https://hub.docker.com/r/boypt/cloud-torrent/

``` sh
$ docker run -d -p 3000:3000 -v /path/to/my/downloads:/downloads -v /path/to/my/torrents:/torrents boypt/cloud-torrent
```

## Source

*[Go](https://golang.org/dl/) is required to install from source*

``` sh
$ git clone https://github.com/boypt/simple-torrent.git
$ cd simple-torrent
$ ./scripts/make_release.sh
```

# Usage

## Commandline Options
```
$ cloud-torrent --help

  Usage: cloud-torrent_linux_amd64 [options]

  Options:
  --title, -t             Title of this instance (default SimpleTorrent)
  --port, -p              Listening port (default 3000)
  --host, -h              Listening interface (default all)
  --auth, -a              Optional basic auth in form 'user:password'
  --config-path, -c       Configuration file path (default cloud-torrent.json)
  --key-path, -k          TLS Key file path
  --cert-path             TLS Certicate file path
  --log, -l               Enable request logging
  --open, -o              Open now with your default browser
  --disable-log-time, -d  Don't print timestamp in log
  --version, -v           display version
  --help                  display help

  Version:
    1.X.Y

  Read more:
    https://github.com/boypt/simple-torrent

```

## Configuration file

A sample json will be created on the first run of simple-torrent.

```json
{
  "AutoStart": true,
  "Debug": false,
  "ObfsPreferred": true,
  "ObfsRequirePreferred": false,
  "DisableTrackers": false,
  "DisableIPv6": false,
  "DownloadDirectory": "/home/ubuntu/Workdir/cloud-torrent/downloads",
  "WatchDirectory": "/home/ubuntu/Workdir/cloud-torrent/torrents",
  "EnableUpload": true,
  "EnableSeeding": true,
  "IncomingPort": 50007,
  "DoneCmd": "",
  "SeedRatio": 1.5,
  "UploadRate": "High",
  "DownloadRate": "Unlimited",
  "TrackerListURL": "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt"
}
```

* `AutoStart`: Whether start torrent task on added Magnet/Torrent.
* `Debug` Print debug log from torrent engine (lots of them)
* `ObfsPreferred`: Whether torrent header obfuscation is preferred.
* `ObfsRequirePreferred`: Whether the value of `ObfsPreferred` is a strict requirement. This hides torrent traffic from being censored.
* `DisableTrackers`: Don't announce to trackers. This only leaves DHT to discover peers.
* `DisableIPv6`: Don't connect to IPv6 peers.
* `DisableEncryption` A switch disables [BitTorrent protocol encryption](https://en.wikipedia.org/wiki/BitTorrent_protocol_encryption)
* `DownloadDirectory` The directory where downloaded file saves.
* `WatchDirectory` The directory SimpleTorrent will watch and load new added `.torrent`, See [Torrent Watcher](https://github.com/boypt/simple-torrent/wiki/Torrent-Watcher)
* `EnableUpload` Whether send chunks to peers
* `EnableSeeding` Whether upload even after there's nothing further for us. By default uploading is not altruistic, we'll only upload to encourage the peer to reciprocate.
* `IncomingPort` The port SimpleTorrent listens to.
* `DoneCmd` An external program to call on task finished. See [DoneCmd Usage](https://github.com/boypt/simple-torrent/wiki/DoneCmdUsage).
* `SeedRatio` The ratio of task Upload/Download data when reached, the task will be stop.
* `UploadRate`/`DownloadRate` The global speed limiter, a fixed level amoung `Low`(~50k/s), `Medium`(~500k/s) and `High`(~1500k/s) is accepted as value, all other values (or empty) will result in unlimited rate.
* `TrackerListURL`: A https URL to a trackers list, this option is design to retrive public trackers from [ngosang/trackerslist](https://github.com/ngosang/trackerslist). If configred, all trackers will be added to each torrent task.

## Systemd example

Below is an example of a service for Simple Torrent located in `/cloud-torrent` with `cloud-torrent` as user

```
[Unit]
Description=Cloud-Torrent on port 3000

[Service]
ExecStart=/cloud-torrent/Cloud-Torrent -t MySimpleTorrentWebPage -h 127.0.0.1 -p 3000 -a USER:PASSWORD -c /cloud-torrent/cloud-torrent.json
Restart=always
RestartSec=15
User=cloud-torrent

[Install]
WantedBy=multi-user.target
```

You can create it with `sudo nano /etc/systemd/system/Simple-Torrent.service`

Start it with `sudo systemctl start Simple-Torrent`

Enable it at boot with `sudo systemctl enable Simple-Torrent`

## Nginx Configuration

Below is an example of a Nginx configuration for Simple Torrent

```
# http => https
server {
    listen 80;
    listen [::]:80; # IPv6 support
    server_name torrent.yourdomain.com;

    # This is for letsencrypt only
    root /cloud-torrent/ssl;
    location ^~ /.well-known/acme-challenge {
        auth_basic off;
        try_files $uri =404;
        expires -1;
    }

    location / {
        return 301 https://$host$request_uri;
        include 'preset/HSTS';
        include 'preset/SecurityHeaders';
    }
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name torrent.yourdomain.com;

    ssl_certificate /root/.acme.sh/torrent.yourdomain.com/fullchain.cer;
    ssl_certificate_key /root/.acme.sh/torrent.yourdomain.com/torrent.yourdomain.com.key ;
    ssl_trusted_certificate /root/.acme.sh/torrent.yourdomain.com/ca.cer;

    # Logs
    access_log /var/log/nginx/torrent-access.log;
    error_log /var/log/nginx/torrent-error.log;

    include preset/SSL; # cipher eliptic curve etc
    include preset/Development; #To avoid referencing
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        include 'preset/HSTS';
        include 'preset/SecurityHeaders';
    }
    location /sync {

        proxy_http_version 1.1;
        proxy_cache off;
        proxy_buffering off;

        proxy_set_header Connection keep-alive;
        proxy_set_header Cache-Control: no-cache;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_pass http://127.0.0.1:3000/sync;
    }
}
```

*include 'preset/SecurityHeaders';*

```
dd_header X-Content-Type-Options nosniff;

# please see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
# add_header X-Frame-Options deny;
add_header X-Frame-Options SAMEORIGIN;

add_header X-XSS-Protection "1; mode=block";

add_header Referrer-Policy "no-referrer-when-downgrade";

# optional header - use it with care - you are warned!
# add_header Access-Control-Allow-Origin "*";
```

*include preset/Development;*

```
#####   for public facing development sites; also called as staging sites   #####

# deny access to robots.txt across the board
location = /robots.txt { access_log off; deny all; }
location ~ /sitemap { access_log off; deny all; }

# block sitemaps with .xml and .xml.gz endings such as news-sitemap.xml (Yoast SEO)
location ~ \.xml$ { access_log off; deny all; }
location ~ \.xml\.gz$ { access_log off; deny all; }

# deny specific bots
if ( $http_user_agent ~ "Google" ) { return 403; }
if ( $http_user_agent ~ "bingbot" ) { return 403; }
```

*include preset/SSL;*

```
    ssl_prefer_server_ciphers on;

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    ssl_protocols TLSv1.2 TLSv1.3;

    # From https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SH>

    ssl_dhparam /etc/nginx/dhparam.pem;

    ssl_stapling on;
    ssl_stapling_verify on;

    ssl_ecdh_curve 'secp521r1:secp384r1';
    ssl_session_tickets off;
```

*include 'preset/HSTS';*

```
add_header Strict-Transport-Security "max-age=31536000";
```

# Credits 
* Credits to @jpillora for [Cloud Torrent](https://github.com/jpillora/cloud-torrent).
* Credits to @anacrolix for https://github.com/anacrolix/torrent
