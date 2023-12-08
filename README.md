# fail2drop v0.6.4
**Dropping IP addresses that repeatedly fail with iptables**

* Repo: github.com/pepa65/fail2drop
* License: GPLv3+
* After: github.com/apache2046/fail2drop
* Linux single binary, Golang source.
* IPs dropped in-kernel with Netfilter (nftables) rules.
* Can install systemd unit file for automated start, runs fine without systemd.
* Installs configfile template when not present.
* Logs to single file which can be specified in configfile.
* IPs can be whitelisted in configfile.
* Multiple logfiles can be monitored with multiple patterns and bancounts from configfile.
* Usage: `fail2drop` [ CFGFILE | `-i`|`install` | `-u`|`uninstall` | `-V`|`version` ]
* Default configfile: `/etc/fail2drop.yml`

## Install
* Required: `sudo` `systemd`

## Installing by downloading the self-contained binary
* Required: `wget` (or any other way to download the binary)
* Get the appropriate link to the latest released binary at:
  https://github.com/pepa65/fail2drop/releases

```
wget -qO fail2drop "LINK"
chmod +x fail2drop
sudo ./fail2drop install
# Edit /etc/fail2drop.yml and then restart the service:
sudo systemctl restart fail2drop
```

### Installing with go
* Required: `go`

```
sudo go install github.com/pepa65/fail2drop@latest
sudo fail2drop install
# Edit /etc/fail2drop.yml and then restart the service:
sudo systemctl restart fail2drop
```

### Installing by building from the repo
* Required: `git` `go`

```
git clone https://github.com/pepa65/fail2drop
cd fail2drop
go build
sudo cp fail2drop.yml /etc/
# Edit /etc/fail2drop.yml
sudo ./fail2drop install
```

## Uninstall
`fail2drop uninstall`

* The binary can be removed with: `sudo rm /usr/local/bin/fail2drop`
* The configfile can be removed with: `sudo rm /etc/fail2drop.yml`

## Configure
* See the included example configfile `fail2drop.yml`.
* The logfile recording the bans is `/var/log/fail2drop.log` by default,
  but can be specified in the configfile with `logout:`.
* IP addresses can be whitelisted under `whitelist:` (prepended by `- `).
* Multiple `searchlog` conditions can be named and specified, with:
  - `logfile:` - The path of the log file to be searched
  - `tag:` - The initial search tag to filter lines in the log file
  - `ipregex:` - A regular expression that hopefully contains an offending IP address.
  - `bancount:` - The maximum number of offences allowed.
* If `/etc/fail2drop.yml` does not exist, `fail2drop install` will put a template there.

## Monitor
* Check current table with: `sudo nft list table mangle` (from package `nftables`).
* Check the log of banned IPs: `less /var/log/fail2drop.log`
* Unban all banned entries: `sudo nft flush table mangle`

## Update
```
cd fail2drop  # Go to the directory with the cloned repo
git pull
go build
./fail2drop install
```
