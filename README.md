# fail2drop v0.4.1
**Dropping IP addresses that repeatedly fail with iptables**

* Repo: github.com/pepa65/fail2drop
* License: GPLv3+
* After: github.com/apache2046/fail2drop
* Linux small single binary, Golang source.
* IPs dropped in-kernel with Netfilter (nftables) rules.
* Can install systemd unit file for automated start, runs fine without systemd.
* Multiple logfiles can be monitored with multiple patterns and bancounts.
* IPs can be whitelisted.
* Logs to single file.
* Usage: `fail2drop` [`install`|`-i`|`--install` | `uninstall`|`-u`|`--uninstall` | `version`|`-V`|`--version`]

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
```

### Installing with go
* Required: `go`

```
sudo go install github.com/pepa65/fail2drop@latest
sudo fail2drop install
```

### Installing by building from the repo
* Required: `git` `go`

```
git clone https://github.com/pepa65/fail2drop
cd fail2drop
go build
sudo ./fail2drop install
```

## Uninstall
`fail2drop uninstall`

The binary can be removed with: `rm /usr/local/bin/fail2drop`

## Configure
* Right now, the configuration is compiled in (so build from the repo).
* Multiple `searchlog` conditions can be specified, with:
  - `logfile`: The path of the log file to be searched
  - `tag`: The initial search tag to filter lines in the log file
  - `ipregex`: A regular expression that hopefully contains an offending IP address.
  - `bancount`: The maximum number of offences allowed.
* IP addresses can be whitelisted.
* The logfile recording the bans is `/var/log/fail2drop.log` by default.

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
