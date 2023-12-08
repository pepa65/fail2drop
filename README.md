# fail2drop v0.3.0
**Dropping IP addresses that repeatedly fail with iptables**

* Repo: github.com/pepa65/fail2drop
* License: GPLv3+
* After: github.com/apache2046/fail2drop

## Install
* Required: `git` `go` `sudo` `systemd`

```
git clone https://github.com/pepa65/fail2drop
cd fail2drop
go build
sudo mv fail2drop /usr/local/bin/
sudo cp fail2drop.service /etc/systemd/system/
sudo systemctl enable fail2drop.service
sudo systemctl start fail2drop.service
```

## Configure
* Right now, the configuration is compiled in.
* Multiple `searchlog` conditions can be specified, with:
  - `logfile`: The path of the log file to be searched
  - `tag`: The initial search tag to filter lines in the log file
  - `ipregex`: A regular expression that hopefully contains an offending IP address.
  - `bancount`: The maximum number of offences allowed.
* IP addresses can be whitelisted.
* The logfile recording the bans is `/var/log/fail2drop.log` (as defined in `fail2drop.service`).

## Monitor
* Check current table with: `sudo nft list table mangle` (from package `nftables`).
* Check the log of banned IPs: `less /var/log/fail2drop.log`
* Unban all banned entries: `sudo nft flush table mangle`

## Update
```
cd fail2drop  # Go to the directory with the cloned repo
git pull
go build
sudo systemctl stop fail2drop.service
sudo mv fail2drop /usr/local/bin/
sudo cp fail2drop.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start fail2drop.service
```
