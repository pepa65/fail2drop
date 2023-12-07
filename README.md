# Fail2Drop
**Dropping IP addresses that repeatedly fail on sshd with iptables**

* Repo: github.com/pepa65/fail2drop
* After: github.com/apache2046/fail2drop

## Install
* Required: `git go sudo systemd`

```
git clone https://github.com/pepa65/fail2drop
cd fail2drop
go build fail2drop.go
sudo mv fail2drop /usr/local/bin/
sudo cp fail2drop.service /etc/systemd/system/
sudo systemctl enable fail2drop.service
sudo systemctl start fail2drop.service
```

* The logfile to base banning decisions on can be given on the commandline or be pre-configured in the source.
* The of failures that triggers a ban can be pre-configured in the source.
* The logfile recording the bans is `/var/log/fail2drop.log` (as defined in `fail2drop.service`).
* Check current table with: `sudo nft list table mangle` (from package `nftables`).
