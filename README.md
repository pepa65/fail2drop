# Fail2Drop
**Dropping IP addresses that repeatedly fail on sshd with iptables**

* Repo: github.com/pepa65/fail2drop
* After: github.com/apache2046/fail2drop

## Install
* Required: `auditd git go sudo systemd`

```
git clone https://github.com/pepa65/fail2drop
cd fail2drop
go build fail2drop.go
sudo cp fail2drop /usr/bin/
sudo cp fail2drop.service /etc/systemd/system/
sudo systemctl enable fail2drop.service
sudo systemctl start fail2drop.service
```

* The logfile to examine can be given on the commandline or pre-configured in the source.
* The minimum number of failures can be pre-configured in the source.
