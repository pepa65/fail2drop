# fail2drop v0.14.6
**Drop repeat-offending IP addresses in-kernel (netfilter)**

* Repo: github.com/pepa65/fail2drop
* License: GPLv3+
* After: github.com/apache2046/fail2drop
* Packets from IPs dropped in-kernel with Netfilter (nftables) rules.
* Linux small single stand-alone binary distribution with Golang source.
  This version uses a rule for each banned IP.
* Can install systemd unit file for automated start, runs fine without systemd.
* Installs a basic configfile for sshd when not present.
* Package `nftables` (binary `nft`) does not need to be installed (but do install it to check counts/state/results!).
* Bash version that requires package `nftables` (tested to work with version `0.8.2` and up).
  The bash version uses sets of IP addresses with a single rule.
* Logs to single file which can be specified in configfile, `/etc/fail2drop.yml` by default.
* IPs can be whitelisted in configfile.
* Multiple logfiles can be monitored with multiple patterns and bancounts from configfile.
* Usage: `fail2drop` [ CFGFILE | `-o`|`--once` | `-n`|`noaction` | `-i`|`install` | `-u`|`uninstall` | `-h`|`help` | `-V`|`version` ]
  - Can use an alternate configfile from the commandline, otherwise 
    `fail2drop.yml` in the current directory will be used, and finally `/etc/fail2drop.yml`.
  - Can run once (or being called from `cron` occasionally) to add drop rules to nftables,
    without needing to constantly monitor the log files, for very lightweight operation.
		In this case the output is to stdout, so wants to be redirected in cron jobs
  - Can run once and list the to-be-banned IP addresses without affecting the system.
  - Can install the binary, a template for the configfile, the systemd unit file and enable & start the service.
  - Can stop & disable the service and remove the unit file.
  - Can show a help text.
  - Can show the version.
* Running 'noaction', showing the help text or version does not require privileges, the rest does.

## Install
* Required: `sudo` (or any way to operate with root privileges)

## Installing by downloading the self-contained binary
* Required: `wget` (or any other way to download the binary)
* Get the appropriate link to the latest released binary at:
  https://github.com/pepa65/fail2drop/releases
* Or use `4e4.in/fail2drop`

```
wget -q 4e4.in/fail2drop
chmod +x fail2drop
sudo ./fail2drop install
# Edit /etc/fail2drop.yml if required, and if changed, do:
sudo systemctl restart fail2drop
```

Or for `fail2drop.sh`, use `gitlab.com/pepa65/fail2drop/raw/main/fail2drop.sh`, or:
```
wget -q 4e4.in/fail2drop.sh
chmod +x fail2drop.sh
sudo cp fail2drop.sh /usr/local/bin/
sudo chown root:root /usr/local/bin/fail2drop.sh
wget -q 4e4.in/fail2drop.yml
sudo cp fail2drop.yml /etc/
sudo chown root:root /etc/fail2drop.yml
```

### Installing with go
* Required: `go` properly installed

```
sudo go install github.com/pepa65/fail2drop@latest
sudo fail2drop install
# Edit /etc/fail2drop.yml if required, and if changed, do:
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
sudo chown root:root /etc/fail2drop.yml
sudo ./fail2drop install
```

### Installing for use with cron
Install, then uninstall (the binary and configfile will stay).
Then add this command to a crontab: `/usr/local/bin/fail2drop --once 2>>/var/log/fail2drop.log`
(The output of `once` is on `stderr`.)

Or add: `/usr/local/bin/fail2drop.sh 2>>/var/log/fail2drop.log`
(The output of the bash version is also on `stderr`.)

## Uninstall
`fail2drop uninstall`

* The binary can be removed with: `sudo rm /usr/local/bin/fail2drop`
* The bash script can be removed with: `sudo rm /usr/local/bin/fail2drop.sh`
* The configfile can be removed with: `sudo rm /etc/fail2drop.yml`

## Usage
Basically, run continuously through the systemd service file,
or run occasionally with the `once` option, or run 'once' without affecting
the system to see what would get banned by running with the `noaction` option.
```
fail2drop v0.14.5 - Drop repeat-offending IP addresses in-kernel (netfilter)
Repo:   github.com/pepa65/fail2drop
Usage:  fail2drop [ OPTION | CONFIGFILE ]
    OPTION:
      -o|once:         Add to-be-banned IPs in a single run (or from 'cron').
      -n|noaction:     Do a 'once' single run without affecting the system.
      -i|install:      Install the binary, a template for the configfile, the
                       systemd unit file and enable & start the service.
      -u|uninstall:    Stop & disable the service and remove the unit file.
      -h|help:         Show this help text.
      -V|version:      Show the version.
    CONFIGFILE:        Used if given, otherwise 'fail2drop.yml' in the current
                       directory or finally '/etc/fail2drop.yml' will get used.
  Privileges are required to run except for 'noaction', 'help' and 'version'.
```

## Configure
* See the included example configfile `fail2drop.yml` (works for sshd on Ubuntu).
* The logfile recording the bans is `/var/log/fail2drop.log` by default,
  but can be specified in the configfile with `varlog:`.
* IP addresses can be whitelisted under `whitelist:` (prepended by `- `).
* Multiple `searchlog` conditions can be named and specified, after:
  - `logfile:` - The path of the log file to be searched
  - `tag:` - The initial search tag to filter lines in the log file
  - `ipregex:` - A regular expression that should contains an offending IP address.
  - `bancount:` - The maximum number of offences allowed.
* If `/etc/fail2drop.yml` does not exist, `fail2drop install` will put the repo content
  of `fail2drop.yml` there. This can be modified and extended.

## Monitor
* Check current table with: `sudo nft list ruleset` (`nft` from package `nftables`).
* Check the log of banned IPs: `less /var/log/fail2drop.log`
* Unban all banned entries: `sudo nft delete inet table fail2drop`
* To remove the ban on a specific IP address for the golang version, use this function:
```
f2del(){
	local a=$1 x i h
	if [[ ${a//:} = $a ]]
	then
		printf -v i '0x%02x%02x%02x%02x' ${a//./ }
	else
		[[ $a = ${a#::} ]] || a=0$a
		[[ $a = ${a%::} ]] || a+=0
		printf -v x '%8s' ${a//[^:]}
		x=${x//:} x=:${x// /0:}
		a=${a/::/$x}
		printf -v i '0x%4s%4s%4s%4s%4s%4s%4s%4s\n' ${a//:/ }
		i=${i// /0}
	fi
  h=$(sudo nft -a list table inet fail2drop |grep "$i")
	h=${h##* }
	sudo nft delete rule inet fail2drop FAIL2DROP handle $h
}
```
* To remove the ban on a specific IP address for the bash version, use this function:
```
f2delb(){
	[[ ${1//:} = $1 ]] && set=badip || set=badip6
	sudo nft delete element inet fail2drop $set "{$1}"
}
```

## Update
Basically, run the new binary with the `install` option.
```
cd fail2drop  # Go to the directory with the cloned repo
git pull
go build
./fail2drop install
```

To update the bash version `fail2drop.sh`:
```
wget -q 4e4.in/fail2drop.sh
chmod +x fail2drop.sh
sudo cp fail2drop.sh /usr/local/bin/
sudo chown root:root /usr/local/bin/fail2drop.sh
```
