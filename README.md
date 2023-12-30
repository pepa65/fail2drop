# fail2drop v0.12.2
**Drop repeat-offending IP addresses in-kernel (netfilter)**

* Repo: github.com/pepa65/fail2drop
* License: GPLv3+
* After: github.com/apache2046/fail2drop
* Linux single stand-alone binary distribution with Golang source.
* IPs dropped in-kernel with Netfilter (nftables) rules.
* Can install systemd unit file for automated start, runs fine without systemd.
* Installs a basic configfile for sshd when not present.
* Logs to single file which can be specified in configfile.
* IPs can be whitelisted in configfile.
* Multiple logfiles can be monitored with multiple patterns and bancounts from configfile.
* Usage: `fail2drop` [ CFGFILE | `-c`|`check` | `-o`|`--once` | `-i`|`install` | `-u`|`uninstall` | `-h`|`help` | `-V`|`version` ]
  - Can use an alternate configfile from the commandline, otherwise 
    `fail2drop.yml` in the current directory will be used, and finally `/etc/fail2drop.yml`.
  - Can check and list the to-be-banned IP addresses without affecting the system.
  - Can run once (or being called from `cron` occasionally) to add drop rules to nftables,
    without needing to constantly monitor the log files, for very lightweight operation.
		In this case the output is to stdout, so wants to be redirected in cron jobs
  - Can install the binary, a template for the configfile, the systemd unit file and enable & start the service.
  - Can stop & disable the service and remove the unit file.
  - Can show a help text.
  - Can show the version.
* Checking and showing the help text and version does not require privileges, the rest does.
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
# Edit /etc/fail2drop.yml if required, and if changed, do:
sudo systemctl restart fail2drop
```

Or for `fail2drop.sh`:
```
wget -q https://gitlab.com/pepa65/fail2drop/raw/main/fail2drop.sh
chmod +x fail2drop.sh
sudo cp fail2drop.sh /usr/local/bin/
sudo chown root:root /usr/local/bin/fail2drop.sh
wget -q https://gitlab.com/pepa65/fail2drop/raw/main/fail2drop.yml
sudo cp fail2drop.sh /etc/
sudo chown root:root /etc/fail2drop.yml
```

### Installing with go
* Required: `go`

```
sudo go install github.com/pepa65/fail2drop@latest
sudo fail2drop install
# Edit /etc/fail2drop.yml if required, andif changed, do:
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
(The output of `once` is on stderr.)

Or add: `/usr/local/bin/fail2drop.sh 2>>/var/log/fail2drop.log`
(The output is also on stderr.)

## Uninstall
`fail2drop uninstall`

* The binary can be removed with: `sudo rm /usr/local/bin/fail2drop`
* The configfile can be removed with: `sudo rm /etc/fail2drop.yml`

## Usage
Basically, run continuously through the systemd service file,
or run occasionally with the `once` option,
or just check what would get banned by running with the `check` option.
```
fail2drop v0.12.2 - Drop repeat-offending IP addresses in-kernel (netfilter)
Repo:   github.com/pepa65/fail2drop
Usage:  fail2drop [ OPTION | CONFIGFILE ]
    OPTION:
      -c|check:        List to-be-banned IPs without affecting the system.
      -o|once:         Add to-be-banned IPs in a single run (or from 'cron').
      -i|install:      Install the binary, a template for the configfile, the
                       systemd unit file and enable & start the service.
      -u|uninstall:    Stop & disable the service and remove the unit file.
      -h|help:         Show this help text.
      -V|version:      Show the version.
    CONFIGFILE:        Used if given, otherwise 'fail2drop.yml' in the current
                       directory or finally '/etc/fail2drop.yml' will get used.
  Privileges are required to run except for 'check', 'help' and 'version'.
```

## Configure
* See the included example configfile `fail2drop.yml` (works for sshd on Ubuntu).
* The logfile recording the bans is `/var/log/fail2drop.log` by default,
  but can be specified in the configfile with `varlog:`.
* IP addresses can be whitelisted under `whitelist:` (prepended by `- `).
* Multiple `searchlog` conditions can be named and specified, with:
  - `logfile:` - The path of the log file to be searched
  - `tag:` - The initial search tag to filter lines in the log file
  - `ipregex:` - A regular expression that hopefully contains an offending IP address.
  - `bancount:` - The maximum number of offences allowed.
* If `/etc/fail2drop.yml` does not exist, `fail2drop install` will put the repo content
  of `fail2drop.yml` there. This can be modified and extended.

## Monitor
* Check current table with: `sudo nft list ruleset` (`nft` from package `nftables`).
* Check the log of banned IPs: `less /var/log/fail2drop.log`
* Unban all banned entries: `sudo nft delete inet table fail2drop`
* To remove the ban on a specific IP address, use this function:
```
nfdel(){
  [[ -z $1 ]] &&
    echo "Error: give IP address as argument" &&
    return ||
    echo "Info: trying to remove IP address '$1'"
  local h=$( nft -a list table ip mangle |grep $1)
  h=${h##* }
  [[ -z $h ]] &&
    echo "IP address '$1' not found in table mangle" &&
    return
  nft delete rule mangle FAIL2DROP handle $h &&
    echo "IP address '$1' with handle '$h' deleted"
}

## Update
Basically, run the new binary with the `install` option.
```
cd fail2drop  # Go to the directory with the cloned repo
git pull
go build
./fail2drop install
```

To update the bash version `fail2drop.sh`, see: **Installing by downloading the self-contained binary**
