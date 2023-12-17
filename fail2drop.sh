#!/usr/bin/env bash

# fail2drop.sh - The 'check' and 'once' functionality of fail2drop in bash
# Usage: fail2scan [-n|--noaction | CONFIGFILE]
#     -n/--noaction: No system changes, just show what would be logged (check)
#   If CONFIGFILE is not given, then fail2drop.yml in the current directory
#   will be used if present, otherwise /etc/fail2drop.yml.
# Required: sudo[or privileged user] grep nftables(nft)

version=0.10.0
configfile=fail2drop.yml
(($#>2)) &&
	echo "Too many arguments, only -n/--noaction / CONFIGFILE allowed" &&
	exit 1

scan=0
if [[ $1 ]]
then
	if [[ $1 = -n || $1 = --noaction || $1 = -c || $1 = --check ]]
	then # No configfile specified
		scan=1
		[[ ! -f $configfile ]] &&
			configfile=/etc/$configfile
	else # Must be configfile
		scan=0
		configfile=$1
	fi
fi
[[ ! -f $configfile ]] &&
	echo "Configfile not found: $configfile" &&
	exit 2

# Analyze the configfile
whitelist=0 set=
while read -er line
do
	[[ ${line:0:1} = '#' || ${#line} = 0 ]] &&
		continue
	case $line in
	varlog:*) # Entry varlog
		whitelist=0 set=
		set -- $line
		shift
		varlog=${@%%#*}
		#echo "varlog: $varlog"
	;;
	whitelist:)
		whitelist=1 set=
		#echo "whitelist:"
	;;
	'- '*) # IP address of whitelist
		((!whitelist)) &&
			echo "Error: Stray list item, not in whitelist: '$line'" &&
			exit 3
		okips+=(${line#- })
		#echo "- ${line#- }"
	;;
	*:) # Set header
		[[ $set ]] &&
			echo "Error: Incomplete set: $set" &&
			exit 4
		set=${line%:}
		#echo "$set:"
	;;
	logfile:*)
		[[ -z $set ]] &&
			echo "Error: logfile attribute not part of a set" &&
			exit 5
		[[ $logfile ]] &&
			echo -e "Error: Previous logfile attribute unused: $logfile\nLine: $line" &&
			exit 6
		set -- $line
		shift
		logfile=${@%%#*} logfile=${logfile#\'} logfile=${logfile%\'} logfile=${logfile#\"} logfile=${logfile%\"}
		#echo "  logfile: $logfile"
	;;
	tag:*)
		[[ -z $set ]] &&
			echo "Error: tag attribute not part of a set" &&
			exit 7
		[[ $tag ]] &&
			echo -e "Error: Previous tag attribute unused: $tag\nLine: $line" &&
			exit 8
		set -- $line
		shift
		tag=${@%%#*} tag=${tag#\'} tag=${tag%\'} tag=${tag#\"} tag=${tag%\"}
		#echo "  tag: $tag"
	;;
	ipregex:*)
		[[ -z $set ]] &&
			echo "Error: ipregex attribute not part of a set" &&
			exit 9
		[[ $ipregex ]] &&
			echo -e "Error: Previous ipregex attribute unused: $ipregex\nLine: $line" &&
			exit 10
		set -- $line
		shift
		ipregex=${@%%#*} ipregex=${ipregex#\'} ipregex=${ipregex%\'} ipregex=${ipregex#\"} ipregex=${ipregex%\"}
		#echo "  ipregex: $ipregex"
	;;
	bancount:*)
		[[ -z $set ]] &&
			echo "Error: bancount attribute not part of a set" &&
			exit 11
		[[ $bancount ]] &&
			echo -e "Error: Previous bancount attribute unused: $bancount\nLine: $line" &&
			exit 12
		set -- $line
		shift
		bancount=${@%%#*} bancount=${bancount#\'} bancount=${bancount%\'} bancount=${bancount#\"} bancount=${bancount%\"}
		#echo "  bancount: $bancount"
	;;
	*)
		echo "Error: Unrecognized entry: $line"
		exit 13
	esac
	if [[ $set && $logfile && $tag && $ipregex && $bancount ]]
	then
		sets+=("$set")
		logfiles+=("$logfile")
		tags+=("$tag")
		ipregexs+=("$ipregex")
		bancounts+=("$bancount")
		set= logfile= tag= ipregex= bancount=
	fi
done <"$configfile"
[[ $set ]] &&
	echo "Error: incomplete set '$set'" &&
	exit 14

# Exit if nothing to process
((${#sets[@]})) || exit

sudo=
((EUID)) &&
	sudo=sudo
if ((!scan))
then # Set up nftable fail2drop
	$sudo nft delete table inet fail2drop
	nftconf="
table inet fail2drop {
   set badip {
    type ipv4_addr;
    flags interval;
  };
  set badip6 {
    type ipv6_addr;
    flags interval;
  };
  chain FAIL2DROP {
    type filter hook input priority first; policy accept;
    ip saddr @badip counter packets 0 bytes 0 drop;
    ip6 saddr @badip6 counter packets 0 bytes 0 drop;
  }
}"
	echo "$nftconf" |$sudo nft -f -
fi

declare -A ipcount
for i in ${!sets[@]}
do # Process each set
	ips=$(grep "${tags[$i]}" "${logfiles[$i]}" |
		grep -o "${ipregexs[$i]}" |
		grep -o '[1-9][0-9]*\.[1-9][0-9]*\.[1-9][0-9]*\.[1-9][0-9]*')
	ip6s=$(grep "${tags[$i]}" "${logfiles[$i]}" |
		grep -o "${ipregexs[$i]}" |
		grep -o '[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){7}')
	stamp="$(date +%Y-%m-%d_%H:%M:%S) [fail2drop.sh v$version]"
	for ip in $ips
	do # Process ipv4
		[[ -z ${ipcount[$ip]} ]] &&
			ipcount[$ip]=1 ||
			((++ipcount[$ip]))
		((ipcount[$ip] == bancounts[$i])) &&
			echo "$stamp '${sets[$i]}' ban $ip" &&
			((!scan)) &&
			$sudo nft add element inet fail2drop badip "{$ip}"
	done
	for ip in $ip6s
	do # Process ipv6
		[[ -z ${ipcount[$ip]} ]] &&
			ipcount[$ip]=1 ||
			((++ipcount[$ip]))
		((ipcount[$ip] == bancounts[$i])) &&
			echo "$stamp '${sets[$i]}' ban $ip" &&
			((!scan)) &&
			$sudo nft add element inet fail2drop badip6 "{$ip}"
	done
done
