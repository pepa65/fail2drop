#!/usr/bin/env bash

# fail2drop.sh - The 'once' and 'noaction' functionality of fail2drop in bash
# Usage: fail2drop.sh -h|--help | -V|--version | [-n|--noaction] [-c|--clear | CONFIGFILE]
#     -n/--noaction:  No system changes, just show what would be added
#     -c/--clear:     Clear all entries from the fail2drop kernel table
#   If CONFIGFILE is not given, then fail2drop.yml in the current directory
#   will be used if present, otherwise /etc/fail2drop.yml.
# Required: sudo[or privileged user] grep nftables(nft)[0.8.2+ work for sure]

self=fail2drop.sh
version=0.15.0
configfile=fail2drop.yml
nft=/usr/sbin/nft

Usage(){
	echo "$self v$version"
	echo "Usage:  $self ARGS"
	echo "    ARGS:  -h|--help | -V|--version | [-n|--noaction] [-c|--clear | CONFIGFILE]"
	exit 0
}

Err(){ # 1:msg 2:exitcode(optional)
	echo "$1" >&2
	[[ $2 ]] &&
		exit $2
}

[[ ! -f $configfile ]] &&
	configfile=/etc/$configfile
noaction=0 clear=0 config=0
for a in $@
do
	case $a in
	-h|--help|help) Usage ;;

	-V|--version|version) echo "$self v$version" && exit 0 ;;

	-n|--noaction|noaction) noaction=1 ;;
	-c|--clear|clear) clear=1 ;;
	*) ((config)) &&
			Err "Unrecognized option, configfile already given: '$configfile'" 1
		config=1 configfile=$a
	esac
done

sudo=
((EUID)) &&
	sudo=sudo
if ((clear))
then
	((!noaction)) &&
		$sudo $nft delete table inet fail2drop
	exit
fi

[[ ! -f $configfile ]] &&
	Err "Error: Configfile not found: $configfile" 2

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
			Err "Error: Stray list item, not in whitelist: '$line'" 3

		okips+=(${line#- })
		#echo "- ${line#- }"
	;;
	*:) # Set header
		whitelist=0
		[[ $set ]] &&
			Err "Error: Incomplete set: $set" 4
		set=${line%:}
		#echo "$set:"
	;;
	logfile:*)
		whitelist=0
		[[ -z $set ]] &&
			Err "Error: logfile attribute not part of a set" 5

		[[ $logfile ]] &&
			Err -e "Error: Previous logfile attribute unused: $logfile\nLine: $line" 6

		set -- $line
		shift
		logfile=${@%%#*} logfile=${logfile#\'} logfile=${logfile%\'} logfile=${logfile#\"} logfile=${logfile%\"}
		#echo "  logfile: $logfile"
	;;
	tag:*)
		whitelist=0
		[[ -z $set ]] &&
			Err "Error: tag attribute not part of a set" 7

		[[ $tag ]] &&
			Err -e "Error: Previous tag attribute unused: $tag\nLine: $line" 8

		set -- $line
		shift
		tag=${@%%#*} tag=${tag#\'} tag=${tag%\'} tag=${tag#\"} tag=${tag%\"}
		#echo "  tag: $tag"
	;;
	ipregex:*)
		whitelist=0
		[[ -z $set ]] &&
			Err "Error: ipregex attribute not part of a set" 9

		[[ $ipregex ]] &&
			Err -e "Error: Previous ipregex attribute unused: $ipregex\nLine: $line" 10

		set -- $line
		shift
		ipregex=${@%%#*} ipregex=${ipregex#\'} ipregex=${ipregex%\'} ipregex=${ipregex#\"} ipregex=${ipregex%\"}
		#echo "  ipregex: $ipregex"
	;;
	bancount:*)
		whitelist=0
		[[ -z $set ]] &&
			Err "Error: bancount attribute not part of a set" 11

		[[ $bancount ]] &&
			Err -e "Error: Previous bancount attribute unused: $bancount\nLine: $line" 12

		set -- $line
		shift
		bancount=${@%%#*} bancount=${bancount#\'} bancount=${bancount%\'} bancount=${bancount#\"} bancount=${bancount%\"}
		#echo "  bancount: $bancount"
	;;
	*)
		Err "Error: Unrecognized entry: $line" 13
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
	Err "Error: incomplete set '$set'" 14

# Exit if nothing to process
((${#sets[@]})) || exit

if ((!noaction))
then # Set up nftable fail2drop
	tmp=$(mktemp)
	v=$($nft -v) c=
	[[ ${v//[^.0-9]} > 0.9.4 ]] && c=' counter;'
	$sudo $nft delete table inet fail2drop 2>/dev/null
	cat <<-EOF >"$tmp"
		table inet fail2drop {
		  set badip {type ipv4_addr;$c};
		  set badip6 {type ipv6_addr;$c};
		  chain FAIL2DROP {
		    type filter hook prerouting priority -300; policy accept;
		    ip saddr @badip counter packets 0 bytes 0 drop;
		    ip6 saddr @badip6 counter packets 0 bytes 0 drop;
		  }
		}
	EOF
	$sudo $nft -f "$tmp"
	rm -- "$tmp"
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
	stamp="$(date +'%Y/%m/%d %H:%M:%S') [$self v$version]"
	for ip in $ips
	do # Process ipv4
		for w in ${okips[@]}
		do # Check whitelist
			[[ $w = $ip ]] && continue 2
		done
		[[ -z ${ipcount[$ip]} ]] &&
			ipcount[$ip]=1 ||
			((++ipcount[$ip]))
		((ipcount[$ip] == bancounts[$i])) &&
			Err "$stamp '${sets[$i]}' ban $ip" &&
			((!noaction)) &&
			$sudo $nft add element inet fail2drop badip "{$ip}"
	done
	for ip in $ip6s
	do # Process ipv6
		for w in ${okips[@]}
		do # Check whitelist
			[[ $w = $ip ]] && continue 2
		done
		[[ -z ${ipcount[$ip]} ]] &&
			ipcount[$ip]=1 ||
			((++ipcount[$ip]))
		((ipcount[$ip] == bancounts[$i])) &&
			Err "$stamp '${sets[$i]}' ban $ip" &&
			((!noaction)) &&
			$sudo $nft add element inet fail2drop badip6 "{$ip}"
	done
done
