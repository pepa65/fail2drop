package main

import (
	"log"
	"regexp"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/nxadm/tail"
)

const version  = "0.2.0"

type logsearch struct{
	logfile  string
	tag      string
	ipregex  string
	bancount int
}

var logsearches = [...]logsearch{
	{"/var/log/auth.log", "sshd", `Connection closed by [1-9][^ ]*`, 5},
	{"/var/log/dovecot", "imap-login: Info: Disconnected", ` rip=[^ ]*`, 5},
}

type iprecord struct {
	count int
	added bool
}

var record = map[string]*iprecord{}

func banip(ipaddr string) {
	var ipt *iptables.IPTables
	var err error
	if strings.Contains(ipaddr, ".") {
		ipt, err = iptables.New(iptables.IPFamily(iptables.ProtocolIPv4), iptables.Timeout(5))
	} else {
		ipt, err = iptables.New(iptables.IPFamily(iptables.ProtocolIPv6), iptables.Timeout(5))
	}
	if err != nil {
		log.Fatalln(err)
	}

	err = ipt.AppendUnique("mangle", "FAIL2DROP", "--src", ipaddr, "-j", "DROP")
	if err != nil {
		log.Fatalln(err)
	}
}

func process(logsearch logsearch, line string) {
	if !strings.Contains(line, logsearch.tag) {
		return
	}

	regex := regexp.MustCompile(logsearch.ipregex)
	results := regex.FindStringSubmatch(line)
	if len(results) == 0 {
		return
	}

	regex = regexp.MustCompile(`[1-9][0-9]*\.[1-9][0-9]*\.[1-9][0-9]*\.[1-9][0-9]*`)
	ipaddrs := regex.FindStringSubmatch(results[0])
	if len(ipaddrs) == 0 {
		return
	}

	ipaddr := ipaddrs[0]
	rec, ok := record[ipaddr]
	if !ok {
		rec = &iprecord{}
		record[ipaddr] = rec
	}
	rec.count += 1
	if rec.count > logsearch.bancount && !rec.added {
		log.Printf("[fail2drop v%s] ban %s\n", version, ipaddr)
		banip(ipaddr)
		rec.added = true
	}
}

func inittable() {
	for _, proto := range []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6} {
		ipt, err := iptables.New(iptables.IPFamily(proto), iptables.Timeout(5))
		if err != nil {
			log.Fatalln(err)
		}

		exist, err := ipt.ChainExists("mangle", "FAIL2DROP")
		if err != nil {
			log.Fatalln(err)
		}

		if !exist {
			err = ipt.NewChain("mangle", "FAIL2DROP")
			if err != nil {
				log.Fatalln(err)
			}

			err = ipt.Insert("mangle", "PREROUTING", 1, "-j", "FAIL2DROP")
			if err != nil {
				log.Fatalln(err)
			}
		}
	}
}

func follow(logsearch logsearch) {
	t, _ := tail.TailFile(logsearch.logfile, tail.Config{Follow: true, ReOpen: true})
	for line := range t.Lines {
		process(logsearch, line.Text)
	}
}

func main() {
	inittable()
	for _, logsearch := range logsearches {
		go follow(logsearch)
	}
}
