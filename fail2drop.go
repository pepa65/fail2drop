package main

import (
	"log"
	"regexp"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/nxadm/tail"
)

const version  = "0.3.0"

type logsearch struct{
	logfile  string
	tag      string
	ipregex  string
	bancount int
}

var whitelist = [...]string {"192.168.1.128", "192.168.1.10", "147.78.241.159"}

var logsearches = [...]logsearch{
	{"/var/log/auth.log", "sshd", `Connection closed by [1-9][^ ]*`, 5},
	{"/var/log/auth.log.1", "sshd", `Connection closed by [1-9][^ ]*`, 5},
}

type iprecord struct {
	count int
	added bool
}

var (
	records = map[string]*iprecord{}
	wg      sync.WaitGroup
)

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

	for _, ip := range whitelist {
		if ip == ipaddr {
			return
		}
	}

	err = ipt.AppendUnique("mangle", "FAIL2DROP", "--src", ipaddr, "-j", "DROP")
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("[fail2drop v%s] ban %s\n", version, ipaddr)
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
		regex = regexp.MustCompile(`[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){7}`)
		if len(ipaddrs) == 0 {
			return
		}
	}

	ipaddr := ipaddrs[0]
	record, ok := records[ipaddr]
	if !ok {
		record = &iprecord{}
		records[ipaddr] = record
	}
	record.count += 1
	if record.count > logsearch.bancount && !record.added {
		banip(ipaddr)
		record.added = true
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
	defer wg.Done()
	t, _ := tail.TailFile(logsearch.logfile, tail.Config{Follow: true, ReOpen: true})
	for line := range t.Lines {
		process(logsearch, line.Text)
	}
}

func main() {
	inittable()
	for _, logsearch := range logsearches {
		wg.Add(1)
		go follow(logsearch)
	}
	wg.Wait()
}
