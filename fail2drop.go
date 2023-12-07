package main

import (
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/nxadm/tail"
)

const (
	readlog  = "/var/log/auth.log"
	bancount = 5
)

type iprecord struct {
	count    int
	inserted bool
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

func getip(str string) string {
	r := regexp.MustCompile(`Connection closed by [1-9][^ ]*`)
	result := r.FindStringSubmatch(str)
	if len(result) == 0 {
		return ""
	}

	parts := strings.Split(result[0], " ")
	return parts[len(parts)-1]
}

func process(line string) {
	if !strings.Contains(line, "sshd") {
		return
	}

	ipaddr := getip(line)
	if ipaddr == "" {
		return
	}

	r, ok := record[ipaddr]
	if !ok {
		r = &iprecord{}
		record[ipaddr] = r
	}
	r.count += 1
	if r.count > bancount && !r.inserted {
		log.Println("ban", ipaddr)
		banip(ipaddr)
		r.inserted = true
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

func main() {
	inittable()
	var logfile string
	if len(os.Args) == 1 {
		logfile = readlog
	} else {
		logfile = os.Args[1]
	}
	t, _ := tail.TailFile(logfile, tail.Config{Follow: true, ReOpen: true})
	for line := range t.Lines {
		process(line.Text)
	}
}
