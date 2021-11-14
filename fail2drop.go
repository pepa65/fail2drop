package main

import (
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/nxadm/tail"
)

func getIp(str string) string {
	re1 := regexp.MustCompile(`rhost=([^ ]*)[ ]`)
	result := re1.FindStringSubmatch(str)
	if len(result) != 0 {
		return result[1]
	}

	re2 := regexp.MustCompile(`Unable to negotiate with ([^ ]*) `)
	result = re2.FindStringSubmatch(str)
	if len(result) != 0 {
		return result[1]
	}
	re3 := regexp.MustCompile(`Failed password for ([^ ]*) from ([^ ]*) `)
	result = re3.FindStringSubmatch(str)

	if len(result) != 0 {
		return result[2]
	}
	return ""
}
func banip(ipaddr string) bool {
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

	return true
}

type iprecord struct {
	cnt      int
	inserted bool
}

var rec = map[string]*iprecord{}

func process(line string) {
	if !strings.Contains(line, "sshd") {
		return
	}
	ipaddr := getIp(line)
	if ipaddr == "" {
		return
	}
	// fmt.Println(ipaddr)
	r, ok := rec[ipaddr]
	if !ok {
		r = &iprecord{}
		rec[ipaddr] = r
	}
	r.cnt += 1
	// fmt.Println(ipaddr, rec[ipaddr])
	if r.cnt > 5 && !r.inserted {
		log.Println("ban", ipaddr)
		banip(ipaddr)
		r.inserted = true
	}

}
func initWork() {
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
	initWork()
	var logfile string
	if len(os.Args) == 1 {
		logfile = "/var/log/auth.log"
	} else {
		logfile = os.Args[1]
	}
	t, _ := tail.TailFile(logfile, tail.Config{Follow: true, ReOpen: true})
	for line := range t.Lines {
		process(line.Text)
	}
}
