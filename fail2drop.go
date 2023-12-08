package main

import (
	_ "embed"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
	"github.com/nxadm/tail"
)

const (
	version = "0.3.0"
	name    = "fail2drop"
	prefix  = "/usr/local/bin/"
)

var whitelist = [...]string {"192.168.1.128", "192.168.1.10", "147.78.241.159"}

type logsearch struct{
	logfile  string
	tag      string
	ipregex  string
	bancount int
}

var logsearches = [...]logsearch{
	{"/var/log/auth.log", "sshd", `Connection closed by [1-9][^ ]*`, 5},
	{"/var/log/auth.log.1", "sshd", `Connection closed by [1-9][^ ]*`, 5},
}

type iprecord struct {
	count int
	added bool
}

var (
	records  = map[string]*iprecord{}
	wg       sync.WaitGroup
	//go:embed unit.tmpl
	unitfile string
	unitname = "/etc/systemd/system/" + name + ".service"
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

	log.Printf("[%s v%s] ban %s\n", name, version, ipaddr)
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

func follow(logsearch logsearch) {
	defer wg.Done()
	t, _ := tail.TailFile(logsearch.logfile, tail.Config{Follow: true, ReOpen: true})
	for line := range t.Lines {
		process(logsearch, line.Text)
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

func install() {
	bin, err := os.ReadFile(os.Args[0])
	if err != nil {
		log.Fatalln(err)
	}

	err = os.WriteFile(prefix + name, bin, 0755)
	if err != nil {
		if errors.Is(err, syscall.EACCES) {
			log.Fatalln("insufficient permissions, run with root privileges")
		}

		log.Fatalln(err)
	}

	var f *os.File
	f, err = os.Create(unitname)
	if err != nil {
		log.Fatalln(err, "could not create systemd unit file " + unitname)
	}

	exec.Command("systemctl", "stop", name).Run()
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf(unitfile, name, version, name, name, name))
	if err != nil {
		log.Fatalln(err, "could not instantiate systemd unit file " + unitname)
	}

	err = exec.Command("systemctl", "daemon-reload").Run()
	if err != nil {
		log.Fatalln(err, "could not reload the systemd service daemons")
	}

	err = exec.Command("systemctl", "start", name).Run()
	if err != nil {
		log.Fatalln(err, "could not start systemd service " + name)
	}

	err = exec.Command("systemctl", "enable", name).Run()
	if err != nil {
		log.Fatalln(err, "could not enable systemd service " + name)
	}
}

func uninstall() {
	exec.Command("systemctl", "stop", name).Run()
	output, err := exec.Command("systemctl", "disable", name).CombinedOutput()
	if err != nil && strings.Contains(string(output), "Access denied") {
		log.Fatalln(err, "insufficient permissions, run with root privileges")
	}

	err = os.Remove(unitname)
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		log.Fatalln(err, "failure to remove unit file " + unitname)
	}

	log.Println("Unit file removed")
}

func main() {
	if len(os.Args) > 1 {
		if len(os.Args) > 2 {
			log.Fatalln("Too many arguments")
		}
		switch os.Args[1] {
			case "version", "-V", "--version":
				fmt.Println(name + " v" + version)
			case "install", "-i", "--install":
				install()
			case "uninstall", "-u", "--uninstall":
				uninstall()
			default:
				log.Fatalln("Only 'install', 'uninstall' or 'version' allowed as argument")
		}

		os.Exit(0)
	}

	inittable()
	for _, logsearch := range logsearches {
		wg.Add(1)
		go follow(logsearch)
	}
	wg.Wait()
}
