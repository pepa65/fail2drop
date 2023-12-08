package main

import (
	_ "embed"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
	"github.com/nxadm/tail"
	"gopkg.in/yaml.v2"
)

const (
	version   = "0.6.0"
	name      = "fail2drop"
	prefix    = "/usr/local/bin/"
	defconfig = "/etc/fail2drop.yml"
	deflogout = "/var/log/fail2drop.log"
)

type logsearch struct {
	logfile  string
	tag      string
	ipregex  string
	bancount int
}

type Config struct {
	logout      string
	whitelist   []string
	logsearches map[string]logsearch
}

type iprecord struct {
	count int
	added bool
}

var (
	//go:embed unit.tmpl
	unitfile string
	//go:embed config.tmpl
	config   string
	unitname = "/etc/systemd/system/" + name + ".service"
	records  = map[string]*iprecord{}
	cfg      Config
	wg       sync.WaitGroup
)

func banip(ipaddr, set string) {
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

	for _, ip := range cfg.whitelist {
		if ip == ipaddr {
			return
		}
	}

	err = ipt.AppendUnique("mangle", "FAIL2DROP", "--src", ipaddr, "-j", "DROP")
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("[%s v%s] ban '%s' %s\n", name, version, set, ipaddr)
}

func process(logsearch logsearch, line, set string) {
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
		banip(ipaddr, set)
		record.added = true
	}
}

func follow(logsearch logsearch, set string) {
	defer wg.Done()
	t, _ := tail.TailFile(logsearch.logfile, tail.Config{Follow: true, ReOpen: true})
	for line := range t.Lines {
		process(logsearch, line.Text, set)
	}
}

func inits(cfgfile string) {
	cfgdata, err := ioutil.ReadFile(cfgfile)
	if err != nil {
		log.Fatalln(err)
  }

	cfg.logout = deflogout
	err = yaml.UnmarshalStrict(cfgdata, &cfg)
	if err != nil {
		log.Fatalln("Error in config file " + cfgfile + "\n" + err.Error())
	}

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
	exec.Command("systemctl", "stop", name).Run()
	bin, err := os.ReadFile(os.Args[0])
	if err != nil {
		log.Fatalln(err)
	}

	err = os.WriteFile(prefix+name, bin, 0755)
	if err != nil {
		if errors.Is(err, syscall.EACCES) {
			log.Fatalln("insufficient permissions, run with root privileges")
		}

		log.Fatalln(err)
	}

	var f *os.File
	f, err = os.OpenFile(config, os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		_, err = f.WriteString(fmt.Sprintf(config))
	}
	f.Close()
	if err != nil {
		log.Fatalln(err, "could not create new configfile "+config)
	}

	f, err = os.Create(unitname)
	if err != nil {
		log.Fatalln(err, "could not create systemd unit file "+unitname)
	}

	exec.Command("systemctl", "stop", name).Run()
	_, err = f.WriteString(fmt.Sprintf(unitfile, name, version, name, name, name))
	f.Close()
	if err != nil {
		log.Fatalln(err, "could not instantiate systemd unit file "+unitname)
	}

	err = exec.Command("systemctl", "daemon-reload").Run()
	if err != nil {
		log.Fatalln(err, "could not reload the systemd service daemons")
	}

	err = exec.Command("systemctl", "start", name).Run()
	if err != nil {
		log.Fatalln(err, "could not start systemd service "+name)
	}

	err = exec.Command("systemctl", "enable", name).Run()
	if err != nil {
		log.Fatalln(err, "could not enable systemd service "+name)
	}
	os.Exit(0)
}

func uninstall() {
	exec.Command("systemctl", "stop", name).Run()
	exec.Command("systemctl", "disable", name).Run()
	err := os.Remove(unitname)
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		log.Fatalln(err, "failure to remove unit file "+unitname)
	}
	os.Exit(0)
}

func main() {
	usage := "Usage: " + name + " [ CFGFILE | -i|install | -u|uninstall | -V|version ]"
	cfgfile := defconfig
	if len(os.Args) > 2 {
		fmt.Println(usage)
		log.Fatalln("Too many arguments")
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-V", "--version":
			fmt.Println(name + " v" + version)
			os.Exit(0)

		case "install", "-i", "--install":
			install()
		case "uninstall", "-u", "--uninstall":
			uninstall()
		default:
			cfgfile = os.Args[1]
		}
	}
	inits(cfgfile)
	for set, logsearch := range cfg.logsearches {
		wg.Add(1)
		go follow(logsearch, set)
	}
	wg.Wait()
}
