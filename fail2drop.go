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
	"gopkg.in/yaml.v3"
)

const (
	version   = "0.9.6"
	name      = "fail2drop"
	prefix    = "/usr/local/bin/"
)

type logsearch struct {
	set      string
	logfile  string
	tag      string
	ipregex  string
	bancount int
}

type iprecord struct {
	count int
	added bool
}

var (
	whitelist []string
	//go:embed unit.tmpl
	unittmpl string
	//go:embed fail2drop.yml
	cfgtmpl  string
	config   = "/etc/" + name + ".yml"
	varlog   = "/var/log/" + name + ".log"
	unitname = "/etc/systemd/system/" + name + ".service"
	records  = map[string]*iprecord{}
	check    = false
	once     = false
	wg       sync.WaitGroup
)

func usage(msg string) {
	help := name + " v" + version + " - Drop repeatedly offending IP addresses with nftables\n" +
		"Repo:   github.com/pepa65/fail2drop\n" +
		"Usage:  " + name + " [ OPTION | CONFIGFILE ]\n" +
		"    OPTION:\n" +
		"      -c|check:        List to-be-banned IPs without affecting the system.\n" +
		"      -o|once:         Add to-be-banned IPs in a single run (or from 'cron').\n" +
		"      -i|install:      Install the binary, a template for the configfile, the\n" +
		"                       systemd unit file and enable & start the service.\n" +
		"      -u|uninstall:    Stop & disable the service and remove the unit file.\n" +
		"      -h|help:         Show this help text.\n" +
    "      -V|version:      Show the version.\n" +
		"    CONFIGFILE:        Used if given, otherwise '" + name + ".yml' in the current\n" +
		"                       directory or finally '/etc/" + name + ".yml' will get used.\n" +
		"  Privileges are required to run, except for 'check', 'help' and 'version'."
	fmt.Println(help)
	if msg != "" {
		fmt.Println("\n", msg)
		os.Exit(1)
	}

	os.Exit(0)
}

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

	for _, ip := range whitelist {
		if ip == ipaddr {
			return
		}
	}
	if !check {
		err = ipt.AppendUnique("mangle", "FAIL2DROP", "--src", ipaddr, "-j", "DROP")
		if err != nil {
			log.Fatalln(err)
		}
	}

	log.Printf("[%s v%s] '%s' ban %s\n", name, version, set, ipaddr)
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
		banip(ipaddr, logsearch.set)
		record.added = true
	}
}

func follow(logsearch logsearch) {
	if check || once {
		t, err := tail.TailFile(logsearch.logfile, tail.Config{MustExist:true, CompleteLines:true})
		if err == nil {
			for line := range t.Lines {
				process(logsearch, line.Text)
			}
		}
	} else {
		defer wg.Done()
		t, err := tail.TailFile(logsearch.logfile, tail.Config{MustExist:true, CompleteLines:true, Follow:true, ReOpen:true})
		if err == nil {
			for line := range t.Lines {
				process(logsearch, line.Text)
			}
		}
	}
}

func initnf() {
	if check {
		return
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
	// Write the binary if not in PATH
	exec.Command("systemctl", "stop", name).Run()
	bin, err := os.ReadFile(os.Args[0])
	if err == nil {
		err = os.WriteFile(prefix+name, bin, 0755)
		if err != nil {
			if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ETXTBSY) {
				log.Fatalln("insufficient permissions, run with root privileges")
			}

			log.Fatalln(err)
		}
		os.Chown(prefix+name, 0, 0)
	}

	var f *os.File
	f, err = os.OpenFile(config, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(cfgtmpl)
	}
	f.Close()

	f, err = os.Create(unitname)
	if err != nil {
		log.Fatalln(err, "could not create systemd unit file "+unitname)
	}

	exec.Command("systemctl", "stop", name).Run()
	_, err = f.WriteString(fmt.Sprintf(unittmpl, name, version, name, varlog, varlog))
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
	if len(os.Args) > 2 {
		usage("Too many arguments")
	}

	doinstall, given := false, false
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "help", "-h", "--help":
			usage("")
		case "version", "-V", "--version":
			fmt.Println(name + " v" + version)
			os.Exit(0)

		case "uninstall", "-u", "--uninstall":
			uninstall()

		case "install", "-i", "--install":
			doinstall = true
		case "check", "-c", "--check":
			check = true
		case "once", "-o", "--once":
			once = true
		default:
			config = os.Args[1]
			given = true
		}
	}

	var cfgdata []byte
	var err error
	if given { // If specified, only use that as config source
		cfgdata, err = os.ReadFile(config)
		if err != nil {
			log.Fatalln("Given configfile not found: " + config)
		}

	} else { // If not specified, check PWD
		cfgdata, err = os.ReadFile(name + ".yml")
		if err != nil { // If not in PWD, check /etc
			cfgdata, err = os.ReadFile(config)
			if err != nil {
				if doinstall {
					install()
				}

				log.Println("No configfile '" + name + ".yml' found in the current directory,")
				log.Fatalln("nor at the default location: " + config)
			}
		}
	}

	var cfg interface{}
	err = yaml.Unmarshal(cfgdata, &cfg)
	if err != nil {
		log.Fatalln("syntax error in the configfile: " + config)
	}

	cfgslice := cfg.(map[string]interface{})
	if doinstall {
		l, ok := cfgslice["varlog"]
		if ok {
			varlog = l.(string)
		}
		install()
	}

	initnf()
  for key, value := range cfgslice {
		switch key {
		case "varlog":
			varlog = value.(string)
		case "whitelist":
			if value != nil {
				for _, ip := range value.([]interface{}) {
					whitelist = append(whitelist, ip.(string))
				}
			}
		default:
			var logsearch logsearch
			logsearch.set = key
			count := 0
			values := value.(map[string]interface{})
			for k, v := range values {
				switch k {
				case "logfile":
					logsearch.logfile = v.(string)
					count += 1
				case "tag":
					logsearch.tag = v.(string)
					count += 1
				case "ipregex":
					logsearch.ipregex = v.(string)
					count += 1
				case "bancount":
					logsearch.bancount = v.(int)
					count += 1
				}
			}
			if count == 4 { // All 4 properties are needed
				if check || once {
					follow(logsearch)
				} else {
					wg.Add(1)
					go follow(logsearch)
				}
			}
		}
	}
	if !check && !once {
		wg.Wait()
	}
}
