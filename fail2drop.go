package main

import (
	_ "embed"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"

	nf "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/nxadm/tail"
	"gopkg.in/yaml.v3"
)

const (
	version = "0.13.4"
	name    = "fail2drop"
	prefix  = "/usr/local/bin/"
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
	noaction = false
	once     = false
	wg       sync.WaitGroup
)

func usage(msg string) {
	help := name + " v" + version + " - Drop repeat-offending IP addresses in-kernel (netfilter)\n" +
		"Repo:   github.com/pepa65/fail2drop\n" +
		"Usage:  " + name + " [ OPTION | CONFIGFILE ]\n" +
		"    OPTION:\n" +
		"      -o|once:         Add to-be-banned IPs in a single run (or from 'cron').\n" +
		"      -n|noaction:     Do a 'once' single run without affecting the system.\n" +
		"      -i|install:      Install the binary, a template for the configfile, the\n" +
		"                       systemd unit file and enable & start the service.\n" +
		"      -u|uninstall:    Stop & disable the service and remove the unit file.\n" +
		"      -h|help:         Show this help text.\n" +
		"      -V|version:      Show the version.\n" +
		"    CONFIGFILE:        Used if given, otherwise '" + name + ".yml' in the current\n" +
		"                       directory or finally '/etc/" + name + ".yml' will get used.\n" +
		"  Privileges are required to run, except for 'noaction', 'help' and 'version'."
	fmt.Println(help)
	if msg != "" {
		fmt.Println("\n", msg)
		os.Exit(1)
	}

	os.Exit(0)
}

func banip(ipaddr, set string) {
	for _, ip := range whitelist {
		if ip == ipaddr {
			return
		}
	}

	if !noaction {
		var err error
		conn := &nf.Conn{}
		fail2drop := &nf.Table{}
		tables, _ := conn.ListTablesOfFamily(nf.TableFamilyINet)
		for _, t := range tables {
			if t.Name == "fail2drop" {
	 			fail2drop = t
				break
			}
		}
		if fail2drop.Name != "fail2drop" {
			log.Fatalln("Error: nftable table inet fail2drop not found")
		}

		chain := &nf.Chain{}
		chains, _ := conn.ListChainsOfTableFamily(nf.TableFamilyINet)
		for _, c := range chains {
			if c.Name == "FAIL2DROP" {
				chain = c
				break
			}
		}
		if chain.Name != "FAIL2DROP" {
			log.Fatalln("Error: nftable chain FAIL2DROP on table inet fail2drop not found")
		}

		rule := &nf.Rule{}
		rules, _ := conn.GetRules(fail2drop, chain)
		for _, r := range rules { // Use UserData (IP) as ID for a rule
			if string(r.UserData) == ipaddr {
				return
			}
		}

		if strings.Contains(ipaddr, ".") { // IPv4
			// nft add rule inet fail2drop FAIL2DROP ip saddr IPADDR counter drop
			rule = &nf.Rule{
				UserData: []byte(ipaddr),
				Table:    fail2drop,
				Chain:    chain,
				Exprs:    []expr.Any{
					// payload ip => reg 1
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       12,
						Len:          4,
					},
					// compare reg 1 eq to IPADDR
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte(net.ParseIP(ipaddr).To4()),
					},
					&expr.Counter{Bytes: 0, Packets: 0},
					// immediate reg 0 drop
					&expr.Verdict{
						Kind: expr.VerdictDrop,
					},
				},
			}
		} else { // IPv6
			// nft add rule inet fail2drop FAIL2DROP ip6 saddr IPADDR counter drop
			rule = &nf.Rule{
				UserData: []byte(ipaddr),
				Table:    fail2drop,
				Chain:    chain,
				Exprs:    []expr.Any{
					// payload ip6 => reg 1
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       8,
						Len:          16,
					},
					// compare reg 1 eq to IPADDR
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte(net.ParseIP(ipaddr)),
					},
					&expr.Counter{Bytes: 0, Packets: 0},
					// immediate reg 0 drop
					&expr.Verdict{
						Kind: expr.VerdictDrop,
					},
				},
			}
		}
		conn.AddRule(rule)
		err = conn.Flush()
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
	defer wg.Done()
	var t *tail.Tail
	var err error
	if once {
		t, err = tail.TailFile(logsearch.logfile, tail.Config{MustExist: true, CompleteLines: true})
	} else {
		t, err = tail.TailFile(logsearch.logfile, tail.Config{MustExist: true, CompleteLines: true, Follow: true, ReOpen: true})
	}
	if err == nil {
		for line := range t.Lines {
			process(logsearch, line.Text)
		}
	}
}

func initnf() {
	if noaction {
		return
	}

	conn := &nf.Conn{}
	// nft delete table inet fail2drop
	conn.DelTable(&nf.Table{Name: "fail2drop"})
	conn.Flush()
	fail2drop := &nf.Table{
		Family: nf.TableFamilyINet,
		Name:   "fail2drop",
	}
	// nft add table inet fail2drop
	fail2drop = conn.AddTable(fail2drop)
	// nft add chain inet fail2drop FAIL2DROP
	chain := &nf.Chain{
		Name:    "FAIL2DROP",
		Table:   fail2drop,
		Type:    nf.ChainTypeFilter,
		Hooknum: nf.ChainHookPrerouting,
		Priority: nf.ChainPriorityRaw,
	}
	chain = conn.AddChain(chain)
	conn.Flush()
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
		case "noaction", "-n", "--noaction", "check", "-c", "--check":
			noaction, once = true, true
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
	var logsearches []logsearch
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
				logsearches = append(logsearches, logsearch)
			}
		}
	}
	for _, logsearch := range logsearches {
		wg.Add(1)
		go follow(logsearch)
	}
	wg.Wait()
}
