package main

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	http.HandleFunc("/", DNSHandler)

	err := loadRootConfig()
	if err != nil {
		log.Fatal("Error loading root config:", err.Error())
	}

	err = http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func DNSHandler(w http.ResponseWriter, req *http.Request) {
	domainname, err := url.QueryUnescape(strings.Trim(req.URL.Path, "/"))
	if err != nil {
		http.Error(w, "Invalid domainname", 400)
		return
	}
	domainname = dns.Fqdn(domainname)

	nocache := req.URL.Query().Get("nocache") != ""

	var lastns string

	if nocache {
		lastns, err = getAuthoritativeNS(domainname)
		if err != nil {
			http.Error(w, fmt.Sprintf("error getting authoritative NS: %q", err.Error()), 500)
			return
		}
	} else {
		lastns = rootConfig.Servers[0]
	}

	c := &dns.Client{Net: "tcp"}

	m := new(dns.Msg)
	m.SetQuestion(domainname, dns.TypeANY)
	r, _, err := c.Exchange(m, lastns+":53")
	if err != nil {
		http.Error(w, fmt.Sprintf("error getting ANY for %q: %q", domainname, err.Error()), 500)
		return
	}

	// TODO: need to filter out results for hostnames I'm not looking for
	cnamelist, alist := GetCnameAndAFromMsg(r, domainname)

	m = new(dns.Msg)
	m.SetQuestion(domainname, dns.TypeA)
	r, _, err = c.Exchange(m, lastns+":53")
	if err != nil {
		http.Error(w, fmt.Sprintf("error getting A for %q: %q", domainname, err.Error()), 500)
		return
	}

	cnamelist2, alist2 := GetCnameAndAFromMsg(r, domainname)
	for _, c := range cnamelist2 {
		cnamelist = AppendIfMissing(cnamelist, c)
	}
	for _, a := range alist2 {
		alist = AppendIfMissing(alist, a)
	}

	json.NewEncoder(w).Encode(CheckDNSResponse{
		A:      alist,
		CNAME:  cnamelist,
		LastNS: lastns,
	})
	return
}

func GetCnameAndAFromMsg(m *dns.Msg, hostname string) (cnamelist []string, alist []string) {
	cnamelist = make([]string, 0)
	alist = make([]string, 0)

	if len(m.Answer) > 0 {
		for _, rec := range m.Answer {
			if a, ok := rec.(*dns.A); ok {
				if a.Hdr.Name == hostname {
					alist = AppendIfMissing(alist, a.A.String())
				}
			} else if cname, ok := rec.(*dns.CNAME); ok {
				if cname.Hdr.Name == hostname {
					cnamelist = AppendIfMissing(cnamelist, cname.Target)
				}
			}
		}
	}
	return
}

func getAuthoritativeNS(domainname string) (string, error) {
	lastns, err := RecursiveNS(domainname)
	if err != nil {
		return "", err
	}
	return lastns, nil
}

type CheckDNSResponse struct {
	A      []string
	CNAME  []string
	LastNS string
}

func AppendIfMissing(slice []string, s string) []string {
	for _, ele := range slice {
		if ele == s {
			return slice
		}
	}
	return append(slice, s)
}

var rootConfig *dns.ClientConfig

func loadRootConfig() (err error) {
	rootConfig, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return err
	}
	return nil
}

func RecursiveNS(hostname string) (string, error) {
	subdomains := strings.Split(dns.Fqdn(hostname), ".")
	c := &dns.Client{Net: "udp"}

	return recurseNS(c, subdomains)
}

func recurseNS(c *dns.Client, subdomains []string) (string, error) {
	var lastns string
	if len(subdomains) > 1 {
		var err error
		lastns, err = recurseNS(c, subdomains[1:])
		if err != nil {
			fmt.Printf("ERROR WITH SUBDOMAINS %v: %s\n", subdomains, err.Error())
			return "", err
		}
	} else {
		return rootConfig.Servers[0], nil
	}

	domainname := dns.Fqdn(strings.Join(subdomains, "."))

	m := new(dns.Msg)
	m.SetQuestion(domainname, dns.TypeNS)
	r, _, err := c.Exchange(m, lastns+":53")
	if err != nil {
		return "", fmt.Errorf("error getting NS for %q: %q", domainname, err.Error())
	}

	nslist := make([]string, 0)
	if len(r.Answer) > 0 {
		if ns, ok := r.Answer[0].(*dns.NS); ok {
			nslist = append(nslist, ns.Ns)
		}
	} else if len(r.Ns) > 0 {
		if ns, ok := r.Ns[0].(*dns.NS); ok {
			nslist = append(nslist, ns.Ns)
		}
	}

	if len(nslist) == 0 {
		return lastns, nil
	}

	return nslist[rand.Intn(len(nslist))], nil
}
