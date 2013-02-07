package main

import (
	"fmt"
	"github.com/miekg/dns"
	"math/rand"
)

type VerifyResponse struct {
	Status  string                       `json:"status"`
	Code    int                          `json:"code"`
	Message string                       `json:"message"`
	Data    map[string]*CheckDNSResponse `json:"data"`
	Error   *LookupError                 `json:"error,omitempty"`
}

type LookupError struct {
	Error    string `json:"error"`
	Hostname string `json:"hostname,omitempty"`
}

func VerifyTarget(host1, host2, target_alias string, nocache bool) (VerifyResponse, error) {
	cr, err := LookupDNS(host1, nocache)
	if err != nil {
		return VerifyResponse{Error: &LookupError{
			Error:    err.Error(),
			Hostname: host1,
		}}, err
	}

	if cr.CNAME == host2 {
		// it's a direct CNAME, that makes it easy
		return VerifyResponse{
			Status:  "ok",
			Code:    1,
			Message: "direct CNAME match",
			Data:    map[string]*CheckDNSResponse{host1: cr},
		}, nil
	}

	// Since it's not a direct CNAME, we need to resolve the A records of either
	// target_alias or host2
	target_host := host2
	if target_alias != "" {
		target_host = target_alias
	}

	cr2, err := LookupDNS(target_host, nocache)
	if err != nil {
		return VerifyResponse{Error: &LookupError{
			Error:    err.Error(),
			Hostname: target_host,
		}}, err
	}

	for _, a := range cr.A {
		for _, a2 := range cr2.A {
			if a == a2 {
				// ALIAS or static IP match
				return VerifyResponse{
					Status:  "warning",
					Code:    2,
					Message: "ALIAS or Static IP match",
					Data:    map[string]*CheckDNSResponse{host1: cr, target_host: cr2},
				}, nil
			}
		}
	}

	return VerifyResponse{
		Status:  "no_match",
		Code:    0,
		Message: "no matches",
		Data:    map[string]*CheckDNSResponse{host1: cr, host2: cr2},
	}, nil
}

func LookupDNS(domainname string, nocache bool) (*CheckDNSResponse, error) {
	var lastns string
	var err error

	if nocache {
		lastns, err = RecursiveNS(domainname)
		if err != nil {
			return nil, fmt.Errorf("error getting authoritative NS: %q", err.Error())
		}
	} else {
		lastns = rootConfig.Servers[0]
	}

	c := &dns.Client{Net: "tcp"}

	m := new(dns.Msg)
	m.SetQuestion(domainname, dns.TypeANY)
	r, _, err := c.Exchange(m, lastns+":53")
	if err != nil {
		return nil, fmt.Errorf("error getting ANY %q: %q", domainname, err.Error())
	}

	alist, cname := GetCnameAndAFromMsg(r, domainname)

	m = new(dns.Msg)
	m.SetQuestion(domainname, dns.TypeA)
	r, _, err = c.Exchange(m, lastns+":53")
	if err != nil {
		return nil, fmt.Errorf("error getting A for %q: %q", domainname, err.Error())
	}

	alist2, cname2 := GetCnameAndAFromMsg(r, domainname)
	if cname == "" {
		cname = cname2
	}
	for _, a := range alist2 {
		alist = AppendIfMissing(alist, a)
	}

	cr := &CheckDNSResponse{
		A:      alist,
		CNAME:  cname,
		LastNS: lastns,
	}
	return cr, nil
}

func GetCnameAndAFromMsg(m *dns.Msg, hostname string) (alist []string, cname string) {
	alist = make([]string, 0)

	if len(m.Answer) > 0 {
		for _, rec := range m.Answer {
			if a, ok := rec.(*dns.A); ok {
				if a.Hdr.Name == hostname {
					alist = AppendIfMissing(alist, a.A.String())
				}
			} else if cn, ok := rec.(*dns.CNAME); ok {
				if cn.Hdr.Name == hostname && cname == "" {
					cname = cn.Target
				}
			}
		}
	}
	return
}

type CheckDNSResponse struct {
	A      []string
	CNAME  string
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
	fulldomain := dns.Fqdn(hostname)
	c := &dns.Client{Net: "udp"}

	labels := dns.SplitLabels(fulldomain)
	return recurseNS(c, fulldomain, labels)
}

var rootns = []string{
	"a.root-servers.net", "b.root-servers.net", "c.root-servers.net",
	"d.root-servers.net", "e.root-servers.net", "f.root-servers.net",
	"g.root-servers.net", "h.root-servers.net", "i.root-servers.net",
	"j.root-servers.net", "k.root-servers.net", "l.root-servers.net",
	"m.root-servers.net"}

func recurseNS(c *dns.Client, fulldomain string, labels []string) (string, error) {
	var lastns string
	if len(labels) > 0 {
		var err error
		lastns, err = recurseNS(c, fulldomain, labels[1:])
		if err != nil {
			fmt.Printf("ERROR WITH LABELS %v: %s\n", labels, err.Error())
			return "", err
		}
	} else {
		return rootns[rand.Intn(len(rootns))], nil
	}

	m := new(dns.Msg)
	m.SetQuestion(fulldomain, dns.TypeA)
	r, _, err := c.Exchange(m, lastns+":53")
	if err != nil {
		return "", fmt.Errorf("error getting NS for %q: %q", fulldomain, err.Error())
	}

	nslist := make([]string, 0)
	if len(r.Ns) > 0 {
		for i := range r.Ns {
			if ns, ok := r.Ns[i].(*dns.NS); ok {
				nslist = append(nslist, ns.Ns)
			}
		}
	}

	if len(nslist) == 0 {
		return lastns, nil
	}

	return nslist[rand.Intn(len(nslist))], nil
}
