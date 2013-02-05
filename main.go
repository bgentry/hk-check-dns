package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	r := mux.NewRouter()
	r.NotFoundHandler = http.HandlerFunc(NotFoundHandler)
	r.HandleFunc("/lookup/{hostname}", LookupHandler)
	r.HandleFunc("/verify_target/{hostname1}/{hostname2}", VerifyTargetHandler)
	http.Handle("/", r)

	err := loadRootConfig()
	if err != nil {
		log.Fatal("Error loading root config:", err.Error())
	}

	err = http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func NotFoundHandler(w http.ResponseWriter, req *http.Request) {
	http.Error(w, "{\"error\": \"not found\"}", 404)
}

func LookupHandler(w http.ResponseWriter, req *http.Request) {
	domainname := dns.Fqdn(mux.Vars(req)["hostname"])
	nocache := req.URL.Query().Get("nocache") != ""

	cr, err := LookupDNS(domainname, nocache)
	if err != nil {
		http.Error(w, fmt.Sprintf("{\"error\": %q}", err.Error()), 500)
		return
	}
	json.NewEncoder(w).Encode(cr)
	return
}

func VerifyTargetHandler(w http.ResponseWriter, req *http.Request) {
	hostname1 := dns.Fqdn(mux.Vars(req)["hostname1"])
	hostname2 := dns.Fqdn(mux.Vars(req)["hostname2"])
	nocache := req.URL.Query().Get("nocache") != ""

	cr, err := LookupDNS(hostname1, nocache)
	if err != nil {
		http.Error(w, fmt.Sprintf("{\"error\": %q, \"hostname\": %q}", err.Error(), hostname1), 500)
		return
	}

	if cr.CNAME == hostname2 {
		// it's a direct CNAME, that makes it easy
		json.NewEncoder(w).Encode(VerifyResponse{
			Status:  "ok",
			Code:    1,
			Message: "direct CNAME match",
			Data:    map[string]*CheckDNSResponse{hostname1: cr},
		})
		return
	}

	// else need to resolve hostname2
	cr2, err := LookupDNS(hostname2, nocache)
	if err != nil {
		http.Error(w, fmt.Sprintf("{\"error\": %q, \"hostname\": %q}", err.Error(), hostname2), 500)
		return
	}

	if cr2.CNAME == hostname2 {
		// indirect CNAME / CNAME chain
		json.NewEncoder(w).Encode(VerifyResponse{
			Status:  "warning",
			Code:    3,
			Message: "indirect CNAME / CNAME chain",
			Data:    map[string]*CheckDNSResponse{hostname1: cr, hostname2: cr2},
		})
		return
	}

	for _, a := range cr.A {
		for _, a2 := range cr2.A {
			if a == a2 {
				// ALIAS or static IP match
				json.NewEncoder(w).Encode(VerifyResponse{
					Status:  "warning",
					Code:    2,
					Message: "ALIAS or Static IP match",
					Data:    map[string]*CheckDNSResponse{hostname1: cr, hostname2: cr2},
				})
				return
			}
		}
	}

	json.NewEncoder(w).Encode(VerifyResponse{
		Status:  "error",
		Code:    0,
		Message: "no matches",
		Data:    map[string]*CheckDNSResponse{hostname1: cr, hostname2: cr2},
	})
	return
}

type VerifyResponse struct {
	Status  string                       `json:"status"`
	Code    int                          `json:"code"`
	Message string                       `json:"message"`
	Data    map[string]*CheckDNSResponse `json:"data"`
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
		return rootConfig.Servers[0], nil
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
