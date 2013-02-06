package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"net/http"
	"os"
)

var authuser, authpassword string

func main() {
	port := envStringOrDefault("PORT", "5000")
	authuser = envStringOrDefault("AUTH_USER", "user")
	authpassword = envStringOrDefault("AUTH_PASSWORD", "changeme")

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

func envStringOrDefault(name, defaultvalue string) string {
	val := os.Getenv(name)
	if val == "" {
		return defaultvalue
	}
	return val
}

func getBasicAuth(r *http.Request) (username string, password string) {
	authString := r.Header.Get("Authorization")
	if len(authString) > 6 && string(authString[0:5]) == "Basic" {
		creds, err := base64.StdEncoding.DecodeString(authString[6:])
		if err != nil {
			log.Printf("level=error type=credential_decode_error message=%q", err.Error())
			return "", ""
		}
		username, password = split(string(creds), ':', true)
	}
	return
}

func split(s string, c byte, cutc bool) (string, string) {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			if cutc {
				return s[0:i], s[i+1:]
			}
			return s[0:i], s[i:]
		}
	}
	return s, ""
}

func checkAuth(r *http.Request, username string, password string) bool {
	u, p := getBasicAuth(r)
	return u == username && p == password
}

func UnauthorizedResponse(w http.ResponseWriter) {
	http.Error(w, "{\"error\": \"unauthorized\"}", 401)
}

func NotFoundHandler(w http.ResponseWriter, req *http.Request) {
	http.Error(w, "{\"error\": \"not found\"}", 404)
}

func LookupHandler(w http.ResponseWriter, req *http.Request) {
	if !checkAuth(req, authuser, authpassword) {
		UnauthorizedResponse(w)
		return
	}

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
	if !checkAuth(req, authuser, authpassword) {
		UnauthorizedResponse(w)
		return
	}

	hostname1 := dns.Fqdn(mux.Vars(req)["hostname1"])
	hostname2 := dns.Fqdn(mux.Vars(req)["hostname2"])
	nocache := req.URL.Query().Get("nocache") != ""

	target_alias := req.URL.Query().Get("target_alias")
	if target_alias != "" {
		target_alias = dns.Fqdn(target_alias)
	}

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

	// Since it's not a direct CNAME, we need to resolve the A records of either
	// target_alias or hostname2
	target_host := hostname2
	if target_alias != "" {
		target_host = target_alias
	}

	cr2, err := LookupDNS(target_host, nocache)
	if err != nil {
		http.Error(w, fmt.Sprintf("{\"error\": %q, \"hostname\": %q}", err.Error(), target_host), 500)
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
					Data:    map[string]*CheckDNSResponse{hostname1: cr, target_host: cr2},
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
