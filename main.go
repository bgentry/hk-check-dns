package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/miekg/dns"
	"log"
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
	r.HandleFunc("/lookup/{hostname}", LookupHandler).Methods("GET")
	r.HandleFunc("/verify_target/{hostname1}/{hostname2}", VerifyTargetHandler).
		Methods("GET")
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

	vr, err := VerifyTarget(hostname1, hostname2, target_alias, nocache)
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(vr.Error)
		return
	}

	json.NewEncoder(w).Encode(vr)
	return
}
