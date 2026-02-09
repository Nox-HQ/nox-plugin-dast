package main

import (
	"crypto/tls"
	"net/http"
)

// DAST-001: Missing security headers - server sends responses without CSP, HSTS, etc.
func handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte("<html>Welcome</html>"))
}

// DAST-002: Insecure CORS - wildcard origin
func setupCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

// DAST-003: Missing TLS - plain HTTP and disabled cert verification
func startServer() {
	http.ListenAndServe(":8080", nil)
}

func insecureClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

var apiURL = "http://api.example.com/v1/data"

// DAST-004: Insecure cookie settings
func setCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   false,
		HttpOnly: false,
	}
	http.SetCookie(w, cookie)
}

// DAST-005: Missing rate limiting on API endpoint
func setupRoutes() {
	http.HandleFunc("/api/users", handleUsers)
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("users"))
}

// DAST-006: Open redirect - user input used in redirect
func handleLogin(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("next")
	http.Redirect(w, r, next, http.StatusFound)
}

func handleRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}
