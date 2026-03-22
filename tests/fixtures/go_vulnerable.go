// Deliberately vulnerable Go code for testing
package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os/exec"
	"crypto/tls"
)

// SQL Injection
func getUser(db *sql.DB, name string) {
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}

func getUserFmt(db *sql.DB, id string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
	db.Query(query)
}

// Command Injection
func runCommand(input string) {
	exec.Command("bash", "-c", input).Run()
}

// Weak Hash
func hashData(data []byte) {
	h := md5.New()
	h.Write(data)
}

// Weak Random
func generateToken() int {
	return rand.Intn(1000000)
}

// TLS Skip Verify
func insecureClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

// Hardcoded Credentials
var password = "secret123"
var apiKey = "sk-1234567890abcdef"

// Path Traversal
func serveFile(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, r.URL.Path)
}
