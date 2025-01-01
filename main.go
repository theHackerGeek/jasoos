package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"

	_ "github.com/mattn/go-sqlite3"
)

// ScanResult holds details of a scan.
type ScanResult struct {
	Target          string   `json:"target"`
	Ports           []string `json:"ports"`
	Services        []string `json:"services"`
	OS              string   `json:"os"`
	Vulnerabilities []string `json:"vulnerabilities"`
}

func main() {
	// Initialize database
	db, err := sql.Open("sqlite3", "jasoos_results.db")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create a table for storing scan results
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS results (
		target TEXT,
		ports TEXT,
		services TEXT,
		os TEXT,
		vulnerabilities TEXT
	)`)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	// Prompt for target
	var target string
	fmt.Print("Enter target IP or domain: ")
	fmt.Scanln(&target)

	// Perform scans
	ports := performPortScan(target)
	services := performServiceEnumeration(target, ports)
	os := performOSFingerprinting(target)
	vulnerabilities := checkVulnerabilities(services)

	// Store result in the database
	scanResult := ScanResult{
		Target:          target,
		Ports:           ports,
		Services:        services,
		OS:              os,
		Vulnerabilities: vulnerabilities,
	}
	storeResults(db, scanResult)

	// Generate a report
	generateReport(scanResult)
}

func performPortScan(target string) []string {
	fmt.Println("Running port scan...")
	cmd := exec.Command("nmap", "-p-", "-T4", "-oG", "-", target)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to run nmap: %v", err)
	}
	// Parse output for open ports (simplified example)
	ports := []string{"80", "443"} // Replace with actual parsing logic
	return ports
}

func performServiceEnumeration(target string, ports []string) []string {
	fmt.Println("Enumerating services...")
	// Simulate service enumeration output
	services := []string{"HTTP (Apache)", "HTTPS (Nginx)"} // Replace with real logic
	return services
}

func performOSFingerprinting(target string) string {
	fmt.Println("Performing OS fingerprinting...")
	cmd := exec.Command("nmap", "-O", target)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to perform OS fingerprinting: %v", err)
	}
	// Simulate OS detection
	return "Linux" // Replace with real parsing logic
}

func checkVulnerabilities(services []string) []string {
	fmt.Println("Checking vulnerabilities...")
	// Simulate vulnerability check output
	vulnerabilities := []string{"CVE-2021-12345: Apache HTTPD 2.4.49 Path Traversal"}
	return vulnerabilities
}

func storeResults(db *sql.DB, result ScanResult) {
	portsJSON, _ := json.Marshal(result.Ports)
	servicesJSON, _ := json.Marshal(result.Services)
	vulnerabilitiesJSON, _ := json.Marshal(result.Vulnerabilities)

	_, err := db.Exec(`INSERT INTO results (target, ports, services, os, vulnerabilities) VALUES (?, ?, ?, ?, ?)`,
		result.Target, string(portsJSON), string(servicesJSON), result.OS, string(vulnerabilitiesJSON))
	if err != nil {
		log.Fatalf("Failed to insert results: %v", err)
	}
	fmt.Println("Scan results stored in database.")
}

func generateReport(result ScanResult) {
	fmt.Println("Generating report...")
	report := fmt.Sprintf(`Scan Report for %s

Ports:
%s

Services:
%s

Operating System:
%s

Vulnerabilities:
%s
`,
		result.Target, result.Ports, result.Services, result.OS, result.Vulnerabilities)

	reportFile := "jasoos_report.txt"
	if err := os.WriteFile(reportFile, []byte(report), 0644); err != nil {
		log.Fatalf("Failed to write report: %v", err)
	}
	fmt.Printf("Report saved as %s\n", reportFile)
}
