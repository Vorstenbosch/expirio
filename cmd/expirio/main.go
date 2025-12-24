package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"
	"github.com/vorstenbosch/expirio/internal/model"
)

func main() {
    args := os.Args[1:]
    
    if len(args) < 1 {
        fmt.Println("Usage: expirio [options] <host1> <host2> ...")
        os.Exit(1)
    }

    var hostsInfo []model.HostInfo

    for _, host := range args {
        hostInfo, err := getHostInfo(host)
        if err != nil {
            fmt.Printf("Error retrieving info for host %s: %v\n", host, err)
        }

        hostsInfo = append(hostsInfo, hostInfo)
    }

    printHostsInfo(hostsInfo)
}

func getHostInfo(host string) (model.HostInfo, error) {
    hostInfo := model.HostInfo{Host: host}
    
    // Add port if not specified
    if _, _, err := net.SplitHostPort(host); err != nil {
        host = net.JoinHostPort(host, "443")
    }

    // Connect with TLS, skip verification to allow self-signed
    conn, err := tls.Dial("tcp", host, &tls.Config{
        InsecureSkipVerify: true,
    })
    if err != nil {
        return hostInfo, fmt.Errorf("error connecting: %w", err)
    }
    defer conn.Close()

    // Get certificates
    certs := conn.ConnectionState().PeerCertificates
    if len(certs) == 0 {
        return hostInfo, fmt.Errorf("no certificates found")
    }

    // Get system cert pool for verification
    roots, err := x509.SystemCertPool()
    if err != nil {
        return hostInfo, fmt.Errorf("failed to load system cert pool: %w", err)
    }

    // Extract hostname for verification
    hostname, _, _ := net.SplitHostPort(host)

    for _, cert := range certs {
        // Verify certificate against system roots
        opts := x509.VerifyOptions{
            Roots:         roots,
            DNSName:       hostname,
            Intermediates: x509.NewCertPool(),
        }
        
        // Add intermediate certs
        for i := 1; i < len(certs); i++ {
            opts.Intermediates.AddCert(certs[i])
        }

        _, verifyErr := cert.Verify(opts)
        trusted := verifyErr == nil

        certInfo := model.CertificateInfo{
            Host:          host,
            Issuer:        cert.Issuer.CommonName,
            ValidFrom:     cert.NotBefore.Format(time.RFC3339),
            ValidTo:       cert.NotAfter.Format(time.RFC3339),
            DaysRemaining: int(time.Until(cert.NotAfter).Hours() / 24),
            Trusted:       trusted,
        }
        hostInfo.CertificatesInfo = append(hostInfo.CertificatesInfo, certInfo)
    }

    return hostInfo, nil
}


func printHostsInfo(hostsInfo []model.HostInfo) {
	for _, hostInfo := range hostsInfo {
		fmt.Printf("Host: %s\n", hostInfo.Host)
		for _, certInfo := range hostInfo.CertificatesInfo {
			fmt.Printf("  Certificate:\n")
			fmt.Printf("    Issuer: %s\n", certInfo.Issuer)
			fmt.Printf("    Valid From: %s\n", certInfo.ValidFrom)
			fmt.Printf("    Valid To: %s\n", certInfo.ValidTo)
			fmt.Printf("    Days Remaining: %d\n", certInfo.DaysRemaining)
			fmt.Printf("    Trusted: %t\n", certInfo.Trusted)
		}
		fmt.Println()
	}
}
