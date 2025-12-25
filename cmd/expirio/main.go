package main

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "flag"
    "fmt"
    "net"
    "os"
    "strings"
    "time"
    "github.com/vorstenbosch/expirio/internal/model"
)

func main() {
    mode := flag.String("mode", "info", "mode of operation: info or warn")
    days := flag.Int("days", 30, "Number of days to warn before certificate expiration (only used in warn mode)")
    file := flag.String("file", "", "Path to file containing list of hosts (one per line)")
  
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "Usage: %s [options] <host1> <host2> ...\n\n", os.Args[0])
        fmt.Fprintf(os.Stderr, "Options:\n")
        flag.PrintDefaults()
    }

    flag.Parse()

    args := flag.Args() // remaining hosts after flags

    if len(args) < 1 || *mode != "info" && *mode != "warn" {
        flag.Usage()
        os.Exit(1)
    }

    var endpoints []model.Endpoint

    // Read hosts from file if specified
    if *file != "" {
        fileHosts, err := readHostsFromFile(*file)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
            os.Exit(1)
        }
        args = append(args, fileHosts...)
    }

    for _, host := range args {
        hostInfo, err := getHostInfo(host)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error retrieving info for host %s: %v\n", host, err)
        }

        endpoints = append(endpoints, hostInfo)
    }

    if *mode == "info" {
        printendpoints(endpoints)
    } else {
        for _, hostInfo := range endpoints {
            printWarningIfExpiring(hostInfo, *days)
        }
    }
}

func readHostsFromFile(filePath string) ([]string, error) {
    data, err := os.ReadFile(filePath)
    if err != nil {
        return nil, err
    }

    lines := []string{}
    for _, line := range strings.Split(string(data), "\n") {
        trimmed := strings.TrimSpace(line)
        if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
            lines = append(lines, trimmed)
        }
    }
    return lines, nil
}

func printWarningIfExpiring(hostInfo model.Endpoint, days int) {
    for _, certInfo := range hostInfo.CertificatesInfo {
        if certInfo.DaysRemaining <= days {
            printJSON(certInfo)
        }
    }
}

func getHostInfo(host string) (model.Endpoint, error) {
    hostInfo := model.Endpoint{Host: host}
    
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

    hostInfo.Port = fmt.Sprintf("%d", conn.RemoteAddr().(*net.TCPAddr).Port)

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


func printendpoints(endpoints []model.Endpoint) {
    printJSON(endpoints)
}

func printJSON[T any](data T) {
    jsonData, err := json.MarshalIndent(data, "", "  ")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
        os.Exit(1)
    }
    fmt.Println(string(jsonData))
}