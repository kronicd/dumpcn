package main
import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)
func worker(jobChan <-chan string, resChan chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	var transport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	config.VerifyPeerCertificate = func(certificates [][]byte, _ [][]*x509.Certificate) error {
		certs := make([]*x509.Certificate, len(certificates))
		for i, asn1Data := range certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return errors.New("tls: failed to parse certificate from server")
			}
			certs[i] = cert
		}
		opts := x509.VerifyOptions{
			Roots:         config.RootCAs, // On the server side, use config.ClientCAs.
			DNSName:       config.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err := certs[0].Verify(opts)
		if err != nil && strings.Contains(err.Error(), "certificate has expired or is not yet valid") {
		 	return nil
		 }
		return err
	}
	var client = &http.Client{
		Timeout:   time.Second * 10,
		Transport: transport,
	}
	for {
		job, ok := <-jobChan
		if !ok {
			return
		}
		if !strings.HasPrefix(job, "https://") {
			job = "https://" + job
		}
		req, reqErr := http.NewRequest("GET", job, nil)
		if reqErr != nil {
			continue
		}
		resp, clientErr := client.Do(req)
		if clientErr != nil {
			continue
		}
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			certChain := [][]byte{}
			cn := resp.TLS.PeerCertificates[0].Subject.CommonName
			config.ServerName = cn
			x := resp.TLS.PeerCertificates[:]
			for _, i := range x {
				certChain = append(certChain, i.Raw)
			}
			//fmt.Fprintf(os.Stderr, "%s,%s", config.ServerName, job)
			//resChan <- fmt.Sprintf("%s,%s", resp.TLS.PeerCertificates[0].Subject.CommonName, job)
			valid := config.VerifyPeerCertificate(certChain, [][]*x509.Certificate{})
			if valid != nil {
				fmt.Fprintf(os.Stderr,"Invalid: %s\n",job)
				// continue
			} else {
				resChan <- fmt.Sprintf("%s,%s", resp.TLS.PeerCertificates[0].Subject.CommonName, job)
			}
		}
	}
}
func main() {
	workers := flag.Int("t", 32, "numbers of threads")
	flag.Parse()
	scanner := bufio.NewScanner(os.Stdin)
	jobChan := make(chan string)
	resChan := make(chan string)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(*workers)
	go func() {
		wg.Wait()
		close(done)
	}()
	for i := 0; i < *workers; i++ {
		go worker(jobChan, resChan, &wg)
	}
	go func() {
		for scanner.Scan() {
			jobChan <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			log.Println(err)
		}
		close(jobChan)
	}()
	for {
		select {
		case <-done:
			return
		case res := <-resChan:
			fmt.Println(res)
		}
	}
}