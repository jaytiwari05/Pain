package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// ensureCert returns (certPath, keyPath) ready for ListenAndServeTLS.
// If the operator provided paths, those are used as-is.
// Otherwise a self-signed cert is auto-generated once in ListenerDataDir
// and reused on subsequent restores.
func ensureCert(certFile, keyFile, dataDir, listenerName string) (string, string, error) {
	if certFile != "" && keyFile != "" {
		return certFile, keyFile, nil
	}

	autoCert := filepath.Join(dataDir, listenerName+".crt")
	autoKey := filepath.Join(dataDir, listenerName+".key")

	if _, err := os.Stat(autoCert); os.IsNotExist(err) {
		fmt.Printf("[Pain Listener] generating self-signed cert: %s\n", autoCert)
		if err := generateSelfSignedCert(autoCert, autoKey); err != nil {
			return "", "", fmt.Errorf("cert generation failed: %w", err)
		}
	}

	return autoCert, autoKey, nil
}

func generateSelfSignedCert(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pain-c2"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}

	cf, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer cf.Close()
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	kf, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer kf.Close()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
