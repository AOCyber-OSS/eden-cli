package daemon

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	caCertFile = "ca-cert.pem"
	caKeyFile  = "ca-key.pem"
	maxCache   = 1024

	// caSupersededFile holds CA certificates that were replaced on disk but
	// may still be trusted in the keychain. TrustCA removes them from the
	// keychain and then deletes this file.
	caSupersededFile = "ca-cert.superseded.pem"

	// caPermittedDomain is the only DNS name space the CA may sign for. The
	// leading dot permits every name under .test (eden.test, foo.eden.test)
	// and nothing else, so a leaked CA key cannot mint a trusted certificate
	// for a real domain.
	caPermittedDomain = ".test"

	// caLifetime bounds how long a leaked CA key stays useful. An expired or
	// unconstrained CA is regenerated on load (see loadCA).
	caLifetime = 825 * 24 * time.Hour
)

// caExcludedIPRanges excludes every IPv4 and IPv6 address. Leaves are only
// ever issued for SNI DNS names, so the CA has no reason to sign an IP SAN.
func caExcludedIPRanges() []*net.IPNet {
	return []*net.IPNet{
		{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	}
}

// CA holds a local certificate authority for generating on-demand leaf certs.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	mu      sync.RWMutex
	cache   map[string]*tls.Certificate

	// replaced is true when loading found a CA that had expired or lacked
	// the required NameConstraints and generated a new one in its place.
	replaced bool
}

// Replaced reports whether LoadOrCreateCA replaced an existing CA (expired or
// missing NameConstraints). The new CA is not trusted until `eden dev setup`
// runs TrustCA, which also removes the old one from the keychain.
func (ca *CA) Replaced() bool { return ca.replaced }

// LoadOrCreateCA loads an existing CA from caDir, or generates a new one if
// the cert/key files do not exist.
func LoadOrCreateCA(caDir string) (*CA, error) {
	certPath := filepath.Join(caDir, caCertFile)
	keyPath := filepath.Join(caDir, caKeyFile)

	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)

	if certExists && keyExists {
		return loadCA(certPath, keyPath)
	}

	if certExists != keyExists {
		slog.Warn("ca: partial CA files found, regenerating",
			"cert_exists", certExists,
			"key_exists", keyExists,
		)
	}

	return createCA(caDir)
}

// loadCA reads existing PEM files and parses the CA certificate and key.
func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("ca: failed to decode cert PEM from %s", certPath)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing certificate: %w", err)
	}

	// Replace a CA that has expired or predates the NameConstraints fix. The
	// old certificate is recorded so TrustCA can remove it from the keychain:
	// an unconstrained root stays trusted for every domain until it is gone.
	reason := ""
	switch {
	case time.Now().After(cert.NotAfter):
		reason = "certificate expired"
	case !hasRequiredConstraints(cert):
		reason = "certificate lacks NameConstraints"
	}
	if reason != "" {
		caDir := filepath.Dir(certPath)
		slog.Warn("ca: replacing CA; run 'eden dev setup' to trust the new one and remove the old one from the keychain",
			"reason", reason, "expires", cert.NotAfter)
		if err := recordSuperseded(caDir, certBlock.Bytes); err != nil {
			return nil, err
		}
		ca, err := createCA(caDir)
		if err != nil {
			return nil, err
		}
		ca.replaced = true
		return ca, nil
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("ca: failed to decode key PEM from %s", keyPath)
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing private key: %w", err)
	}

	slog.Info("ca: loaded existing CA", "subject", cert.Subject.CommonName, "expires", cert.NotAfter.Format("2006-01-02"))

	return &CA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

// hasRequiredConstraints reports whether cert carries the critical
// NameConstraints this package now requires of its CA.
func hasRequiredConstraints(cert *x509.Certificate) bool {
	if !cert.PermittedDNSDomainsCritical {
		return false
	}
	if len(cert.PermittedDNSDomains) != 1 || cert.PermittedDNSDomains[0] != caPermittedDomain {
		return false
	}
	return len(cert.ExcludedIPRanges) >= 2
}

// recordSuperseded appends a replaced CA certificate to the superseded file.
// Appending (not overwriting) keeps every replaced root until TrustCA has
// removed each one from the keychain.
func recordSuperseded(caDir string, certDER []byte) error {
	f, err := os.OpenFile(filepath.Join(caDir, caSupersededFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("ca: recording superseded CA: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		f.Close()
		return fmt.Errorf("ca: recording superseded CA: %w", err)
	}
	return f.Close()
}

// readSupersededCerts returns the CA certificates recorded as superseded in
// caDir, or none if there are none.
func readSupersededCerts(caDir string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Join(caDir, caSupersededFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ca: reading superseded CAs: %w", err)
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ca: parsing superseded CA: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// createCA generates a new ECDSA P-256 CA and writes PEM files to caDir.
func createCA(caDir string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: generating serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Eden Dev CA",
			Organization: []string{"Eden Development"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour), // back-date slightly
		NotAfter:              time.Now().Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,

		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{caPermittedDomain},
		ExcludedIPRanges:            caExcludedIPRanges(),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("ca: creating certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing created certificate: %w", err)
	}

	// Encode PEM.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("ca: marshalling key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Write files.
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		return nil, fmt.Errorf("ca: creating directory: %w", err)
	}

	// Key first, then cert: a running daemon (ReloadingCA) only switches once
	// the files form a matching pair.
	if err := os.WriteFile(filepath.Join(caDir, caKeyFile), keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("ca: writing key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(caDir, caCertFile), certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("ca: writing cert: %w", err)
	}

	slog.Info("ca: generated new CA", "dir", caDir, "expires", cert.NotAfter.Format("2006-01-02"))

	return &CA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

// GetCertificate returns a TLS certificate for the given hostname. It is
// designed to be used as tls.Config.GetCertificate. Certificates are generated
// on demand and cached.
func (ca *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	hostname := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if hostname == "" {
		return nil, fmt.Errorf("ca: no SNI hostname in TLS handshake")
	}
	if !strings.HasSuffix(hostname, caPermittedDomain) {
		return nil, fmt.Errorf("ca: refusing to issue a certificate for %q (outside %s)", hostname, caPermittedDomain)
	}

	// Check cache with read lock.
	ca.mu.RLock()
	if cached, ok := ca.cache[hostname]; ok {
		ca.mu.RUnlock()
		return cached, nil
	}
	ca.mu.RUnlock()

	// Generate new leaf cert.
	leafCert, err := ca.generateLeaf(hostname)
	if err != nil {
		return nil, err
	}

	// Store in cache with write lock.
	ca.mu.Lock()
	// Evict half the cache if at capacity.
	if len(ca.cache) >= maxCache {
		count := 0
		for k := range ca.cache {
			delete(ca.cache, k)
			count++
			if count >= maxCache/2 {
				break
			}
		}
		slog.Debug("ca: evicted cache entries", "evicted", count)
	}
	ca.cache[hostname] = leafCert
	ca.mu.Unlock()

	slog.Debug("ca: generated leaf cert", "hostname", hostname)
	return leafCert, nil
}

// generateLeaf creates a new leaf certificate signed by the CA for the given hostname.
func (ca *CA) generateLeaf(hostname string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generating leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: generating leaf serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{hostname},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("ca: creating leaf certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER, ca.cert.Raw},
		PrivateKey:  key,
	}

	return tlsCert, nil
}

// CertPEMPath returns the path to the CA certificate PEM file.
func (ca *CA) CertPEMPath(caDir string) string {
	return filepath.Join(caDir, caCertFile)
}

// Keychain is the seam over the macOS `security` tool, so tests can exercise
// trust replacement without touching the real keychain or prompting for a
// password.
type Keychain interface {
	// AddTrustedRoot trusts the PEM certificate at certPath as a root.
	AddTrustedRoot(certPath string) error
	// DeleteCert removes the certificate with the given SHA-1 hash (upper-case
	// hex) and its user trust settings.
	DeleteCert(sha1Hex string) error
}

// systemKeychain is the real login keychain. Tests use trustCA with a fake.
var systemKeychain Keychain = macKeychain{}

// TrustCA adds the CA certificate to the macOS login keychain as a trusted
// root, first removing any CA this package replaced (see LoadOrCreateCA). This
// operation may prompt for the user's admin password.
func TrustCA(certPath string) error {
	return trustCA(systemKeychain, certPath)
}

func trustCA(kc Keychain, certPath string) error {
	caDir := filepath.Dir(certPath)
	superseded, err := readSupersededCerts(caDir)
	if err != nil {
		return err
	}
	// A failed removal must not leave the developer without a trusted CA, so
	// the new root is trusted regardless; the superseded record is kept so the
	// next `eden dev setup` retries the removal, and the error is returned.
	var removeErr error
	for _, old := range superseded {
		sum := sha1.Sum(old.Raw)
		err := kc.DeleteCert(strings.ToUpper(hex.EncodeToString(sum[:])))
		if errors.Is(err, ErrCertNotFound) {
			continue // never trusted, or already removed: nothing left to do
		}
		if err != nil && removeErr == nil {
			removeErr = fmt.Errorf("ca: the replaced CA is still trusted in the keychain; re-run 'eden dev setup': %w", err)
		}
	}

	if err := kc.AddTrustedRoot(certPath); err != nil {
		return errors.Join(err, removeErr)
	}
	if removeErr != nil {
		return removeErr
	}

	if len(superseded) > 0 {
		if err := os.Remove(filepath.Join(caDir, caSupersededFile)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("ca: clearing superseded CA record: %w", err)
		}
		slog.Info("ca: removed replaced CA from macOS keychain", "count", len(superseded))
	}
	return nil
}

// macKeychain drives the macOS `security` tool against the login keychain.
type macKeychain struct{}

func loginKeychainPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("ca: getting home directory: %w", err)
	}
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db"), nil
}

func (macKeychain) AddTrustedRoot(certPath string) error {
	keychainPath, err := loginKeychainPath()
	if err != nil {
		return err
	}

	fmt.Println("  Trusting CA certificate (you may be prompted for your admin password)...")

	cmd := exec.Command("security", "add-trusted-cert",
		"-r", "trustRoot",
		"-k", keychainPath,
		certPath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ca: trusting certificate failed: %w\n"+
			"  Manual trust: security add-trusted-cert -r trustRoot -k %s %s",
			err, keychainPath, certPath)
	}

	slog.Info("ca: certificate trusted in macOS keychain")
	return nil
}

func (macKeychain) DeleteCert(sha1Hex string) error {
	keychainPath, err := loginKeychainPath()
	if err != nil {
		return err
	}

	fmt.Println("  Removing replaced Eden CA certificate from the keychain...")

	var out bytes.Buffer
	cmd := exec.Command("security", "delete-certificate", "-Z", sha1Hex, "-t", keychainPath)
	cmd.Stdout = io.MultiWriter(os.Stdout, &out)
	cmd.Stderr = io.MultiWriter(os.Stderr, &out)
	runErr := cmd.Run()

	exitCode := 0
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		exitCode = exitErr.ExitCode()
	} else if runErr != nil {
		return fmt.Errorf("deleting certificate %s: %w", sha1Hex, runErr)
	}
	err = deleteCertError(exitCode, out.String())
	if err == nil || errors.Is(err, ErrCertNotFound) {
		return err
	}
	// Any other failure counts as "not found" only if the cert really is
	// absent, so a cert that is still trusted is never forgotten.
	if present, lerr := keychainHasCert(keychainPath, sha1Hex); lerr == nil && !present {
		return fmt.Errorf("%w (%v)", ErrCertNotFound, err)
	}
	return fmt.Errorf("deleting certificate %s: %w\n"+
		"  Manual removal: security delete-certificate -Z %s -t %s",
		sha1Hex, err, sha1Hex, keychainPath)
}

// ErrCertNotFound reports that the certificate to delete is not in the
// keychain, so there is nothing left to remove.
var ErrCertNotFound = errors.New("certificate not found in keychain")

// deleteCertError classifies a `security delete-certificate` result. Exit
// status 44 is errSecItemNotFound.
func deleteCertError(exitCode int, output string) error {
	switch exitCode {
	case 0:
		return nil
	case 44:
		return ErrCertNotFound
	default:
		return fmt.Errorf("security exited %d: %s", exitCode, strings.TrimSpace(output))
	}
}

// keychainHasCert reports whether a certificate named "Eden Dev CA" with the
// given SHA-1 hash is in the keychain. It only reads the keychain.
func keychainHasCert(keychainPath, sha1Hex string) (bool, error) {
	out, err := exec.Command("security", "find-certificate", "-a", "-Z", "-c", "Eden Dev CA", keychainPath).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 44 {
			return false, nil
		}
		return false, err
	}
	for _, h := range parseSHA1Hashes(string(out)) {
		if strings.EqualFold(h, sha1Hex) {
			return true, nil
		}
	}
	return false, nil
}

// parseSHA1Hashes extracts the "SHA-1 hash:" values from `security
// find-certificate -Z` output.
func parseSHA1Hashes(output string) []string {
	var hashes []string
	for _, line := range strings.Split(output, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "SHA-1 hash:"); ok {
			hashes = append(hashes, strings.TrimSpace(rest))
		}
	}
	return hashes
}

// ReloadingCA is the daemon's CertProvider. It serves leaves from the CA on
// disk and switches to a new one when `eden dev setup` replaces it, so a
// running daemon never keeps signing with a root that setup has just removed
// from the keychain.
type ReloadingCA struct {
	dir   string
	mu    sync.Mutex
	ca    *CA
	stamp caFileStamp
}

// caFileStamp identifies one version of the CA files on disk.
type caFileStamp struct {
	certMod, keyMod   time.Time
	certSize, keySize int64
}

// NewReloadingCA wraps ca, which was loaded from dir.
func NewReloadingCA(dir string, ca *CA) *ReloadingCA {
	st, _ := statCAFiles(dir)
	return &ReloadingCA{dir: dir, ca: ca, stamp: st}
}

// GetCertificate implements CertProvider.
func (r *ReloadingCA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.current().GetCertificate(hello)
}

// current returns the CA to sign with, reloading it if the files changed.
// A change that does not load cleanly (setup mid-write, a key that does not
// match the cert, a CA without the constraints) keeps the previous CA and is
// retried on the next handshake.
func (r *ReloadingCA) current() *CA {
	r.mu.Lock()
	defer r.mu.Unlock()

	st, err := statCAFiles(r.dir)
	if err != nil || st == r.stamp {
		return r.ca
	}
	next, err := readCAFiles(r.dir)
	if err != nil {
		slog.Debug("ca: CA files changed but did not load; keeping the current CA", "error", err)
		return r.ca
	}
	slog.Info("ca: reloaded replaced CA", "expires", next.cert.NotAfter.Format("2006-01-02"))
	r.ca = next
	r.stamp = st
	return r.ca
}

func statCAFiles(dir string) (caFileStamp, error) {
	c, err := os.Stat(filepath.Join(dir, caCertFile))
	if err != nil {
		return caFileStamp{}, err
	}
	k, err := os.Stat(filepath.Join(dir, caKeyFile))
	if err != nil {
		return caFileStamp{}, err
	}
	return caFileStamp{certMod: c.ModTime(), keyMod: k.ModTime(), certSize: c.Size(), keySize: k.Size()}, nil
}

// readCAFiles loads the CA in dir without ever writing: it rejects a pair
// whose key does not match the certificate, and a CA that is expired or
// lacks the required NameConstraints.
func readCAFiles(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, caCertFile))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM) // fails when the key does not match
	if err != nil {
		return nil, fmt.Errorf("ca: cert and key do not form a pair: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ca: key is %T, want ECDSA", pair.PrivateKey)
	}
	if time.Now().After(cert.NotAfter) || !hasRequiredConstraints(cert) {
		return nil, fmt.Errorf("ca: CA on disk is expired or lacks NameConstraints")
	}
	return &CA{cert: cert, key: key, certPEM: certPEM, cache: make(map[string]*tls.Certificate)}, nil
}
