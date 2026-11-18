package daemon

import (
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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestCA creates a fresh CA in a temp directory.
func newTestCA(t *testing.T) (*CA, string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	return ca, dir
}

func TestNewCAHasCriticalNameConstraints(t *testing.T) {
	ca, _ := newTestCA(t)
	c := ca.cert

	if !c.PermittedDNSDomainsCritical {
		t.Error("NameConstraints extension must be critical")
	}
	if len(c.PermittedDNSDomains) != 1 || c.PermittedDNSDomains[0] != ".test" {
		t.Errorf("PermittedDNSDomains = %v, want [.test]", c.PermittedDNSDomains)
	}
	var v4, v6 bool
	for _, r := range c.ExcludedIPRanges {
		ones, bits := r.Mask.Size()
		if ones == 0 && bits == 32 {
			v4 = true
		}
		if ones == 0 && bits == 128 {
			v6 = true
		}
	}
	if !v4 || !v6 {
		t.Errorf("ExcludedIPRanges = %v, want all of IPv4 and IPv6 excluded", c.ExcludedIPRanges)
	}
}

// signLeaf signs a server leaf directly with the CA key, bypassing
// generateLeaf's own hostname guard — this is what an attacker holding a
// leaked CA key would do.
func signLeaf(t *testing.T, ca *CA, dnsNames []string, ips []net.IP) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cn := "ip-leaf"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("signing leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func verifyAgainstCA(ca *CA, leaf *x509.Certificate, dnsName string) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:   dnsName,
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func TestCARejectsLeafOutsideTestButAcceptsEdenTest(t *testing.T) {
	ca, _ := newTestCA(t)

	bad := signLeaf(t, ca, []string{"example.com"}, nil)
	if err := verifyAgainstCA(ca, bad, "example.com"); err == nil {
		t.Error("leaf for example.com verified against the CA; NameConstraints must reject it")
	}

	good := signLeaf(t, ca, []string{"foo.eden.test"}, nil)
	if err := verifyAgainstCA(ca, good, "foo.eden.test"); err != nil {
		t.Errorf("leaf for foo.eden.test failed verification: %v", err)
	}
}

func TestCARejectsLeafWithIPSAN(t *testing.T) {
	ca, _ := newTestCA(t)
	leaf := signLeaf(t, ca, nil, []net.IP{net.ParseIP("127.0.0.1")})
	if err := verifyAgainstCA(ca, leaf, "127.0.0.1"); err == nil {
		t.Error("leaf with IP SAN verified against the CA; ExcludedIPRanges must reject it")
	}
}

func TestGetCertificateRefusesHostOutsideTest(t *testing.T) {
	ca, _ := newTestCA(t)

	if _, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"}); err == nil {
		t.Error("GetCertificate issued a leaf for example.com; it must refuse names outside .test")
	}

	got, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "foo.eden.test"})
	if err != nil {
		t.Fatalf("GetCertificate(foo.eden.test): %v", err)
	}
	leaf, err := x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAgainstCA(ca, leaf, "foo.eden.test"); err != nil {
		t.Errorf("served foo.eden.test leaf failed verification: %v", err)
	}
}

func TestCALifetimeIsBounded(t *testing.T) {
	ca, _ := newTestCA(t)
	life := time.Until(ca.cert.NotAfter)
	if max := 825 * 24 * time.Hour; life > max {
		t.Errorf("CA lifetime = %v, want <= %v", life, max)
	}
}

// writeLegacyCA writes a CA shaped like the pre-fix template (no
// NameConstraints, 10-year lifetime) into dir and returns its certificate.
func writeLegacyCA(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Eden Dev CA", Organization: []string{"Eden Development"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, caCertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestLoadRegeneratesUnconstrainedCA(t *testing.T) {
	dir := t.TempDir()
	legacy := writeLegacyCA(t, dir)

	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	if ca.cert.Equal(legacy) {
		t.Fatal("unconstrained legacy CA was loaded as-is; it must be regenerated")
	}
	if !ca.cert.PermittedDNSDomainsCritical || len(ca.cert.PermittedDNSDomains) == 0 {
		t.Error("regenerated CA lacks NameConstraints")
	}
	if !ca.Replaced() {
		t.Error("Replaced() = false after regenerating an unconstrained CA")
	}

	superseded, err := readSupersededCerts(dir)
	if err != nil {
		t.Fatalf("readSupersededCerts: %v", err)
	}
	if len(superseded) != 1 || !superseded[0].Equal(legacy) {
		t.Errorf("superseded certs = %d, want exactly the legacy CA recorded for keychain removal", len(superseded))
	}
}

func TestLoadKeepsConstrainedCA(t *testing.T) {
	first, dir := newTestCA(t)

	again, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	if !again.cert.Equal(first.cert) {
		t.Error("constrained CA was regenerated on load; it must be kept")
	}
	if again.Replaced() {
		t.Error("Replaced() = true for a CA that already had the constraint")
	}
	if got, _ := readSupersededCerts(dir); len(got) != 0 {
		t.Errorf("superseded certs = %d, want 0", len(got))
	}
}

// fakeKeychain records calls instead of running the macOS `security` tool.
type fakeKeychain struct {
	calls     []string
	deleteErr error
	addErr    error
}

func (f *fakeKeychain) AddTrustedRoot(certPath string) error {
	f.calls = append(f.calls, "add "+certPath)
	return f.addErr
}

func (f *fakeKeychain) DeleteCert(sha1Hex string) error {
	f.calls = append(f.calls, "delete "+sha1Hex)
	return f.deleteErr
}

func sha1Hex(c *x509.Certificate) string {
	sum := sha1.Sum(c.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func TestTrustCARemovesSupersededRootThenTrustsNew(t *testing.T) {
	dir := t.TempDir()
	legacy := writeLegacyCA(t, dir)
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	kc := &fakeKeychain{}
	certPath := ca.CertPEMPath(dir)

	if err := trustCA(kc, certPath); err != nil {
		t.Fatalf("trustCA: %v", err)
	}

	want := []string{"delete " + sha1Hex(legacy), "add " + certPath}
	if strings.Join(kc.calls, "|") != strings.Join(want, "|") {
		t.Errorf("keychain calls = %q, want %q", kc.calls, want)
	}
	if _, err := os.Stat(filepath.Join(dir, caSupersededFile)); !os.IsNotExist(err) {
		t.Errorf("superseded record still present after a successful replace (stat err = %v)", err)
	}
}

func TestTrustCAWithNothingSupersededOnlyAdds(t *testing.T) {
	ca, dir := newTestCA(t)
	kc := &fakeKeychain{}
	certPath := ca.CertPEMPath(dir)

	if err := trustCA(kc, certPath); err != nil {
		t.Fatalf("trustCA: %v", err)
	}
	if len(kc.calls) != 1 || kc.calls[0] != "add "+certPath {
		t.Errorf("keychain calls = %q, want only the add", kc.calls)
	}
}

func TestTrustCADeleteFailureStillTrustsNewAndKeepsRecord(t *testing.T) {
	dir := t.TempDir()
	writeLegacyCA(t, dir)
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	kc := &fakeKeychain{deleteErr: errors.New("user cancelled")}
	certPath := ca.CertPEMPath(dir)

	if err := trustCA(kc, certPath); err == nil {
		t.Error("trustCA returned nil although the old root is still trusted")
	}
	if kc.calls[len(kc.calls)-1] != "add "+certPath {
		t.Errorf("keychain calls = %q, want the new root trusted anyway", kc.calls)
	}
	if got, _ := readSupersededCerts(dir); len(got) != 1 {
		t.Errorf("superseded certs = %d, want the record kept so the next setup retries", len(got))
	}
}

// copyCAFiles copies the named CA files from src to dst and bumps their
// mtime, as `eden dev setup` regenerating the CA would.
func copyCAFiles(t *testing.T, src, dst string, names ...string) {
	t.Helper()
	bump := time.Now().Add(time.Duration(len(names)+1) * time.Minute)
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(src, n))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dst, n)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, bump, bump); err != nil {
			t.Fatal(err)
		}
	}
}

func servedLeaf(t *testing.T, cp CertProvider) *x509.Certificate {
	t.Helper()
	got, err := cp.GetCertificate(&tls.ClientHelloInfo{ServerName: "foo.eden.test"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestReloadingCAPicksUpReplacedCAWithoutRestart(t *testing.T) {
	oldCA, dir := newTestCA(t)
	r := NewReloadingCA(dir, oldCA)
	if err := verifyAgainstCA(oldCA, servedLeaf(t, r), "foo.eden.test"); err != nil {
		t.Fatalf("leaf before replacement: %v", err)
	}

	// `eden dev setup` replaces the CA on disk while the daemon runs.
	newCA, newDir := newTestCA(t)
	copyCAFiles(t, newDir, dir, caKeyFile, caCertFile)

	if err := verifyAgainstCA(newCA, servedLeaf(t, r), "foo.eden.test"); err != nil {
		t.Errorf("daemon still serves leaves from the replaced CA: %v", err)
	}
}

func TestReloadingCAKeepsCurrentCAWhileReplacementIsHalfWritten(t *testing.T) {
	oldCA, dir := newTestCA(t)
	r := NewReloadingCA(dir, oldCA)
	newCA, newDir := newTestCA(t)

	// Only the new cert has landed; the key on disk is still the old one.
	copyCAFiles(t, newDir, dir, caCertFile)
	if err := verifyAgainstCA(oldCA, servedLeaf(t, r), "foo.eden.test"); err != nil {
		t.Errorf("mid-write: want leaves still from the current CA: %v", err)
	}

	copyCAFiles(t, newDir, dir, caKeyFile)
	if err := verifyAgainstCA(newCA, servedLeaf(t, r), "foo.eden.test"); err != nil {
		t.Errorf("after the key landed: want leaves from the new CA: %v", err)
	}
}

func TestTrustCATreatsAlreadyAbsentSupersededCertAsRemoved(t *testing.T) {
	dir := t.TempDir()
	writeLegacyCA(t, dir)
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	kc := &fakeKeychain{deleteErr: fmt.Errorf("security: %w", ErrCertNotFound)}

	if err := trustCA(kc, ca.CertPEMPath(dir)); err != nil {
		t.Errorf("trustCA: %v; a superseded cert that was never in the keychain is already gone", err)
	}
	if got, _ := readSupersededCerts(dir); len(got) != 0 {
		t.Errorf("superseded certs = %d, want the record cleared", len(got))
	}
}

func TestDeleteCertErrorClassifiesNotFound(t *testing.T) {
	// security(1) exits 44 (errSecItemNotFound) when nothing matches the hash.
	if err := deleteCertError(44, "Unable to delete certificate matching \"ABC\""); !errors.Is(err, ErrCertNotFound) {
		t.Errorf("exit 44: err = %v, want ErrCertNotFound", err)
	}
	if err := deleteCertError(1, "User interaction is not allowed."); err == nil || errors.Is(err, ErrCertNotFound) {
		t.Errorf("exit 1: err = %v, want a real failure", err)
	}
	if err := deleteCertError(0, ""); err != nil {
		t.Errorf("exit 0: err = %v, want nil", err)
	}
}

func TestParseSHA1HashesFromFindCertificateOutput(t *testing.T) {
	out := `SHA-256 hash: 1111111111111111111111111111111111111111111111111111111111111111
SHA-1 hash: 40EFF54ABFD5F180DC2613A58BF0FB25FB581CD5
keychain: "/Users/x/Library/Keychains/login.keychain-db"
SHA-256 hash: 2222222222222222222222222222222222222222222222222222222222222222
SHA-1 hash: 0123456789ABCDEF0123456789ABCDEF01234567
`
	got := parseSHA1Hashes(out)
	want := []string{"40EFF54ABFD5F180DC2613A58BF0FB25FB581CD5", "0123456789ABCDEF0123456789ABCDEF01234567"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("parseSHA1Hashes = %v, want %v", got, want)
	}
}
