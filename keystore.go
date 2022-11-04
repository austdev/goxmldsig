package dsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
	"time"
)

type X509KeyStore interface {
	GetKeyPair() (privateKey *rsa.PrivateKey, cert []byte, err error)
}

type X509ChainStore interface {
	GetChain() (certs [][]byte, err error)
}

type X509CertificateStore interface {
	Certificates() (roots []*x509.Certificate, err error)
}

type MemoryX509CertificateStore struct {
	Roots []*x509.Certificate
}

func (mX509cs *MemoryX509CertificateStore) Certificates() ([]*x509.Certificate, error) {
	return mX509cs.Roots, nil
}

type MemoryX509KeyStore struct {
	privateKey *rsa.PrivateKey
	cert       []byte
}

func (ks *MemoryX509KeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.privateKey, ks.cert, nil
}

func RandomKeyStoreForTest() X509KeyStore {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	return &MemoryX509KeyStore{
		privateKey: key,
		cert:       cert,
	}
}

type MemoryX509Signer struct {
	privateKey crypto.Signer
	cert       []byte
}

func (ms *MemoryX509Signer) Signer() (signer crypto.Signer, err error) {
	return ms.privateKey, nil
}

func (ms *MemoryX509Signer) GetChain() ([][]byte, error) {
	return [][]byte{ms.cert}, nil
}

func (ms *MemoryX509Signer) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return nil, nil, errors.New("missing certificate")
}

func RandomKeyStoreByType(algorithmID string) X509KeyStore {

	info, ok := signatureMethodByIdentifiers[algorithmID]
	if !ok {
		info.PublicKeyAlgorithm = x509.RSA
		info.Hash = crypto.SHA256
		info = signatureMethodInfo{x509.RSA, crypto.SHA256}
	}

	var err error
	var key crypto.Signer
	switch info.PublicKeyAlgorithm {
	case x509.ECDSA:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case x509.RSA:
		key, err = rsa.GenerateKey(rand.Reader, 1024)
	}
	if err != nil {
		panic(err)
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		panic(err)
	}

	return &MemoryX509Signer{
		privateKey: key,
		cert:       cert,
	}
}
