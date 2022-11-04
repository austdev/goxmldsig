package dsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/austdev/goxmldsig/etreeutils"

	"github.com/beevik/etree"
)

type CryptoSigner interface {
	Signer() (signer crypto.Signer, err error)
}

type SigningContext struct {
	Hash          crypto.Hash
	KeyStore      X509KeyStore
	IdAttribute   string
	Prefix        string
	Canonicalizer Canonicalizer
}

func NewDefaultSigningContext(ks X509KeyStore) *SigningContext {
	return &SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IdAttribute:   DefaultIdAttr,
		Prefix:        DefaultPrefix,
		Canonicalizer: MakeC14N11Canonicalizer(),
	}
}

func (ctx *SigningContext) getPublicKeyAlgorithm() x509.PublicKeyAlgorithm {
	if cs, ok := ctx.KeyStore.(CryptoSigner); ok {
		if key, err := cs.Signer(); err == nil {
			switch key.Public().(type) {
			case *ecdsa.PublicKey:
				return x509.ECDSA
			case *rsa.PublicKey:
				return x509.RSA
			}
		}
		return x509.UnknownPublicKeyAlgorithm
	}
	return x509.RSA
}

func (ctx *SigningContext) SetSignatureMethod(algorithmID string) error {
	info, ok := signatureMethodByIdentifiers[algorithmID]
	if !ok {
		return fmt.Errorf("unknown SignatureMethod: %s", algorithmID)
	}

	algo := ctx.getPublicKeyAlgorithm()
	if info.PublicKeyAlgorithm != algo {
		return fmt.Errorf("SignatureMethod %s is incompatible with %s key", algorithmID, algo)
	}

	ctx.Hash = info.Hash

	return nil
}

func (ctx *SigningContext) CreateSignature(id string) *etree.Element {

	sig := &etree.Element{
		Tag:   SignatureTag,
		Space: ctx.Prefix,
	}

	xmlns := "xmlns"
	if ctx.Prefix != "" {
		xmlns += ":" + ctx.Prefix
	}

	sig.CreateAttr(xmlns, Namespace)

	if ctx.IdAttribute != "" && id != "" {
		sig.CreateAttr(ctx.IdAttribute, id)
	}
	return sig
}

func (ctx *SigningContext) AddManifestRef(sig *etree.Element, name string, hash_id crypto.Hash, digest []byte) error {

	digestAlgorithmIdentifier, ok := digestAlgorithmIdentifiers[hash_id]
	if !ok {
		return ErrUnsupportedMethod
	}

	manifest := ctx.constructManifest(sig)
	reference := ctx.createNamespacedElement(manifest, ReferenceTag)
	if name != "" {
		reference.CreateAttr(URIAttr, name)
	}
	digestMethod := ctx.createNamespacedElement(reference, DigestMethodTag)
	digestMethod.CreateAttr(AlgorithmAttr, digestAlgorithmIdentifier)

	digestValue := ctx.createNamespacedElement(reference, DigestValueTag)
	digestValue.SetText(base64.StdEncoding.EncodeToString(digest))

	return nil
}

func (ctx *SigningContext) digest(el *etree.Element) ([]byte, error) {
	canonical, err := ctx.Canonicalizer.Canonicalize(el)
	if err != nil {
		return nil, err
	}

	hash := ctx.Hash.New()
	_, err = hash.Write(canonical)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (ctx *SigningContext) constructManifest(sig *etree.Element) *etree.Element {

	man := sig.FindElementPath(ctx.manifestPath(sig))

	if man == nil {
		object := ctx.createNamespacedElement(sig, ObjectTag)
		man = ctx.createNamespacedElement(object, ManifestTag)
		if ctx.IdAttribute != "" {
			man.CreateAttr(ctx.IdAttribute, ManifestPrefix+sig.SelectAttrValue(ctx.IdAttribute, ""))
		}
	}
	return man
}

func (ctx *SigningContext) manifestPath(sig *etree.Element) etree.Path {

	if ctx.IdAttribute != "" {
		val := ManifestPrefix + sig.SelectAttrValue(ctx.IdAttribute, "")
		pstr := fmt.Sprintf("%s/%s[@%s='%s']", ObjectTag, ManifestTag, ctx.IdAttribute, val)
		if path, err := etree.CompilePath(pstr); err == nil {
			return path
		}
	}
	path, _ := etree.CompilePath(ObjectTag + "/" + ManifestTag)
	return path
}

func (ctx *SigningContext) constructSignedInfo(el *etree.Element, enveloped bool) (*etree.Element, error) {
	digestAlgorithmIdentifier := ctx.GetDigestAlgorithmIdentifier()
	if digestAlgorithmIdentifier == "" {
		return nil, errors.New("unsupported hash mechanism")
	}

	signatureMethodIdentifier := ctx.GetSignatureMethodIdentifier()
	if signatureMethodIdentifier == "" {
		return nil, errors.New("unsupported signature method")
	}

	digest, err := ctx.digest(el)
	if err != nil {
		return nil, err
	}

	signedInfo := &etree.Element{
		Tag:   SignedInfoTag,
		Space: ctx.Prefix,
	}

	// /SignedInfo/CanonicalizationMethod
	canonicalizationMethod := ctx.createNamespacedElement(signedInfo, CanonicalizationMethodTag)
	canonicalizationMethod.CreateAttr(AlgorithmAttr, string(ctx.Canonicalizer.Algorithm()))

	// /SignedInfo/SignatureMethod
	signatureMethod := ctx.createNamespacedElement(signedInfo, SignatureMethodTag)
	signatureMethod.CreateAttr(AlgorithmAttr, signatureMethodIdentifier)

	// /SignedInfo/Reference
	reference := ctx.createNamespacedElement(signedInfo, ReferenceTag)

	// additional signature syntax
	if el.Tag == ManifestTag {
		reference.CreateAttr(TypeAttr, ManifestRefType)
	}

	dataId := el.SelectAttrValue(ctx.IdAttribute, "")
	if dataId == "" {
		reference.CreateAttr(URIAttr, "")
	} else {
		reference.CreateAttr(URIAttr, "#"+dataId)
	}

	// /SignedInfo/Reference/Transforms
	transforms := ctx.createNamespacedElement(reference, TransformsTag)
	if enveloped {
		envelopedTransform := ctx.createNamespacedElement(transforms, TransformTag)
		envelopedTransform.CreateAttr(AlgorithmAttr, EnvelopedSignatureAltorithmId.String())
	}
	canonicalizationAlgorithm := ctx.createNamespacedElement(transforms, TransformTag)
	canonicalizationAlgorithm.CreateAttr(AlgorithmAttr, string(ctx.Canonicalizer.Algorithm()))

	// /SignedInfo/Reference/DigestMethod
	digestMethod := ctx.createNamespacedElement(reference, DigestMethodTag)
	digestMethod.CreateAttr(AlgorithmAttr, digestAlgorithmIdentifier)

	// /SignedInfo/Reference/DigestValue
	digestValue := ctx.createNamespacedElement(reference, DigestValueTag)
	digestValue.SetText(base64.StdEncoding.EncodeToString(digest))

	return signedInfo, nil
}

func (ctx *SigningContext) ConstructSignature(el *etree.Element, enveloped bool) (*etree.Element, error) {

	signedInfo, err := ctx.constructSignedInfo(el, enveloped)
	if err != nil {
		return nil, err
	}

	sig := ctx.CreateSignature("")
	sig.AddChild(signedInfo)

	// When using xml-c14n11 (ie, non-exclusive canonicalization) the canonical form
	// of the SignedInfo must declare all namespaces that are in scope at it's final
	// enveloped location in the document. In order to do that, we're going to construct
	// a series of cascading NSContexts to capture namespace declarations:

	// First get the context surrounding the element we are signing.
	rootNSCtx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}

	// Then capture any declarations on the element itself.
	elNSCtx, err := rootNSCtx.SubContext(el)
	if err != nil {
		return nil, err
	}

	// Followed by declarations on the Signature (which we just added above)
	sigNSCtx, err := elNSCtx.SubContext(sig)
	if err != nil {
		return nil, err
	}

	return ctx.signing(sig, sigNSCtx, signedInfo)
}

func (ctx *SigningContext) signing(sig *etree.Element, sigNSCtx etreeutils.NSContext, signedInfo *etree.Element) (*etree.Element, error) {

	// Finally detatch the SignedInfo in order to capture all of the namespace
	// declarations in the scope we've constructed.
	detatchedSignedInfo, err := etreeutils.NSDetatch(sigNSCtx, signedInfo)
	if err != nil {
		return nil, err
	}

	digest, err := ctx.digest(detatchedSignedInfo)
	if err != nil {
		return nil, err
	}

	var certs [][]byte
	var key crypto.Signer
	if cs, ok := ctx.KeyStore.(CryptoSigner); ok {
		key, err = cs.Signer()
		if err != nil {
			return nil, err
		}
	}

	if cs, ok := ctx.KeyStore.(X509ChainStore); ok {
		certs, err = cs.GetChain()
		if err != nil {
			return nil, err
		}
	}

	if key == nil || len(certs) == 0 {
		// fall back to old interface
		RSAkey, cert, err := ctx.KeyStore.GetKeyPair()
		if err != nil {
			return nil, err
		}
		if len(certs) == 0 {
			certs = [][]byte{cert}
		}
		key = RSAkey
	}

	rawSignature, err := key.Sign(rand.Reader, digest, ctx.Hash)
	if err != nil {
		return nil, err
	}

	signatureValue := ctx.createNamespacedElement(sig, SignatureValueTag)
	signatureValue.SetText(base64.StdEncoding.EncodeToString(rawSignature))

	keyInfo := ctx.createNamespacedElement(sig, KeyInfoTag)
	x509Data := ctx.createNamespacedElement(keyInfo, X509DataTag)
	for _, cert := range certs {
		x509Certificate := ctx.createNamespacedElement(x509Data, X509CertificateTag)
		x509Certificate.SetText(base64.StdEncoding.EncodeToString(cert))
	}

	return sig, nil
}

func (ctx *SigningContext) createNamespacedElement(el *etree.Element, tag string) *etree.Element {
	child := el.CreateElement(tag)
	child.Space = ctx.Prefix
	return child
}

func (ctx *SigningContext) SignManifest(sig *etree.Element) (*etree.Element, error) {

	// First get the default context
	rootNSCtx := etreeutils.DefaultNSContext

	// Followed by declarations on the Signature (which we just added above)
	sigNSCtx, err := rootNSCtx.SubContext(sig)
	if err != nil {
		return nil, err
	}

	man := sig.FindElementPath(ctx.manifestPath(sig))
	if man == nil {
		return nil, errors.New("missing manifest element")
	}

	manifest, err := etreeutils.NSDetatch(sigNSCtx, man)
	if err != nil {
		return nil, err
	}

	signedInfo, err := ctx.constructSignedInfo(manifest, false)
	if err != nil {
		return nil, err
	}

	sig.AddChild(signedInfo)

	return ctx.signing(sig, sigNSCtx, signedInfo)
}

func (ctx *SigningContext) SignEnveloped(el *etree.Element) (*etree.Element, error) {
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		return nil, err
	}

	ret := el.Copy()
	ret.Child = append(ret.Child, sig)

	return ret, nil
}

func (ctx *SigningContext) GetSignatureMethodIdentifier() string {
	algo := ctx.getPublicKeyAlgorithm()

	if ident, ok := signatureMethodIdentifiers[algo][ctx.Hash]; ok {
		return ident
	}
	return ""
}

func (ctx *SigningContext) GetDigestAlgorithmIdentifier() string {
	if ident, ok := digestAlgorithmIdentifiers[ctx.Hash]; ok {
		return ident
	}
	return ""
}

// Useful for signing query string (including DEFLATED AuthnRequest) when
// using HTTP-Redirect to make a signed request.
// See 3.4.4.1 DEFLATE Encoding of https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
func (ctx *SigningContext) SignString(content string) ([]byte, error) {
	hash := ctx.Hash.New()
	if ln, err := hash.Write([]byte(content)); err != nil {
		return nil, fmt.Errorf("error calculating hash: %v", err)
	} else if ln < 1 {
		return nil, fmt.Errorf("zero length hash")
	}
	digest := hash.Sum(nil)

	var signature []byte
	if cs, ok := ctx.KeyStore.(CryptoSigner); ok {
		if key, err := cs.Signer(); err != nil {
			return nil, fmt.Errorf("unable to fetch crypto.Signer interface: %v", err)
		} else if signature, err = key.Sign(rand.Reader, digest, ctx.Hash); err != nil {
			return nil, fmt.Errorf("error signing: %v", err)
		}
	} else if key, _, err := ctx.KeyStore.GetKeyPair(); err != nil {
		return nil, fmt.Errorf("unable to fetch key for signing: %v", err)
	} else if signature, err = rsa.SignPKCS1v15(rand.Reader, key, ctx.Hash, digest); err != nil {
		return nil, fmt.Errorf("error signing: %v", err)
	}
	return signature, nil
}
