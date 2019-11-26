// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls13

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"io"
)

// verifyHandshakeSignature verifies a signature against pre-hashed
// (if required) handshake contents.
func verifyHandshakeSignature(sigType uint8, pubkey crypto.PublicKey, hashFunc crypto.Hash, signed, sig []byte) error {
	switch sigType {
	case signatureECDSA:
		pubKey, ok := pubkey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("tls: ECDSA signing requires a ECDSA public key")
		}
		ecdsaSig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(sig, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("tls: ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pubKey, signed, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("tls: ECDSA verification failure")
		}
	case signatureEd25519:
		pubKey, ok := pubkey.(ed25519.PublicKey)
		if !ok {
			return errors.New("tls: Ed25519 signing requires a Ed25519 public key")
		}
		if !ed25519.Verify(pubKey, signed, sig) {
			return errors.New("tls: Ed25519 verification failure")
		}
	case signaturePKCS1v15:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return errors.New("tls: RSA signing requires a RSA public key")
		}
		if err := rsa.VerifyPKCS1v15(pubKey, hashFunc, signed, sig); err != nil {
			return err
		}
	case signatureRSAPSS:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return errors.New("tls: RSA signing requires a RSA public key")
		}
		signOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
		if err := rsa.VerifyPSS(pubKey, hashFunc, signed, sig, signOpts); err != nil {
			return err
		}
	default:
		return errors.New("tls: unknown signature algorithm")
	}
	return nil
}

const (
	serverSignatureContext = "TLS 1.3, server CertificateVerify\x00"
	clientSignatureContext = "TLS 1.3, client CertificateVerify\x00"
)

var signaturePadding = []byte{
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
}

// signedMessage returns the pre-hashed (if necessary) message to be signed by
// certificate keys in TLS 1.3. See RFC 8446, Section 4.4.3.
func signedMessage(sigHash crypto.Hash, context string, transcript hash.Hash) []byte {
	if sigHash == directSigning {
		b := &bytes.Buffer{}
		b.Write(signaturePadding)
		io.WriteString(b, context)
		b.Write(transcript.Sum(nil))
		return b.Bytes()
	}
	h := sigHash.New()
	h.Write(signaturePadding)
	io.WriteString(h, context)
	h.Write(transcript.Sum(nil))
	return h.Sum(nil)
}

// signatureSchemesForCertificate returns the list of supported SignatureSchemes
// for a given certificate, based on the public key and the protocol version.
//
// It does not support the crypto.Decrypter interface, so shouldn't be used for
// server certificates in TLS 1.2 and earlier, and it must be kept in sync with
// supportedSignatureAlgorithms.
func signatureSchemesForCertificate(version uint16, cert *tls.Certificate) []tls.SignatureScheme {
	priv, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil
	}

	switch pub := priv.Public().(type) {
	case *ecdsa.PublicKey:
		if version != tls.VersionTLS13 {
			// In TLS 1.2 and earlier, ECDSA algorithms are not
			// constrained to a single curve.
			return []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.ECDSAWithSHA1,
			}
		}
		switch pub.Curve {
		case elliptic.P256():
			return []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}
		case elliptic.P384():
			return []tls.SignatureScheme{tls.ECDSAWithP384AndSHA384}
		case elliptic.P521():
			return []tls.SignatureScheme{tls.ECDSAWithP521AndSHA512}
		default:
			return nil
		}
	case *rsa.PublicKey:
		if version != tls.VersionTLS13 {
			return []tls.SignatureScheme{
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1,
			}
		}
		return []tls.SignatureScheme{
			tls.PSSWithSHA256,
			tls.PSSWithSHA384,
			tls.PSSWithSHA512,
		}
	case ed25519.PublicKey:
		return []tls.SignatureScheme{tls.Ed25519}
	default:
		return nil
	}
}

// unsupportedCertificateError returns a helpful error for certificates with
// an unsupported private key.
func unsupportedCertificateError(cert *tls.Certificate) error {
	switch cert.PrivateKey.(type) {
	case rsa.PrivateKey, ecdsa.PrivateKey:
		return fmt.Errorf("tls: unsupported certificate: private key is %T, expected *%T",
			cert.PrivateKey, cert.PrivateKey)
	case *ed25519.PrivateKey:
		return fmt.Errorf("tls: unsupported certificate: private key is *ed25519.PrivateKey, expected ed25519.PrivateKey")
	}

	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("tls: certificate private key (%T) does not implement crypto.Signer",
			cert.PrivateKey)
	}

	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
		case elliptic.P384():
		case elliptic.P521():
		default:
			return fmt.Errorf("tls: unsupported certificate curve (%s)", pub.Curve.Params().Name)
		}
	case *rsa.PublicKey:
	case ed25519.PublicKey:
	default:
		return fmt.Errorf("tls: unsupported certificate key (%T)", pub)
	}

	return fmt.Errorf("tls: internal error: unsupported key (%T)", cert.PrivateKey)
}
