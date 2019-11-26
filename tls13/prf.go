// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls13

import (
	"crypto"
	"crypto/tls"
	"fmt"
)

// hashFromSignatureScheme returns the corresponding crypto.Hash for a given
// hash from a TLS SignatureScheme.
func hashFromSignatureScheme(signatureAlgorithm tls.SignatureScheme) (crypto.Hash, error) {
	switch signatureAlgorithm {
	case tls.PKCS1WithSHA1, tls.ECDSAWithSHA1:
		return crypto.SHA1, nil
	case tls.PKCS1WithSHA256, tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256:
		return crypto.SHA256, nil
	case tls.PKCS1WithSHA384, tls.PSSWithSHA384, tls.ECDSAWithP384AndSHA384:
		return crypto.SHA384, nil
	case tls.PKCS1WithSHA512, tls.PSSWithSHA512, tls.ECDSAWithP521AndSHA512:
		return crypto.SHA512, nil
	case tls.Ed25519:
		return directSigning, nil
	default:
		return 0, fmt.Errorf("tls: unsupported signature algorithm: %#04x", signatureAlgorithm)
	}
}
