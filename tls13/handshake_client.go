// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls13

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func (c *Conn) makeClientHello() (*clientHelloMsg, ecdheParameters, error) {
	config := c.config
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		return nil, nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, nil, errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}
	if nextProtosLength > 0xffff {
		return nil, nil, errors.New("tls: NextProtos values too large")
	}

	clientHelloVersion := supportedVersions[0]
	// The version at the beginning of the ClientHello was capped at TLS 1.2
	// for compatibility reasons. The supported_versions extension is used
	// to negotiate versions now. See RFC 8446, Section 4.2.1.
	if clientHelloVersion > tls.VersionTLS12 {
		clientHelloVersion = tls.VersionTLS12
	}

	hello := &clientHelloMsg{
		vers:                         clientHelloVersion,
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		sessionId:                    make([]byte, 32),
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(config.ServerName),
		supportedCurves:              configCurvePreferences(c.config),
		supportedPoints:              []uint8{pointFormatUncompressed},
		secureRenegotiationSupported: true,
		alpnProtocols:                config.NextProtos,
		supportedVersions:            supportedVersions,
		quicTransportParams:          c.quicTransportParams,
	}

	// FIXME
	/*
		if c.handshakes > 0 {
			hello.secureRenegotiation = c.clientFinished[:]
		}
	*/

	hello.cipherSuites = configCipherSuites(c.config)

	_, err := io.ReadFull(configRand(c.config), hello.random)
	if err != nil {
		return nil, nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	if _, err := io.ReadFull(configRand(c.config), hello.sessionId); err != nil {
		return nil, nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	if hello.vers >= tls.VersionTLS12 {
		hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms
	}

	var params ecdheParameters
	if hello.supportedVersions[0] == tls.VersionTLS13 {
		hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13...)

		curveID := configCurvePreferences(c.config)[0]
		if _, ok := curveForCurveID(curveID); curveID != tls.X25519 && !ok {
			return nil, nil, errors.New("tls: CurvePreferences includes unsupported curve")
		}
		params, err = generateECDHEParameters(configRand(c.config), curveID)
		if err != nil {
			return nil, nil, err
		}
		hello.keyShares = []keyShare{{group: curveID, data: params.PublicKey()}}
	}

	return hello, params, nil
}

func (c *Conn) clientHandshake() (err error) {
	if c.clientHs == nil {
		// This may be a renegotiation handshake, in which case some fields
		// need to be reset.
		c.didResume = false

		hello, ecdheParams, err := c.makeClientHello()
		if err != nil {
			return err
		}

		cacheKey, session, earlySecret, binderKey := c.loadSession(hello)
		if cacheKey != "" && session != nil {
			defer func() {
				// If we got a handshake failure when resuming a session, throw away
				// the session ticket. See RFC 5077, Section 3.2.
				//
				// RFC 8446 makes no mention of dropping tickets on failure, but it
				// does require servers to abort on invalid binders, so we need to
				// delete tickets to recover from a corrupted PSK.
				if err != nil {
					c.config.ClientSessionCache.Put(cacheKey, nil)
				}
			}()
		}

		if _, err := c.writeRecord(recordTypeHandshake, hello.marshal()); err != nil {
			return err
		}

		c.clientHs = &clientHandshakeStateTLS13{
			c:           c,
			hello:       hello,
			ecdheParams: ecdheParams,
			session:     session,
			earlySecret: earlySecret,
			binderKey:   binderKey,
		}
	}

	// In TLS 1.3, session tickets are delivered after the handshake.
	return c.clientHs.handshake()
}

func (c *Conn) loadSession(hello *clientHelloMsg) (cacheKey string,
	session *clientSessionState, earlySecret, binderKey []byte) {
	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return "", nil, nil, nil
	}

	hello.ticketSupported = true

	if hello.supportedVersions[0] == tls.VersionTLS13 {
		// Require DHE on resumption as it guarantees forward secrecy against
		// compromise of the session ticket key. See RFC 8446, Section 4.2.9.
		hello.pskModes = []uint8{pskModeDHE}
	}

	// Session resumption is not allowed if renegotiating because
	// renegotiation is primarily used to allow a client to send a client
	// certificate, which would be skipped if session resumption occurred.
	if c.handshakes != 0 {
		return "", nil, nil, nil
	}

	// Try to resume a previously negotiated TLS session, if available.
	cacheKey = clientSessionCacheKey(c.config)
	tlsSession, ok := c.config.ClientSessionCache.Get(cacheKey)
	if !ok || tlsSession == nil {
		return cacheKey, nil, nil, nil
	}

	// Check that version used for the previous session is still valid.
	versOk := false
	for _, v := range hello.supportedVersions {
		if v == session.vers {
			versOk = true
			break
		}
	}
	if !versOk {
		return cacheKey, nil, nil, nil
	}

	// Check that the cached server certificate is not expired, and that it's
	// valid for the ServerName. This should be ensured by the cache key, but
	// protect the application from a faulty ClientSessionCache implementation.
	if !c.config.InsecureSkipVerify {
		if len(session.verifiedChains) == 0 {
			// The original connection had InsecureSkipVerify, while this doesn't.
			return cacheKey, nil, nil, nil
		}
		serverCert := session.serverCertificates[0]
		if configTime(c.config).After(serverCert.NotAfter) {
			// Expired certificate, delete the entry.
			c.config.ClientSessionCache.Put(cacheKey, nil)
			return cacheKey, nil, nil, nil
		}
		if err := serverCert.VerifyHostname(c.config.ServerName); err != nil {
			return cacheKey, nil, nil, nil
		}
	}

	// Check that the session ticket is not expired.
	if configTime(c.config).After(session.useBy) {
		c.config.ClientSessionCache.Put(cacheKey, nil)
		return cacheKey, nil, nil, nil
	}

	// In TLS 1.3 the KDF hash must match the resumed session. Ensure we
	// offer at least one cipher suite with that hash.
	cipherSuite := cipherSuiteTLS13ByID(session.cipherSuite)
	if cipherSuite == nil {
		return cacheKey, nil, nil, nil
	}
	cipherSuiteOk := false
	for _, offeredID := range hello.cipherSuites {
		offeredSuite := cipherSuiteTLS13ByID(offeredID)
		if offeredSuite != nil && offeredSuite.hash == cipherSuite.hash {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return cacheKey, nil, nil, nil
	}

	// Set the pre_shared_key extension. See RFC 8446, Section 4.2.11.1.
	ticketAge := uint32(configTime(c.config).Sub(session.receivedAt) / time.Millisecond)
	identity := pskIdentity{
		label:               session.sessionTicket,
		obfuscatedTicketAge: ticketAge + session.ageAdd,
	}
	hello.pskIdentities = []pskIdentity{identity}
	hello.pskBinders = [][]byte{make([]byte, cipherSuite.hash.Size())}

	// Compute the PSK binders. See RFC 8446, Section 4.2.11.2.
	psk := cipherSuite.expandLabel(session.masterSecret, "resumption",
		session.nonce, cipherSuite.hash.Size())
	earlySecret = cipherSuite.extract(psk, nil)
	binderKey = cipherSuite.deriveSecret(earlySecret, resumptionBinderLabel, nil)
	transcript := cipherSuite.hash.New()
	transcript.Write(hello.marshalWithoutBinders())
	pskBinders := [][]byte{cipherSuite.finishedHash(binderKey, transcript)}
	hello.updateBinders(pskBinders)

	return
}

func (c *Conn) pickTLSVersion(serverHello *serverHelloMsg) error {
	peerVersion := serverHello.vers
	if serverHello.supportedVersion != 0 {
		peerVersion = serverHello.supportedVersion
	}

	vers, ok := mutualVersion([]uint16{peerVersion})
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x", peerVersion)
	}

	c.vers = vers

	return nil
}

// verifyServerCertificate parses and verifies the provided chain, setting
// c.verifiedChains and c.peerCertificates or sending the appropriate alert.
func (c *Conn) verifyServerCertificate(certificates [][]byte) error {
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}

	if !c.config.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:         c.config.RootCAs,
			CurrentTime:   configTime(c.config),
			DNSName:       c.config.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		var err error
		c.verifiedChains, err = certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		break
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}

	c.peerCertificates = certs

	return nil
}

func (c *Conn) getClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if c.config.GetClientCertificate != nil {
		return c.config.GetClientCertificate(cri)
	}

	for _, chain := range c.config.Certificates {
		if err := cri.SupportsCertificate(&chain); err != nil {
			continue
		}
		return &chain, nil
	}

	// No acceptable certificate found. Don't send a certificate.
	return new(tls.Certificate), nil
}

// clientSessionCacheKey returns a key used to cache sessionTickets that could
// be used to resume previously negotiated TLS sessions with a server.
func clientSessionCacheKey(config *tls.Config) string {
	return config.ServerName
}

// mutualProtocol finds the mutual Next Protocol Negotiation or ALPN protocol
// given list of possible protocols and a list of the preference order. The
// first list must not be empty. It returns the resulting protocol and flag
// indicating if the fallback case was reached.
func mutualProtocol(protos, preferenceProtos []string) (string, bool) {
	for _, s := range preferenceProtos {
		for _, c := range protos {
			if s == c {
				return s, false
			}
		}
	}

	return protos[0], true
}

// hostnameInSNI converts name into an appropriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See RFC 6066, Section 3.
func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
