package transport

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/goburrow/quic/testdata"
)

func TestHandleClientInitial(t *testing.T) {
	const clientInitial = `
c5ff00001710b289a5197320e22fa4c4667b3f9af7ae142d45eef9200c1be344
7e1d65fa03cbe7f4564442004482b6fffe5728f25e4f619b874fc30a7a0f6025
3953d64c7c392a0286582dcd38a8c915d016aef8e99d396234957f08fb96a4f4
6e2ee03a8dfeb528c295003ba13859a5fe76ad30a57bb8d4f13bf94231e56adb
30898d8ad9912d5c52504b06de941f7e7270a1d5094a4d2a10450977ce24a9b9
61a486d865dc2b1b48d6e13d0fb3e60ca08aa574cb4486f9b40036a02ab8c10d
3c95f29f01e8ba5f4081cfe657a06fdca7b941f576fef6e070e9fe26b9284ab7
8e0bc42a65e4c3ebeb1b917b9d4ddbff5d8ae77895753625d9d9fcbadac44a28
2c089090628f36fcd3d09f6e7983a3050cabff020c052c0a9eeec9c2fdb3592f
b5c16fac11f5bbbd7d440a90b75b14293ebc1f8d3fc71ae3870d3778b505f17a
b67e1c27441a77966b3cbe7dd5a11d279f6bc34f6baceedc53ac955d0e214b62
347df8e9c8173c7ec48954a8ee32a2b744908698d98bfc8e89b75c9821c4ccc9
53a98ba3a0a309865056991107a5e17846a6de5ed4266ff77bebbe038cc9c1b7
02ec4b6e4c1dbeb6a0a798f896bf65f3e120d1538668b74b06aa4d1454d90ea4
ddd12d6d6e64dbc7946d97e9fe9b31ac4f594680e0186f98aa83423293b4ea93
461f7e703bcb655b5261fecbb2cb717ab0932dca8e0856879432456225091a20
aafafd54f1f7b859ccdcbca4eb73702c4c8124d2286084ae7efbd2ab0e0abdb4
8c053d9e7165a0c8ca5f6a3855ebb5f89030ec832f00410d7f88c29763041a02
94953bdbd003c0b8b53b76414c227ad797055d0cb0859139ec719fdb72d2cfa3
dc621e7d5721f7a32b8f0760e96ce257b9bd2ba098cdb04f8670039fb102b44f
b98a4a46c9802840b49a700b868c4d5c7f44de47983ebf288e3121fffb61c7c6
d8dbc1d97989e70432b3eaa112758b8d74bf2ff22e3ae9e1b5bff0f41a85d701
245ea1610e5bb672b4190aaedd6c0131fa5e5810a69c585bf13db5657332c494
39f911c135fe9b8a6ae8a988b43736820304d30e3e893bc64fad6d2e98429cce
6fa9fcf23f994e27dbafb5b2aba8e04142f616fc0ed824515b7182cd5b093214
d14f77627393fe5067025b92c7270e10329be0d239037025decf1095b6b4d5f8
8cd7ed3a3cf22e9bcf44f6a018d68fdf68e7745edccf1b4753e290fd0da73264
7a20cb73d2367ed70fc4f3d3530673d1eb41179e9e640dea96d4754be5a8e2f3
8d7d0f63981725360ccaff30edc69f3c60c39f5c67864fd83bc9d5b026dc6311
36c2e8786cf99fc14330d9e747c2856cce695fa67a8340bb635186ad9d1ae13d
a8988f2a7da7191fb31ac04fc69c0b10517e2cdb14d4fcd842a8fc30db8237eb
0d9666c6783f70e3c2cd56a6e53c903be0ded892338659f3322fe667525869ed
492e78b2c5a1d74f3bd23ce67751e53f46d65bbb0f7719ef7b8226818ed7983b
6cf29c55e53b078fa30c0a27f07d212ee306b50c3034f2ce00bc8ade3794856f
34d992bbfc99bd020ffd915323d3bff7f2704ecbc23741216326e998d290ac33
67fbbd7e2f3dc25a847406e0d332fc7e9f896c08e8251355452fa62ee8b512b4
898684e58ef7ad0ed23d384a9f8cbe21bbd7dc4a8b8be18f1d3ed1e38bb22837
4aa0e56ad06e03f8be66878c4617849a`
	config := newConfig()
	b := testdata.DecodeHex(clientInitial)
	h := Header{}
	_, err := h.Decode(b, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Accept(h.DCID, nil, config)
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.Write(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(b) {
		t.Fatalf("bytes received: %d, want %d", n, len(b))
	}
	n, err = c.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("bytes sent: %d", n)
	}
	t.Logf("send: %d", n)
}

func newConfig() *Config {
	const certPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`
	const keyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`

	c := NewConfig()
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		panic(err)
	}
	c.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	return c
}

func TestHandshake(t *testing.T) {
	clientConfig := NewConfig()
	clientConfig.TLS = &tls.Config{
		InsecureSkipVerify: true,
	}
	client, err := Connect([]byte{1, 2, 3, 4}, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := newConfig()
	server, err := Accept(client.dcid, nil, serverConfig)
	if err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 1200)
	start := time.Now()
	for !client.IsEstablished() && !server.IsEstablished() {
		n, err := client.Read(b)
		if n == 0 || err != nil {
			t.Fatalf("client read: %v %v", n, err)
		}
		m, err := server.Write(b[:n])
		if m != n || err != nil {
			t.Fatalf("server write: %v/%v %v", m, n, err)
		}
		n, err = server.Read(b)
		if n == 0 || err != nil {
			t.Fatalf("server read: %v %v", n, err)
		}
		m, err = client.Write(b[:n])
		if m != n || err != nil {
			t.Fatalf("client write: %v/%v %v", m, n, err)
		}
		t.Logf("client received %d bytes", m)
		elapsed := time.Since(start)
		if elapsed > 2*time.Second {
			t.Fatalf("handshake too slow: %v", elapsed)
		}
	}
}
