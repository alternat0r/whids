package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/0xrawsec/golang-utils/crypto/data"
)

// Client structure definition
type Client struct {
	Proto             string `json:"proto" toml:"proto" comment:"Protocol to use to connect to manager (http or https)"`
	Host              string `json:"host" toml:"host" comment:"Hostname or IP of the manager"`
	Port              int    `json:"port" toml:"port" comment:"Port at which endpoint API is running on manager server"`
	UUID              string `json:"endpoint-uuid" toml:"endpoint-uuid" comment:"Endpoint UUID configured on manager used to authenticate this endpoint"`
	Key               string `json:"endpoint-key" toml:"endpoint-key" comment:"Endpoint key configured on manager used to authenticate this endpoint"`
	ServerKey         string `json:"server-key" toml:"server-key" comment:"Key configured on manager, used to authenticate server on this endpoint\n This settings does not protect from MITM, so configuring server\n certificate pinning is recommended."`
	ServerFingerprint string `json:"server-fingerprint" toml:"server-fingerprint" comment:"Configure manager certificate pinning\n Put here the manager's certificate fingerprint"`
	Unsafe            bool   `json:"unsafe" toml:"unsafe" comment:"Allow unsafe HTTPS connection"`
	MaxUploadSize     int64  `json:"max-upload-size" toml:"max-upload-size" comment:"Maximum allowed upload size"`

	localAddr string
}

func (c *Client) HasConnectionSettings() bool {
	return c.Proto != "" && c.Host != "" && c.UUID != "" && c.Key != ""
}

// ManagerIP returns the IP address of the manager if any, returns nil otherwise
func (c *Client) ManagerIP() net.IP {
	if ip := net.ParseIP(c.Host); ip != nil {
		return ip
	}

	if ips, err := net.LookupIP(c.Host); err == nil {
		return ips[0]
	}

	return nil
}

func (c *Client) DialContext(ctx context.Context, network, addr string) (con net.Conn, err error) {
	dialer := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	con, err = dialer.DialContext(ctx, network, addr)

	if err == nil && con != nil {
		if addr, ok := con.LocalAddr().(*net.TCPAddr); ok {
			c.localAddr = addr.IP.String()
		}
	}

	return
}

func (c *Client) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		Config: &tls.Config{InsecureSkipVerify: c.Unsafe},
	}

	nc, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	con := nc.(*tls.Conn)

	if addr, ok := con.LocalAddr().(*net.TCPAddr); ok {
		c.localAddr = addr.IP.String()
	}

	if c.ServerFingerprint == "" {
		return con, nil
	}

	// Only the leaf certificate (the one the server proved possession of the
	// private key for) must be pinned. The rest of the chain is sent by the
	// peer and, when verification is disabled (Unsafe), is not validated, so
	// matching any of them would let a MITM append the legit manager's
	// (public) certificate to its own chain and pass the pinning check.
	connstate := con.ConnectionState()
	if len(connstate.PeerCertificates) == 0 {
		con.Close()
		return nil, fmt.Errorf("server fingerprint not verified: no peer certificate")
	}

	der, err := x509.MarshalPKIXPublicKey(connstate.PeerCertificates[0].PublicKey)
	if err != nil {
		con.Close()
		return nil, err
	}

	if data.Sha256(der) != c.ServerFingerprint {
		con.Close()
		return nil, fmt.Errorf("server fingerprint not verified")
	}

	return con, nil
}

// Transport creates an approriate HTTP transport from a configuration
// Cert pinning inspired by: https://medium.com/@zmanian/server-public-key-pinning-in-go-7a57bbe39438
func (c *Client) Transport() http.RoundTripper {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           c.DialContext,
		DialTLSContext:        c.DialTLSContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func (c *Client) LocalAddr() string {
	return c.localAddr
}
