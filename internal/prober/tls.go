package prober

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

type TLSResult struct {
	Version      uint16
	CipherSuite  uint16
	ServerName   string
	Certificates []*x509.Certificate
	Verified     bool
	VerifyError  error
	DaysToExpiry int
}

func ProbeTLS(ctx context.Context, host string, port int, serverName string, timeout time.Duration) (*TLSResult, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout}
	addr := fmt.Sprintf("%s:%d", host, port)

	conf := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: false,
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, conf)
	handshakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		// Try again with InsecureSkipVerify to capture cert metadata even if self-signed/expired
		insecureConf := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
		}
		rawConn2, err2 := dialer.DialContext(ctx, "tcp", addr)
		if err2 != nil {
			return nil, err
		}
		defer rawConn2.Close()

		tlsConn2 := tls.Client(rawConn2, insecureConf)
		if err2 := tlsConn2.HandshakeContext(handshakeCtx); err2 != nil {
			return nil, err
		}

		state := tlsConn2.ConnectionState()
		res := buildResult(state, false, err)
		return res, nil
	}

	state := tlsConn.ConnectionState()
	return buildResult(state, true, nil), nil
}

func ProbeSTARTTLS(ctx context.Context, host string, port int, timeout time.Duration) (*TLSResult, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout}
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(greeting, "220") {
		return nil, fmt.Errorf("invalid smtp greeting: %s", strings.TrimSpace(greeting))
	}

	// Send EHLO
	if _, err := fmt.Fprintf(conn, "EHLO domain-doctor.diagnostic\r\n"); err != nil {
		return nil, err
	}

	supportsStartTLS := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if strings.Contains(strings.ToUpper(line), "STARTTLS") {
			supportsStartTLS = true
		}
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	if !supportsStartTLS {
		return nil, fmt.Errorf("server does not advertise STARTTLS")
	}

	// Send STARTTLS command
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return nil, err
	}

	resp, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(resp, "220") {
		return nil, fmt.Errorf("starttls command rejected: %s", strings.TrimSpace(resp))
	}

	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	state := tlsConn.ConnectionState()
	return buildResult(state, true, nil), nil
}

func buildResult(state tls.ConnectionState, verified bool, verifyErr error) *TLSResult {
	res := &TLSResult{
		Version:      state.Version,
		CipherSuite:  state.CipherSuite,
		ServerName:   state.ServerName,
		Certificates: state.PeerCertificates,
		Verified:     verified,
		VerifyError:  verifyErr,
	}

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		remaining := time.Until(leaf.NotAfter)
		res.DaysToExpiry = int(remaining.Hours() / 24)
	}

	return res
}
