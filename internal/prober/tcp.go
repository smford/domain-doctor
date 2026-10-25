package prober

import (
	"net"
	"time"
)

type TCPProber struct {
	Timeout time.Duration
}

func NewTCPProber(timeout time.Duration) *TCPProber {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &TCPProber{Timeout: timeout}
}

func (p *TCPProber) CheckPort(address string) (bool, time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, p.Timeout)
	rtt := time.Since(start)
	if err != nil {
		return false, rtt, err
	}
	_ = conn.Close()
	return true, rtt, nil
}
