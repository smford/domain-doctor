package prober

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var PublicResolvers = []string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"9.9.9.9:53",
	"208.67.222.222:53",
}

type DNSProber interface {
	Query(server string, qname string, qtype uint16) (*dns.Msg, time.Duration, error)
	QueryWithDO(server string, qname string, qtype uint16) (*dns.Msg, time.Duration, error)
	QueryWithSubnet(server string, qname string, qtype uint16, clientIP net.IP) (*dns.Msg, time.Duration, error)
	QueryTCP(server string, qname string, qtype uint16) (*dns.Msg, time.Duration, error)
	CheckAXFR(server string, domain string) (bool, int, error)
}

type DefaultDNSProber struct {
	Timeout time.Duration
}

func NewDefaultDNSProber(timeout time.Duration) *DefaultDNSProber {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &DefaultDNSProber{Timeout: timeout}
}

func ensurePort(server string) string {
	if !strings.Contains(server, ":") {
		return server + ":53"
	}
	return server
}

func (p *DefaultDNSProber) Query(server string, qname string, qtype uint16) (*dns.Msg, time.Duration, error) {
	c := new(dns.Client)
	c.Timeout = p.Timeout

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.RecursionDesired = false
	m.SetEdns0(1232, false)

	in, rtt, err := c.Exchange(m, ensurePort(server))
	return in, rtt, err
}

func (p *DefaultDNSProber) QueryRecursive(server string, qname string, qtype uint16) (*dns.Msg, time.Duration, error) {
	c := new(dns.Client)
	c.Timeout = p.Timeout

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)

	in, rtt, err := c.Exchange(m, ensurePort(server))
	return in, rtt, err
}

func (p *DefaultDNSProber) QueryWithDO(server string, qname string, qtype uint16) (*dns.Msg, time.Duration, error) {
	c := new(dns.Client)
	c.Timeout = p.Timeout

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.RecursionDesired = false
	m.SetEdns0(1232, true)

	in, rtt, err := c.Exchange(m, ensurePort(server))
	return in, rtt, err
}

func (p *DefaultDNSProber) QueryWithSubnet(server string, qname string, qtype uint16, clientIP net.IP) (*dns.Msg, time.Duration, error) {
	c := new(dns.Client)
	c.Timeout = p.Timeout

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.RecursionDesired = false

	family := uint16(1)
	sourceNetmask := uint8(24)
	if clientIP.To4() == nil {
		family = 2
		sourceNetmask = 48
	}

	m.SetEdns0(1232, false)
	opt := m.IsEdns0()
	if opt != nil {
		subnet := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        family,
			SourceNetmask: sourceNetmask,
			Address:       clientIP,
		}
		opt.Option = append(opt.Option, subnet)
	}

	in, rtt, err := c.Exchange(m, ensurePort(server))
	return in, rtt, err
}

func (p *DefaultDNSProber) QueryTCP(server string, qname string, qtype uint16) (*dns.Msg, time.Duration, error) {
	c := new(dns.Client)
	c.Net = "tcp"
	c.Timeout = p.Timeout

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.RecursionDesired = false

	in, rtt, err := c.Exchange(m, ensurePort(server))
	return in, rtt, err
}

func (p *DefaultDNSProber) CheckAXFR(server string, domain string) (bool, int, error) {
	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))

	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()

	channel, err := t.In(m, ensurePort(server))
	if err != nil {
		return false, 0, err
	}

	count := 0
	isAllowed := false

	for {
		select {
		case env, ok := <-channel:
			if !ok {
				return isAllowed, count, nil
			}
			if env.Error != nil {
				return isAllowed, count, env.Error
			}
			if len(env.RR) > 0 {
				count += len(env.RR)
				isAllowed = true
			}
		case <-ctx.Done():
			return isAllowed, count, fmt.Errorf("axfr timeout")
		}
	}
}
