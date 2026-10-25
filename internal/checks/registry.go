package checks

import (
	"github.com/smford/domain-doctor/internal/engine"
)

func RegisterAll(e *engine.Engine) {
	e.Register(&DNSDelegationCheck{})
	e.Register(&NegativeCacheCheck{})
	e.Register(&ZoneTransferCheck{})
	e.Register(&RecursionCheck{})
	e.Register(&DNSSECCheck{})
	e.Register(&ASNDiversityCheck{})
	e.Register(&ECSGeoCheck{})
	e.Register(&SPFCheck{})
	e.Register(&DMARCCheck{})
	e.Register(&DKIMCheck{})
	e.Register(&MailSTARTTLSCheck{})
	e.Register(&CAACheck{})
	e.Register(&TLSHealthCheck{})
	e.Register(&SubdomainTakeoverCheck{})
	e.Register(&CTLogCheck{})
	e.Register(&HomographCheck{})
	e.Register(&RDAPCheck{})
	e.Register(&MTASTSCheck{})
	e.Register(&BIMICheck{})
	e.Register(&DefensiveDomainCheck{})
	e.Register(&HTTPSSVCBCheck{})
	e.Register(&DANECheck{})
	e.Register(&FlagDayCheck{})
	e.Register(&NSECWalkCheck{})
	e.Register(&DNSCookiesCheck{})
	e.Register(&WildcardCheck{})
	e.Register(&CDNOriginCheck{})
	e.Register(&PSLBoundaryCheck{})
	e.Register(&PSLCookieIsolationCheck{})
}
