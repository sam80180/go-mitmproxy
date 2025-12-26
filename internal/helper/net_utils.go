package helper

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unicode"

	"github.com/asaskevich/govalidator"
	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/net/idna"
)

func ParseHostAndPort(s string) (string, int, bool) {
	const addrPattern = `^(?::(?P<port0>\d{0,5})|(?P<host1>(?:\d{1,3}\.){3}\d{1,3})(?::(?P<port1>\d{0,5}))?|\[(?P<host2>[0-9a-fA-F:]+)\](?::(?P<port2>\d{0,5}))?)$`
	re := regexp.MustCompile(addrPattern)
	match := re.FindStringSubmatch(s)
	webHost := ""
	webPort := 0
	bMatched := (match != nil)
	if bMatched {
		for i := 1; i <= 2; i++ {
			idxHost := re.SubexpIndex(fmt.Sprintf("host%d", i))
			if idxHost < 0 || match[idxHost] == "" {
				continue
			} // end if
			webHost = match[idxHost]
			break
		} // end for
		for i := 0; i <= 2; i++ {
			idxPort := re.SubexpIndex(fmt.Sprintf("port%d", i))
			if idxPort < 0 || match[idxPort] == "" {
				continue
			} // end if
			webPort, _ = strconv.Atoi(match[idxPort])
			break
		} // end for
	} // end if
	return webHost, webPort, bMatched
} // end ParseHostAndPort()

func LocalIPForPeer(peer net.IP) (net.IP, error) {
	var raddr net.UDPAddr
	if v4 := peer.To4(); v4 != nil {
		raddr = net.UDPAddr{IP: v4, Port: 9}
	} else {
		raddr = net.UDPAddr{IP: peer, Port: 9}
	} // end if
	conn, err := net.DialUDP("udp", nil, &raddr)
	if err != nil {
		return nil, fmt.Errorf("route decision (DialUDP): %w", err)
	} // end if
	defer conn.Close()
	laddr := conn.LocalAddr().(*net.UDPAddr)
	if laddr == nil || laddr.IP == nil {
		return nil, errors.New("no local addr decided")
	} // end if
	return laddr.IP, nil
} // end LocalIPForPeer()

// finds the interface which has `localIP` assigned.
func IfaceByLocalIP(localIP net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	} // end if
	for _, ifi := range ifaces {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			var ipNet *net.IPNet
			switch v := a.(type) {
			case *net.IPNet:
				ipNet = v
			case *net.IPAddr:
				ipNet = &net.IPNet{IP: v.IP, Mask: net.CIDRMask(128, 128)}
			default:
				continue
			} // end switch
			if ipNet.IP.Equal(localIP) {
				return &ifi, nil
			} // end if
		} // end for
	} // end for
	return nil, fmt.Errorf("no interface owns local IP %s", localIP)
} // end IfaceByLocalIP()

// queries neighbor table (ARP/NDP) for IP on iface
func getClientMACViaRTNL(ifi *net.Interface, ip net.IP) (net.HardwareAddr, error) {
	c, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("rtnetlink.Dial: %w", err)
	} // end if
	defer c.Close()
	neighs, err := c.Neigh.List()
	if err != nil {
		return nil, fmt.Errorf("Neigh.List: %w", err)
	} // end if
	for _, n := range neighs {
		if n.Index == uint32(ifi.Index) && n.Attributes.Address != nil && n.Attributes.Address.Equal(ip) && len(n.Attributes.LLAddress) > 0 {
			return n.Attributes.LLAddress, nil
		} // end if
	} // end for
	return nil, nil
} // end getClientMACViaRTNL()

// parses /proc/net/arp (IPv4 only) as a fallback.
func getClientMACFromProc(ip net.IP) (net.HardwareAddr, error) {
	if ip == nil || ip.To4() == nil {
		return nil, errors.New("/proc/net/arp is IPv4 only")
	} // end if
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	} // end if
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() { // skip header
		return nil, errors.New("empty /proc/net/arp")
	} // end if
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// IP address | HW type | Flags | HW address | Mask | Device
		if len(fields) >= 4 && fields[0] == ip.String() {
			macStr := fields[3]
			hw, err := net.ParseMAC(macStr)
			if err != nil {
				return nil, err
			} // end if
			return hw, nil
		} // end if
	} // end for
	return nil, nil
} // end getClientMACFromProc()

// determines the my/server MAC (per-route) and client MAC.
func ResolveMACs(clientIP net.IP) (myMAC, clientMAC net.HardwareAddr, ifaceName string, err error) {
	if clientIP == nil {
		err = errors.New("nil client IP")
		return
	} // end if
	// 1) Which local IP will be used?
	localIP, e := LocalIPForPeer(clientIP)
	if e != nil {
		err = e
		return
	} // end if

	// 2) Which iface owns that local IP?
	ifi, e := IfaceByLocalIP(localIP)
	if e != nil {
		err = e
		return
	} // end if
	ifaceName = ifi.Name
	myMAC = ifi.HardwareAddr

	// 3) Client MAC via rtnetlink, with /proc fallback for IPv4.
	clientMAC, e = getClientMACViaRTNL(ifi, clientIP)
	if e != nil || clientMAC == nil {
		// Fall back for IPv4 (no root requirement typically)
		if clientIP.To4() != nil && runtime.GOOS == "linux" {
			if hw, e2 := getClientMACFromProc(clientIP); hw != nil {
				clientMAC = hw
				return
			} else if e == nil && e2 != nil {
				e = e2
			} // end if
		} // end if
		err = e // keep rtnetlink error if fallback failed or not applicable
		return
	} // end if
	return
} // end ResolveMACs()

func NetAddrToIP(a net.Addr) (net.IP, error) {
	switch v := a.(type) {
	case *net.IPAddr:
		return v.IP, nil
	case *net.TCPAddr:
		return v.IP, nil
	case *net.UDPAddr:
		return v.IP, nil
	case *net.UnixAddr:
		return nil, errors.New("unix addr has no IP")
	case *net.IPNet: // rarely used as net.Addr, but handle anyway
		return v.IP, nil
	case net.Addr: // fallback string parser if you ever pass a plain Addr
		// Try to parse "ip" or "ip:port"
		host, _, err := net.SplitHostPort(v.String())
		if err != nil {
			// maybe it's just a bare IP
			ip := net.ParseIP(v.String())
			if ip == nil {
				return nil, fmt.Errorf("cannot parse addr %q", v.String())
			} // end if
			return ip, nil
		} // end if
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("cannot parse host %q", host)
		} // end if
		return ip, nil
	} // end switch
	return nil, fmt.Errorf("unsupported addr type %T", a)
} // end NetAddrToIP()

func GetPortFromNetAddr(addr net.Addr) (int, error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.Port, nil
	case *net.UDPAddr:
		return a.Port, nil
	} // end switch
	return 0, fmt.Errorf("unsupported addr type: %T", addr)
} // end GetPortFromNetAddr()

type HostResult struct {
	Addr netip.Addr // valid if IsValid() == true
	FQDN string     // valid if not empty
} // end type

func StripPortIfPresent(addr string) string {
	// Fast path: proper host:port (IPv6 must be in brackets)
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	} // end if

	// If it's a bracketed IPv6 with no port, return inside the brackets.
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	} // end if

	// If there's exactly one colon and it looks like a ":<digits>" port, strip it.
	if i := strings.LastIndex(addr, ":"); i > 0 && i < len(addr)-1 {
		allDigits := true
		for _, r := range addr[i+1:] {
			if !unicode.IsDigit(r) {
				allDigits = false
				break
			} // end if
		} // end for
		if allDigits {
			return addr[:i]
		} // end if
	} // end if

	// Otherwise, return as-is (covers bare IPv6, host without port, etc.).
	return addr
} // end StripPortIfPresent()

// ClassifyHost determines whether s is IPv4, IPv6, or an FQDN.
// If it’s an IP, HostResult.Addr is set. If it’s an FQDN, HostResult.FQDN is set.
func ClassifyHost(s string) (*HostResult, error) {
	if s == "" {
		return nil, fmt.Errorf("empty string")
	} // end if
	host := StripPortIfPresent(strings.TrimSpace(s))
	if host == "" {
		return nil, fmt.Errorf("empty host after strip")
	} // end if

	// Normalize IDN (例え.テスト → xn--r8jz45g.xn--zckzah)
	asciiHost, err := idna.Lookup.ToASCII(strings.TrimSuffix(host, "."))
	if err == nil && asciiHost != "" {
		host = asciiHost
	} // end if

	// First: try as IP
	if addr, err := netip.ParseAddr(host); err == nil {
		return &HostResult{Addr: addr}, nil
	} // end if

	// Otherwise: try as DNS name
	if govalidator.IsDNSName(host) && len(host) <= 253 {
		return &HostResult{FQDN: host}, nil
	} // end if
	return nil, fmt.Errorf("not a valid IP or FQDN: %q", s)
} // end ClassifyHost()

func NetAddr2IpAndPort(srcAddr net.Addr) (net.IP, int, error) {
	srcIp, errIpSrc := NetAddrToIP(srcAddr)
	if errIpSrc != nil {
		return nil, 0, errIpSrc
	} // end if
	srcIp = srcIp.To4()
	if srcIp == nil {
		return nil, 0, fmt.Errorf("unsupported address family")
	} // end if
	SrcPort, eSrcPrt := GetPortFromNetAddr(srcAddr)
	if eSrcPrt != nil {
		return nil, 0, eSrcPrt
	} // end if
	return srcIp, SrcPort, nil
} // end NetAddr2IpAndPort()

func LookupAddr(addr string) (net.IP, error) {
	ips, err := net.LookupHost(addr)
	if err != nil {
		return nil, err
	} // end if
	if len(ips) <= 0 {
		return nil, fmt.Errorf("empty result")
	} // end if
	return net.ParseIP(ips[0]), nil
} // end LookupAddr()

func IsValidPort(v int) bool {
	return (0 < v && v <= 65535)
} // end IsValidPort()

func IsValidPortStr(s string) bool {
	v, e := strconv.Atoi(s)
	return e == nil && IsValidPort(v)
} // end IsValidPortStr()
