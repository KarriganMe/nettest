package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type HopStats struct {
	Sent      int
	Received  int
	Latencies []time.Duration
}

type AnalysisResult struct {
	Target    string
	Timestamp time.Time

	// MTR Data
	Hops       []HopStats // Defined earlier
	PacketLoss float64
	AvgLatency time.Duration
	Jitter     time.Duration

	// Censorship Data
	DNSStatus  string // "OK", "SPOOFED", "UNKNOWN"
	SystemIP   string
	TrustedIP  string
	HTTPStatus int // 200, 403, 0 (Timeout)
	IsBlocked  bool
}

type Reporter interface {
	Generate(result *AnalysisResult) string
}

type TextReporter struct{}

func main() {
	// F at the end is used for Flags only
	checkCensorshipF := flag.Bool("censor", false, "Check for censorship")
	checkMTRF := flag.Bool("mtr", false, "Run MTR (Ping/Traceroute)")
	pingTestF := flag.Bool("ping", false, "Run Ping Test")

	targetDNSF := flag.String("dns", "8.8.8.8", "Target DNS server to use for spoofing or poisoning checks.")
	packetCountF := flag.Int("count", 0, "Number of pings to send. Default: 0 - Unlimited")

	outputF := flag.String("o", "", "Save report to file (e.g. report.txt)")

	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("Usage: nettest [flags] <target>\n Example: nettest --censor -dns 8.8.8.8 -count 10 google.com -o report.txt\n Use nettest --help")
		os.Exit(1)
	}
	target := args[0]

	fmt.Printf("Target: %s\n", target)
	result := &AnalysisResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	if runtime.GOOS == "windows" {
		setupWinFirewall()
		defer cleanupWindowsFirewall()
	}

	var output string
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c // Wait for Ctrl+C
		if runtime.GOOS == "windows" {
			fmt.Println("\n\nStopping... Cleaning up Firewall rules...")
			reporter := &TextReporter{}
			result.Summary()
			output = reporter.Generate(result)
			if *outputF != "" {
				os.WriteFile(*outputF, []byte(output), 0644)
			}
			cleanupWindowsFirewall()
			os.Exit(0)
		} else {
			fmt.Println("\n\nStopping...")
			reporter := &TextReporter{}
			result.Summary()
			output = reporter.Generate(result)
			if *outputF != "" {
				os.WriteFile(*outputF, []byte(output), 0644)
			}
			os.Exit(0)
		}
	}()

	if *checkMTRF && *pingTestF {
		fmt.Println("Error: You cannot run --mtr and --ping at the same time.")
		fmt.Println("MTR already provides ping statistics.")
		os.Exit(1)
	}

	if *checkCensorshipF {
		checkCensorship(target, *targetDNSF, result)
	}
	if *checkMTRF {
		mtr(target, *packetCountF, result)
	}
	if *pingTestF {
		count := *packetCountF
		if *packetCountF == 0 {
			count = 999999
		}
		pingTest(target, count, result)
	}

	//output
	reporter := &TextReporter{}
	result.Summary()
	output = reporter.Generate(result)
	if *outputF != "" {
		os.WriteFile(*outputF, []byte(output), 0644)
	} else {
		fmt.Println(output)
	}

	fmt.Println("\nScan finished. Press Enter to exit...")
	fmt.Scanln()
}

func mtr(target string, count int, result *AnalysisResult) {
	fmt.Printf("MTR: Tracing route to %s\n", target)

	dst, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		fmt.Printf("Error resolving target: %v\n", err)
		return
	}

	//connection
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Printf("Error listening ICMP (run as Admin?): %v\n", err)
		return
	}
	defer c.Close()
	p := c.IPv4PacketConn()

	//hops
	if len(result.Hops) == 0 {
		result.Hops = make([]HopStats, 30)
	}

	loops := count
	if loops == 0 {
		loops = 1
	}

	for i := 0; i < loops; i++ {
		fmt.Printf("===== PASS %d =====\n", i+1)
		destinationReached := false
		//traceroute
		for ttl := 1; ttl <= 30; ttl++ {
			if destinationReached {
				break
			}

			id := (os.Getpid() + 717) & 0xffff
			p.SetTTL(ttl)
			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho, Code: 0,
				Body: &icmp.Echo{
					ID:   id,
					Seq:  ttl,
					Data: []byte("NETTEST"),
				},
			}
			msgBytes, _ := msg.Marshal(nil)

			result.Hops[ttl-1].Sent++

			start := time.Now()
			_, err := p.WriteTo(msgBytes, nil, dst)
			if err != nil {
				fmt.Printf("%d: Send Error: %v\n", ttl, err)
				continue
			}

			deadline := time.Now().Add(1 * time.Second)
			p.SetReadDeadline(deadline)
		readloop:
			for time.Now().Before(deadline) {
				replyBuf := make([]byte, 1500)
				n, _, peer, err := p.ReadFrom(replyBuf)
				if err != nil {
					fmt.Printf("%d: * (Timeout)\n", ttl)
					break
				}
				msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), replyBuf[:n])
				if err != nil {
					fmt.Printf("%d: Parse Error: %v\n", ttl, err)
					continue
				}
				switch msg.Type {
				case ipv4.ICMPTypeEchoReply:
					echo, ok := msg.Body.(*icmp.Echo)
					if !ok {
						continue
					}
					if echo.ID != id || echo.Seq != ttl {
						continue
					}
					dstIP := net.ParseIP(target)
					if dstIP == nil {
						ips, err := net.LookupIP(target)
						if err != nil {
							continue
						}
						dstIP = ips[0]
					}
					if dstIP.String() != peer.String() {
						continue
					}

					result.Hops[ttl-1].Latencies = append(result.Hops[ttl-1].Latencies, time.Since(start))
					result.Hops[ttl-1].Received++
					fmt.Printf("Reply from %s: time=%v\n", peer, time.Since(start))
					destinationReached = true
					break readloop

				case ipv4.ICMPTypeTimeExceeded:
					fmt.Printf("%d: %v  %v\n", ttl, peer, time.Since(start))
					result.Hops[ttl-1].Received++
					result.Hops[ttl-1].Latencies = append(result.Hops[ttl-1].Latencies, time.Since(start))
					break readloop

				default:
					{
						continue
					}
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func checkCensorship(target string, dnsServer string, result *AnalysisResult) {
	fmt.Printf("CENSOR: Starting Ban Detection...")

	host, port := parseTarget(target)
	isIPAddr := net.ParseIP(host) != nil

	//DNS Check
	if isIPAddr {
		fmt.Println("Target is IP. Skipping DNS check.")
		result.DNSStatus = "N/A Target is IP"
		result.SystemIP = host
		result.TrustedIP = host
	} else {
		CheckDNSSpoofing(host, dnsServer, result)
	}

	//TCP Connection Test
	targetAddr := net.JoinHostPort(host, port)
	fmt.Printf("Checking TCP on %s...", targetAddr)

	timeout := 3 * time.Second
	conn, err := net.DialTimeout("tcp", targetAddr, timeout)

	if err != nil {
		result.IsBlocked = true
		result.HTTPStatus = 0
		fmt.Printf("TCP Connection to %s FAILED (Blocked or Down)\n", targetAddr)
		return
	}
	conn.Close()

	//DPI Check
	//Only for Web Servers - :80/:443
	if port == "80" || port == "443" {
		fmt.Println("Checking HTTP/HTTPS Reachiblity (DPI)")
		protocol := "https"
		if port == "80" {
			protocol = "http"
		}
		client := http.Client{Timeout: timeout}
		resp, err := client.Get(fmt.Sprintf("%s://%s", protocol, host))

		if err != nil {
			result.IsBlocked = true
			fmt.Println("TCP OK, but HTTP Request Failed (Likely DPI/SNI Block)")
		} else {
			result.IsBlocked = false
			result.HTTPStatus = resp.StatusCode
			resp.Body.Close()
			fmt.Printf("HTTP Status: %d OK\n", resp.StatusCode)
		}
	} else {
		fmt.Println("Port is not 80/443. Skipping HTTP/DPI Check.")
		result.IsBlocked = false // TCP worked, so its not blocked
		result.HTTPStatus = -1
	}
}

func pingTest(target string, count int, result *AnalysisResult) {
	fmt.Printf("PING %s: %d packets...\n", target, count)

	dst, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		fmt.Printf("Error resolving target: %v\n", err)
		return
	}

	//connection
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Printf("Error listening ICMP (run as Admin?): %v\n", err)
		return
	}
	defer c.Close()
	p := c.IPv4PacketConn()

	if len(result.Hops) == 0 {
		result.Hops = make([]HopStats, 1)
	}

	for i := 0; i < count; i++ {
		id := (os.Getpid() + 717) & 0xffff
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   id,
				Seq:  i,
				Data: []byte("NETTEST"),
			},
		}
		msgBytes, err := msg.Marshal(nil)
		if err != nil {
			fmt.Printf("%d: Send Error: %v\n", i, err)
			continue
		}

		result.Hops[0].Sent++

		start := time.Now()

		_, err = p.WriteTo(msgBytes, nil, dst)
		if err != nil {
			fmt.Printf("%d: Send Error: %v\n", i, err)
			continue
		}

		deadline := time.Now().Add(1 * time.Second)
		p.SetReadDeadline(deadline)
	readloop:
		for time.Now().Before(deadline) {
			replyBuf := make([]byte, 1500)
			n, _, peer, err := p.ReadFrom(replyBuf)
			if err != nil {
				fmt.Printf("%d: * (Timeout)\n", i)
				break
			}
			msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), replyBuf[:n])
			if err != nil {
				fmt.Printf("%d: Parse Error: %v\n", i, err)
				continue
			}
			switch msg.Type {
			case ipv4.ICMPTypeEchoReply:
				echo, ok := msg.Body.(*icmp.Echo)
				if !ok {
					continue
				}
				if echo.ID != id || echo.Seq != i {
					continue
				}
				dstIP := net.ParseIP(target)
				if dstIP == nil {
					ips, err := net.LookupIP(target)
					if err != nil {
						continue
					}
					dstIP = ips[0]
				}
				if dstIP.String() != peer.String() {
					continue
				}

				result.Hops[0].Latencies = append(result.Hops[0].Latencies, time.Since(start))
				result.Hops[0].Received++
				fmt.Printf("Reply from %s: time=%v\n", peer, time.Since(start))
				break readloop

			default:
				{
					continue
				}
			}
		}
	}
}

func (h *HopStats) CalculateJitter() time.Duration {
	if len(h.Latencies) < 2 {
		return 0
	}
	var totalDiff time.Duration
	for i := 1; i < len(h.Latencies); i++ {
		diff := h.Latencies[i] - h.Latencies[i-1]
		if diff < 0 {
			diff = -diff
		}
		totalDiff += diff
	}

	return totalDiff / time.Duration(len(h.Latencies)-1)
}

func CheckDNSSpoofing(target string, dnsServer string, result *AnalysisResult) {
	sysIPs, err := net.LookupHost(target)
	if err != nil {
		result.DNSStatus = "FAILED_LOCAL"
		return
	}
	result.SystemIP = sysIPs[0]

	c := new(dns.Client)
	m := new(dns.Msg)

	m.SetQuestion(dns.Fqdn(target), dns.TypeA)
	r, _, err := c.Exchange(m, dnsServer+":53")

	if err != nil {
		fmt.Println("Cant reach DNS server")
		return
	}

	found := false
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			result.TrustedIP = a.A.String()
			found = true
			break
		}
	}

	if !found {
		result.DNSStatus = "NO_TRUSTED_RECORD"
		return
	}

	if result.SystemIP == result.TrustedIP {
		result.DNSStatus = "SUCCESS"
	} else {
		result.DNSStatus = "MISMATCH"
	}
}

func isIP(target string) bool {
	return net.ParseIP(target) != nil
}

func parseTarget(target string) (string, string) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// no port found, assume its just a host
		// default to port 443 (HTTPS) for connectivity checks
		fmt.Println("No port found, defaulting to port 443")
		return target, "443"
	}
	return host, port
}

func (t *TextReporter) Generate(r *AnalysisResult) string {
	return fmt.Sprintf(
		"REPORT for %s\n"+
			"-----------------------------------------------------\n"+
			"Time: %s\n"+
			"Packet Loss: %.2f%%\n"+
			"Avg Latency: %s\n"+
			"Jitter:      %s\n"+
			"-----------------------------------------------------\n"+
			"DNS Status:  %s\n"+
			"System IP:   %s\n"+
			"Trusted IP:  %s\n"+
			"-----------------------------------------------------\n"+
			"OS: %s\n"+
			"=====================================================\n"+
			"==== Network Testing Tool created by karrigan.me ====\n"+
			"======= https://github.com/KarriganMe/nettest =======\n"+
			"=====================================================\n",
		r.Target, r.Timestamp.Format(time.RFC822),
		r.PacketLoss, r.AvgLatency, r.Jitter,
		r.DNSStatus, r.SystemIP, r.TrustedIP,
		runtime.GOOS,
	)
}

func setupWinFirewall() {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=NetTest-Temp", "dir=in", "action=allow", "protocol=icmpv4:11,any", "enable=yes")
	cmd.Run()
}

func cleanupWindowsFirewall() {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=NetTest-Temp")
	cmd.Run()
}

func (r *AnalysisResult) Summary() {
	var lastHop HopStats
	found := false

	for i := len(r.Hops) - 1; i >= 0; i-- {
		if r.Hops[i].Received > 0 {
			lastHop = r.Hops[i]
			found = true
			break
		}
	}

	if !found {
		return
	}

	if lastHop.Sent > 0 {
		r.PacketLoss = 100 - (float64(lastHop.Received) / float64(lastHop.Sent) * 100)
	}

	var totalLatency time.Duration
	for _, lat := range lastHop.Latencies {
		totalLatency += lat
	}

	if len(lastHop.Latencies) > 0 {
		r.AvgLatency = totalLatency / time.Duration(len(lastHop.Latencies))
	}

	r.Jitter = lastHop.CalculateJitter()
}
