// mk8-nncs-local: a minimal Nintendo NAT-Check Server (NCS / "nncs") responder for MK8/Pia.
//
// The MK8 client (Pia NatDetectionJob) resolves nncs1-lp1.n.n.srv.nintendo.net and
// nncs2-lp1.n.n.srv.nintendo.net (redirected to this VPS by the console's custom DNS) and sends
// 16-byte UDP probes to port 10025 on BOTH server identities (confirmed via live capture — port
// 10125 is never actually contacted by a real client, despite this responder also listening
// there). Each probe is 4x u32 BIG-ENDIAN:
//   [0]=type/test_id  [4]=ext_port(ignored)  [8]=ext_ip(ignored)  [12]=local_ip
// We must reply with 16 bytes, 4x u32 BIG-ENDIAN:
//   [0]=echo type unchanged  [4]=observed UDP source port  [8]=observed source IP  [12]=server IP
// The Switch only ever sends test ids 101/102/103; the classifier compares the external port it
// learns across the two server IPs (nncs1 vs nncs2), not across ports. Ports 33334/33335 are
// reachability sinkholes (bind, never reply).
//
// nncs1-lp1 and nncs2-lp1 resolve to two DIFFERENT server IPs in real Nintendo infra (citron's
// own redirect table splits them the same way: nncs1 -> nextendo_server_ip, nncs2 ->
// nextendo_nat_ip). Each responder is bound to an EXPLICIT local IP (never the 0.0.0.0 wildcard)
// so replies always go out with a source address matching the IP the probe actually arrived on.
// This matters because the Switch's Pia client uses a connected UDP socket per probe: if a reply
// comes back from the "wrong" local IP (which is what the kernel's route-selected wildcard
// source would do on a multi-homed host), the OS silently drops it before the game ever sees it.
//
// Protocol verified against MK8 main_v305 disassembly (send 0x962424, parse 0x962500, ports
// 0x2729/0x278d). Run with the container on --network host so the
// observed source IP/port are the client's real external endpoint (not a NAT/docker gateway).
package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// natMap remembers each client's observed external UDP endpoint (public IP -> UDP
// port), written to a shared file so the NEX secure server can inject the REAL UDP
// port into the P2P station URLs at GetSessionURLs time. The Pia client probes nncs
// AFTER it registers its (TCP WebSocket) station URL, so the register port is wrong
// for P2P — this bridge gives the server the right UDP port.
var (
	natMu   sync.Mutex
	natMap  = map[string]string{}
	natFile = func() string {
		if v := os.Getenv("NNCS_NAT_FILE"); v != "" {
			return v
		}
		return "/data/nat_endpoints.txt"
	}()

	// natSeen[ip] = the current probing round for that client: readings observed per server
	// identity (nncs1 vs nncs2, not per destination port — a live capture showed the real
	// client sends every probe to port 10025 on both). A round resets after roundGap of
	// silence: the client opens a fresh local UDP socket per round (initial connect, later
	// P2P hole-punch attempt, ...), and a cone NAT legitimately maps a different local port
	// to a different external port across separate rounds — comparing a stale reading from
	// an old round against a fresh one from a new round misreads ordinary cone behavior as
	// symmetric. Only readings within the same round are ever compared.
	natSeen = map[string]*natRound{}
	natType = map[string]string{} // ip -> "cone"|"sym", latest complete round only
	typeFile = func() string {
		if v := os.Getenv("NNCS_TYPE_FILE"); v != "" {
			return v
		}
		return "/data/nat_types.txt"
	}()
)

// roundGap: a gap longer than this since the last probe from an IP starts a new round.
// Real rounds observed in capture arrive within well under a second of each other.
const roundGap = 3 * time.Second

type natRound struct {
	started  time.Time
	readings map[string]int // serverIdentity -> external port, this round only
}

func recordNAT(ip string, port int) {
	natMu.Lock()
	defer natMu.Unlock()
	natMap[ip] = strconv.Itoa(port)
	var b strings.Builder
	for k, v := range natMap {
		b.WriteString(k + " " + v + "\n")
	}
	_ = os.WriteFile(natFile, []byte(b.String()), 0644)
}

// classifyNAT records (serverIdentity -> external srcPort) for the client's current
// probing round and, once that round has been observed via 2+ server identities, writes
// this round's cone|sym verdict for the IP to /data/nat_types.txt so the secure server's
// shouldRelay() can decide whether the P2P link needs the relay. See natSeen/natRound for
// why a round is only ever compared against itself, never a different round.
func classifyNAT(ip string, serverIdentity string, srcPort int) {
	natMu.Lock()
	defer natMu.Unlock()

	now := time.Now()
	round := natSeen[ip]
	if round == nil || now.Sub(round.started) > roundGap {
		round = &natRound{started: now, readings: map[string]int{}}
		natSeen[ip] = round
	}
	round.readings[serverIdentity] = srcPort

	if len(round.readings) < 2 {
		return
	}
	sym := false
	var first int
	got := false
	for _, sp := range round.readings {
		if !got {
			first, got = sp, true
		} else if sp != first {
			sym = true
		}
	}
	kind := "cone"
	if sym {
		kind = "sym"
	}
	natType[ip] = kind

	var b strings.Builder
	for cip, k := range natType {
		b.WriteString(cip + " " + k + "\n")
	}
	_ = os.WriteFile(typeFile, []byte(b.String()), 0644)
}

func ipToU32(ip net.IP) uint32 {
	if v4 := ip.To4(); v4 != nil {
		return binary.BigEndian.Uint32(v4)
	}
	return 0
}

// serveNCS answers NAT-check probes on the given UDP port, bound to a specific local IP so
// replies always carry that same IP as their source address (see package comment).
func serveNCS(bindIP net.IP, port int, serverIP uint32) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: bindIP, Port: port})
	if err != nil {
		log.Fatalf("[nncs] bind %s:%d failed: %v", bindIP, port, err)
	}
	log.Printf("[nncs] NAT-check responder listening on %s:%d (serverIP=%d)", bindIP, port, serverIP)
	buf := make([]byte, 128)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n < 16 {
			log.Printf("[nncs] %s:%d short %d-byte datagram from %s (ignored)", bindIP, port, n, src)
			continue
		}
		word0 := binary.BigEndian.Uint32(buf[0:4]) // type/test_id -> echoed unchanged
		srcIP := ipToU32(src.IP)
		resp := make([]byte, 16)
		binary.BigEndian.PutUint32(resp[0:4], word0)
		binary.BigEndian.PutUint32(resp[4:8], uint32(src.Port)) // observed external port
		binary.BigEndian.PutUint32(resp[8:12], srcIP)           // observed external IP
		binary.BigEndian.PutUint32(resp[12:16], serverIP)       // server IP
		if _, err := conn.WriteToUDP(resp, src); err != nil {
			log.Printf("[nncs] %s:%d reply to %s failed: %v", bindIP, port, src, err)
			continue
		}
		log.Printf("[nncs] %s:%d test=%d <- %s:%d  replied ext=%s:%d", bindIP, port, word0, src.IP, src.Port, src.IP, src.Port)
		recordNAT(src.IP.String(), src.Port)                    // bridge the external UDP endpoint to the NEX server
		classifyNAT(src.IP.String(), bindIP.String(), src.Port)   // cone vs symmetric (relay trigger)
	}
}

// sinkhole binds a port and drains datagrams without replying (the client only needs it
// reachable, and never gets a reply to validate a source address against, so the wildcard is
// fine here).
func sinkhole(port int) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		log.Printf("[nncs] sinkhole bind :%d failed: %v", port, err)
		return
	}
	log.Printf("[nncs] sinkhole listening on UDP :%d", port)
	buf := make([]byte, 512)
	for {
		if _, _, err := conn.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

func main() {
	serverIPStr := os.Getenv("NNCS_SERVER_IP")
	if serverIPStr == "" {
		serverIPStr = "127.0.0.1"
	}
	ip1 := net.ParseIP(serverIPStr)

	go serveNCS(ip1, 10025, ipToU32(ip1))
	go serveNCS(ip1, 10125, ipToU32(ip1))
	log.Printf("[nncs] mk8-nncs-local started, nncs1=%s", serverIPStr)

	if ip2Str := os.Getenv("NNCS_SERVER_IP2"); ip2Str != "" {
		ip2 := net.ParseIP(ip2Str)
		go serveNCS(ip2, 10025, ipToU32(ip2))
		go serveNCS(ip2, 10125, ipToU32(ip2))
		log.Printf("[nncs] nncs2=%s", ip2Str)
	} else {
		log.Printf("[nncs] NNCS_SERVER_IP2 not set — nncs2 identity not bound")
	}

	go sinkhole(33334)
	go sinkhole(33335)
	select {}
}
