// mk8-nncs-local: a minimal Nintendo NAT-Check Server (NCS / "nncs") responder for MK8/Pia.
//
// The MK8 client (Pia NatDetectionJob) resolves nncs1-lp1.n.n.srv.nintendo.net and
// nncs2-lp1.n.n.srv.nintendo.net (redirected to this VPS by the console's custom DNS) and sends
// 16-byte UDP probes to ports 10025 and 10125. Each probe is 4x u32 BIG-ENDIAN:
//   [0]=type/test_id  [4]=ext_port(ignored)  [8]=ext_ip(ignored)  [12]=local_ip
// We must reply with 16 bytes, 4x u32 BIG-ENDIAN:
//   [0]=echo type unchanged  [4]=observed UDP source port  [8]=observed source IP  [12]=server IP
// The Switch only ever sends test ids 101/102/103; the classifier compares the external port it
// learns across tests. Ports 33334/33335 are reachability sinkholes (bind, never reply).
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

	// natSeen[ip][dstPort] = observed external source port. A symmetric (port-dependent
	// mapping) NAT hands out a DIFFERENT external port per destination, so if the same IP
	// shows different source ports across our two probe ports (10025 vs 10125) it is
	// symmetric — the case the direct natbridge cannot hole-punch, i.e. the relay trigger.
	natSeen  = map[string]map[int]int{}
	typeFile = func() string {
		if v := os.Getenv("NNCS_TYPE_FILE"); v != "" {
			return v
		}
		return "/data/nat_types.txt"
	}()
)

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

// classifyNAT records the (dstPort -> external srcPort) mapping for an IP and, once it
// has seen the client on both probe ports, writes cone|sym to /data/nat_types.txt so the
// secure server's shouldRelay() can decide whether the P2P link needs the relay.
func classifyNAT(ip string, dstPort, srcPort int) {
	natMu.Lock()
	defer natMu.Unlock()
	m := natSeen[ip]
	if m == nil {
		m = map[int]int{}
		natSeen[ip] = m
	}
	m[dstPort] = srcPort

	var b strings.Builder
	for cip, ports := range natSeen {
		sym := false
		var first int
		got := false
		for _, sp := range ports {
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
		b.WriteString(cip + " " + kind + "\n")
	}
	_ = os.WriteFile(typeFile, []byte(b.String()), 0644)
}

func ipToU32(ip net.IP) uint32 {
	if v4 := ip.To4(); v4 != nil {
		return binary.BigEndian.Uint32(v4)
	}
	return 0
}

// serveNCS answers NAT-check probes on the given UDP port.
func serveNCS(port int, serverIP uint32) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		log.Fatalf("[nncs] bind :%d failed: %v", port, err)
	}
	log.Printf("[nncs] NAT-check responder listening on UDP :%d (serverIP=%d)", port, serverIP)
	buf := make([]byte, 128)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n < 16 {
			log.Printf("[nncs] :%d short %d-byte datagram from %s (ignored)", port, n, src)
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
			log.Printf("[nncs] :%d reply to %s failed: %v", port, src, err)
			continue
		}
		log.Printf("[nncs] :%d test=%d <- %s:%d  replied ext=%s:%d", port, word0, src.IP, src.Port, src.IP, src.Port)
		recordNAT(src.IP.String(), src.Port)        // bridge the external UDP endpoint to the NEX server
		classifyNAT(src.IP.String(), port, src.Port) // cone vs symmetric (relay trigger)
	}
}

// sinkhole binds a port and drains datagrams without replying (the client only needs it reachable).
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
	serverIP := ipToU32(net.ParseIP(serverIPStr))

	go serveNCS(10025, serverIP)
	go serveNCS(10125, serverIP)
	go sinkhole(33334)
	go sinkhole(33335)
	log.Printf("[nncs] mk8-nncs-local started (serverIP=%s)", serverIPStr)
	select {}
}
