package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func localSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestNativeProbeSourcePortAndObservedEndpoint(t *testing.T) {
	first, second, client := localSocket(t), localSocket(t), localSocket(t)
	serverIP := ipToU32(net.IPv4(198, 51, 100, 7))
	for _, pair := range [][2]*net.UDPConn{{first, second}, {second, first}} {
		for _, kind := range []uint32{101, 102, 103} {
			packet := make([]byte, 16)
			binary.BigEndian.PutUint32(packet, kind)
			// Client-supplied endpoint words must never replace observed source data.
			binary.BigEndian.PutUint32(packet[4:], 1234)
			binary.BigEndian.PutUint32(packet[8:], ipToU32(net.IPv4(203, 0, 113, 9)))
			receiver := pair[0].LocalAddr().(*net.UDPAddr)
			if _, err := client.WriteToUDP(packet, receiver); err != nil {
				t.Fatal(err)
			}
			pair[0].SetReadDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 128)
			n, observed, err := pair[0].ReadFromUDP(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if err = replyNCS(pair[0], pair[1], buffer[:n], observed, serverIP); err != nil {
				t.Fatal(err)
			}
			client.SetReadDeadline(time.Now().Add(time.Second))
			n, from, err := client.ReadFromUDP(buffer)
			if err != nil {
				t.Fatal(err)
			}
			want := receiver.Port
			if kind == 102 {
				want = pair[1].LocalAddr().(*net.UDPAddr).Port
			}
			if from.Port != want {
				t.Fatalf("test %d on %d replied from %d; want %d", kind, receiver.Port, from.Port, want)
			}
			if n != 16 || binary.BigEndian.Uint32(buffer) != kind || binary.BigEndian.Uint32(buffer[4:]) != uint32(observed.Port) || binary.BigEndian.Uint32(buffer[8:]) != ipToU32(observed.IP) || binary.BigEndian.Uint32(buffer[12:]) != serverIP {
				t.Fatal("observed endpoint or packet contract changed")
			}
			// An endpoint-dependent filter permits the solicited source only. The
			// filtering probe must actually challenge that rule, while 101/103 do not.
			acceptedByPortRestrictedFilter := from.IP.Equal(receiver.IP) && from.Port == receiver.Port
			if acceptedByPortRestrictedFilter == (kind == 102) {
				t.Fatalf("test %d did not exercise the intended filter", kind)
			}
			acceptedByOpenFilter := from.IP.Equal(receiver.IP)
			if !acceptedByOpenFilter {
				t.Fatal("alternate port unexpectedly changed address")
			}
		}
	}
}
