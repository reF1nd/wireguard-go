/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestStdNetBindDisableGSO(t *testing.T) {
	v4Receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer v4Receiver.Close()

	v6Receiver, v6Err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if v6Err == nil {
		defer v6Receiver.Close()
	}

	const shardCount = 2
	wantShards := 1
	if reusePortFn != nil {
		wantShards = shardCount
	}
	for _, disabled := range []bool{false, true} {
		bind := NewStdNetBind(nil, WithSockets(shardCount)).(*StdNetBind)
		bind.SetDisableGSO(disabled)
		if bind.DisableGSO() != disabled {
			t.Fatalf("DisableGSO() = %v, want %v", bind.DisableGSO(), disabled)
		}
		// Close resets the sockets and offload state, so the policy must survive a reopen.
		for round := range 2 {
			_, _, err = bind.Open(0)
			if err != nil {
				t.Fatal(err)
			}
			if bind.DisableGSO() != disabled {
				t.Fatalf("round %d: DisableGSO() = %v, want %v", round, bind.DisableGSO(), disabled)
			}
			if len(bind.v4) != wantShards {
				t.Fatalf("round %d: len(bind.v4) = %d, want %d", round, len(bind.v4), wantShards)
			}
			if v6Err == nil && len(bind.v6) != wantShards {
				t.Fatalf("round %d: len(bind.v6) = %d, want %d", round, len(bind.v6), wantShards)
			}

			for familyName, sockets := range map[string][]*stdNetSocket{"v4": bind.v4, "v6": bind.v6} {
				for idx, sock := range sockets {
					probedTX, probedRX := supportsUDPOffload(sock.conn)
					gotTX := sock.txOffload.Load()
					if round == 0 && idx == 0 {
						t.Logf("disabled=%v family=%s shards=%d probedTX=%v probedRX=%v gotTX=%v gotRX=%v",
							disabled, familyName, len(sockets), probedTX, probedRX, gotTX, sock.rxOffload)
					}
					if gotTX != (probedTX && !disabled) || sock.rxOffload != probedRX {
						t.Fatalf("round %d %s[%d]: offload state lost: disabled=%v probed=(%v,%v) got=(%v,%v)",
							round, familyName, idx, disabled, probedTX, probedRX, gotTX, sock.rxOffload)
					}
				}
			}

			targets := []*net.UDPConn{v4Receiver}
			if v6Err == nil && len(bind.v6) > 0 {
				targets = append(targets, v6Receiver)
			}
			sizes := []int{100, 100, 50}
			recvBuf := make([]byte, 1500)
			for _, receiver := range targets {
				endpoint, err := bind.ParseEndpoint(receiver.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				for flow := range shardCount {
					bufs := make([][]byte, len(sizes))
					for i, size := range sizes {
						bufs[i] = bytes.Repeat([]byte{byte(0x10*(flow+1) + i + 1)}, size)
					}
					err = bind.SendTo(flow, bufs, endpoint, 0)
					if err != nil {
						t.Fatal(err)
					}
					for i, want := range bufs {
						receiver.SetReadDeadline(time.Now().Add(time.Second))
						n, _, err := receiver.ReadFromUDP(recvBuf)
						if err != nil {
							t.Fatal(err)
						}
						if n != len(want) || !bytes.Equal(recvBuf[:n], want) {
							t.Fatalf("round %d flow=%d pkt=%d: datagram mismatch: disabled=%v want len=%d got len=%d",
								round, flow, i, disabled, len(want), n)
						}
					}
				}
			}

			err = bind.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}
