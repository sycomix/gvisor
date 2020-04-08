// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp_close_wait_ack_test

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func TestCloseWaitAck(t *testing.T) {
	windowOffset := seqnum.Size(2)
	for _, tt := range []struct {
		description    string
		makeTestingTCP func(conn *tb.TCPIPv4) tb.TCP
	}{
		{"should Ack to OTW Seq in CLOSE-WAIT", func(conn *tb.TCPIPv4) tb.TCP {
			windowSize := seqnum.Size(*conn.SynAck.WindowSize)
			otwSeq := uint32(conn.LocalSeqNum.Add(windowSize).Add(windowOffset))
			return tb.TCP{SeqNum: tb.Uint32(otwSeq), Flags: tb.Uint8(header.TCPFlagAck)}
		}},
		{"should Ack to unacceptable ACK in CLOSE-WAIT", func(conn *tb.TCPIPv4) tb.TCP {
			windowSize := seqnum.Size(*conn.SynAck.WindowSize)
			unaccAck := uint32(conn.RemoteSeqNum.Add(windowSize).Add(windowOffset))
			return tb.TCP{AckNum: tb.Uint32(unaccAck), Flags: tb.Uint8(header.TCPFlagAck)}
		}},
	} {
		t.Run(tt.description, func(t *testing.T) {
			dut := tb.NewDUT(t)
			defer dut.TearDown()
			listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(listenFd)
			conn := tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})
			defer conn.Close()

			conn.Handshake()
			acceptFd, _ := dut.Accept(listenFd)

			// Send a FIN to DUT to intiate the active close
			conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck | header.TCPFlagFin)})
			if _, err := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)}, time.Second); err != nil {
				t.Fatalf("expected an ACK for our fin and DUT should enter CLOSE_WAIT: %s", err)
			}

			// Send a segment with OTW Seq / unacc ACK and expect an ACK back
			conn.Send(tt.makeTestingTCP(&conn), &tb.Payload{Bytes: []byte("Sample Data")})
			if _, err := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)}, time.Second); err != nil {
				t.Fatalf("expected that the DUT %s: %s", tt.description, err)
			}

			// Now let's verify DUT is indeed in CLOSE_WAIT
			dut.Close(acceptFd)
			if _, err := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck | header.TCPFlagFin)}, time.Second); err != nil {
				t.Fatalf("expected DUT to send a FIN: %s", err)
			}
			// Ack the FIN from DUT
			conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})
			// Send some extra data to DUT
			conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)}, &tb.Payload{Bytes: []byte("Sample Data")})
			if _, err := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagRst)}, time.Second); err != nil {
				t.Fatalf("expected DUT to send an RST: %s", err)
			}
			conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck | header.TCPFlagRst)})
		})
	}
}
