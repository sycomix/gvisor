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

package icmpv6_param_problem_test

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func TestICMPv6ParamProblemTest(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	conn := tb.NewIPv6Conn(t, tb.IPv6{}, tb.IPv6{})
	defer conn.Close()
	conn.Send(
		tb.IPv6{
			NextHeader: tb.Uint8(254),
		},
		&tb.ICMPv6{
			Type:       tb.ICMPv6Type(0x80),
			NDPPayload: []byte("hello world"),
		})
	paramProblem := tb.Layers{
		&tb.Ether{},
		&tb.IPv6{},
		&tb.ICMPv6{
			Type: tb.ICMPv6Type(header.ICMPv6ParamProblem),
		},
	}
	timeout := time.Second
	if conn.ExpectFrame(paramProblem, timeout) == nil {
		t.Errorf("expected %v within %s but got none", paramProblem, timeout)
	}
}
