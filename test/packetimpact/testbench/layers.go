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

package testbench

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/imdario/mergo"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Layer is the interface that all encapsulations must implement.
//
// A Layer is an encapsulation in a packet, such as TCP, IPv4, IPv6, etc. A
// Layer contains all the fields of the encapsulation. Each field is a pointer
// and may be nil.
type Layer interface {
	fmt.Stringer

	// toBytes converts the Layer into bytes. In places where the Layer's field
	// isn't nil, the value that is pointed to is used. When the field is nil, a
	// reasonable default for the Layer is used. For example, "64" for IPv4 TTL
	// and a calculated checksum for TCP or IP. Some layers require information
	// from the previous or next layers in order to compute a default, such as
	// TCP's checksum or Ethernet's type, so each Layer has a doubly-linked list
	// to the layer's neighbors.
	toBytes() ([]byte, error)

	// match checks if the current Layer matches the provided Layer. If either
	// Layer has a nil in a given field, that field is considered matching.
	// Otherwise, the values pointed to by the fields must match. The LayerBase is
	// ignored.
	match(Layer) bool

	// length in bytes of the current encapsulation
	length() int

	// next gets a pointer to the encapsulated Layer.
	next() Layer

	// prev gets a pointer to the Layer encapsulating this one.
	prev() Layer

	// setNext sets the pointer to the encapsulated Layer.
	setNext(Layer)

	// setPrev sets the pointer to the Layer encapsulating this one.
	setPrev(Layer)
}

// LayerBase is the common elements of all layers.
type LayerBase struct {
	nextLayer Layer
	prevLayer Layer
}

func (lb *LayerBase) next() Layer {
	return lb.nextLayer
}

func (lb *LayerBase) prev() Layer {
	return lb.prevLayer
}

func (lb *LayerBase) setNext(l Layer) {
	lb.nextLayer = l
}

func (lb *LayerBase) setPrev(l Layer) {
	lb.prevLayer = l
}

// equalLayer compares that two Layer structs match while ignoring field in
// which either input has a nil and also ignoring the LayerBase of the inputs.
func equalLayer(x, y Layer) bool {
	// opt ignores comparison pairs where either of the inputs is a nil.
	opt := cmp.FilterValues(func(x, y interface{}) bool {
		for _, l := range []interface{}{x, y} {
			v := reflect.ValueOf(l)
			if (v.Kind() == reflect.Ptr || v.Kind() == reflect.Slice) && v.IsNil() {
				return true
			}
		}
		return false
	}, cmp.Ignore())
	return cmp.Equal(x, y, opt, cmpopts.IgnoreTypes(LayerBase{}))
}

func stringLayer(l Layer) string {
	v := reflect.ValueOf(l).Elem()
	t := v.Type()
	var ret []string
	for i := 0; i < v.NumField(); i++ {
		t := t.Field(i)
		if t.Anonymous {
			// Ignore the LayerBase in the Layer struct.
			continue
		}
		v := v.Field(i)
		if v.IsNil() {
			continue
		}
		ret = append(ret, fmt.Sprintf("%s:%v", t.Name, v))
	}
	return fmt.Sprintf("&%s{%s}", t, strings.Join(ret, " "))
}

// Ether can construct and match an ethernet encapsulation.
type Ether struct {
	LayerBase
	SrcAddr *tcpip.LinkAddress
	DstAddr *tcpip.LinkAddress
	Type    *tcpip.NetworkProtocolNumber
}

func (l *Ether) String() string {
	return stringLayer(l)
}

func (l *Ether) toBytes() ([]byte, error) {
	b := make([]byte, header.EthernetMinimumSize)
	h := header.Ethernet(b)
	fields := &header.EthernetFields{}
	if l.SrcAddr != nil {
		fields.SrcAddr = *l.SrcAddr
	}
	if l.DstAddr != nil {
		fields.DstAddr = *l.DstAddr
	}
	if l.Type != nil {
		fields.Type = *l.Type
	} else {
		switch n := l.next().(type) {
		case *IPv4:
			fields.Type = header.IPv4ProtocolNumber
		case *IPv6:
			fields.Type = header.IPv6ProtocolNumber
		default:
			// TODO(b/150301488): Support more protocols, like IPv6.
			return nil, fmt.Errorf("can't deduce the ethernet header's next protocol: %d", n)
		}
	}
	h.Encode(fields)
	return h, nil
}

// LinkAddress is a helper routine that allocates a new tcpip.LinkAddress value
// to store v and returns a pointer to it.
func LinkAddress(v tcpip.LinkAddress) *tcpip.LinkAddress {
	return &v
}

// NetworkProtocolNumber is a helper routine that allocates a new
// tcpip.NetworkProtocolNumber value to store v and returns a pointer to it.
func NetworkProtocolNumber(v tcpip.NetworkProtocolNumber) *tcpip.NetworkProtocolNumber {
	return &v
}

// ParseEther parses the bytes assuming that they start with an ethernet header
// and continues parsing further encapsulations.
func ParseEther(b []byte) (Layers, error) {
	h := header.Ethernet(b)
	ether := Ether{
		SrcAddr: LinkAddress(h.SourceAddress()),
		DstAddr: LinkAddress(h.DestinationAddress()),
		Type:    NetworkProtocolNumber(h.Type()),
	}
	layers := Layers{&ether}
	switch h.Type() {
	case header.IPv4ProtocolNumber:
		moreLayers, err := ParseIPv4(b[ether.length():])
		if err != nil {
			return nil, err
		}
		return append(layers, moreLayers...), nil
	case header.IPv6ProtocolNumber:
		moreLayers, err := ParseIPv6(b[ether.length():])
		if err != nil {
			return nil, err
		}
		return append(layers, moreLayers...), nil
	default:
		// TODO(b/150301488): Support more protocols, like IPv6.
		return nil, fmt.Errorf("can't deduce the ethernet header's next protocol: %#v", b)
	}
}

func (l *Ether) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *Ether) length() int {
	return header.EthernetMinimumSize
}

// IPv4 can construct and match an IPv4 encapsulation.
type IPv4 struct {
	LayerBase
	IHL            *uint8
	TOS            *uint8
	TotalLength    *uint16
	ID             *uint16
	Flags          *uint8
	FragmentOffset *uint16
	TTL            *uint8
	Protocol       *uint8
	Checksum       *uint16
	SrcAddr        *tcpip.Address
	DstAddr        *tcpip.Address
}

func (l *IPv4) String() string {
	return stringLayer(l)
}

func (l *IPv4) toBytes() ([]byte, error) {
	b := make([]byte, header.IPv4MinimumSize)
	h := header.IPv4(b)
	fields := &header.IPv4Fields{
		IHL:            20,
		TOS:            0,
		TotalLength:    0,
		ID:             0,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       0,
		Checksum:       0,
		SrcAddr:        tcpip.Address(""),
		DstAddr:        tcpip.Address(""),
	}
	if l.TOS != nil {
		fields.TOS = *l.TOS
	}
	if l.TotalLength != nil {
		fields.TotalLength = *l.TotalLength
	} else {
		fields.TotalLength = uint16(l.length())
		current := l.next()
		for current != nil {
			fields.TotalLength += uint16(current.length())
			current = current.next()
		}
	}
	if l.ID != nil {
		fields.ID = *l.ID
	}
	if l.Flags != nil {
		fields.Flags = *l.Flags
	}
	if l.FragmentOffset != nil {
		fields.FragmentOffset = *l.FragmentOffset
	}
	if l.TTL != nil {
		fields.TTL = *l.TTL
	}
	if l.Protocol != nil {
		fields.Protocol = *l.Protocol
	} else {
		switch n := l.next().(type) {
		case *TCP:
			fields.Protocol = uint8(header.TCPProtocolNumber)
		case *UDP:
			fields.Protocol = uint8(header.UDPProtocolNumber)
		default:
			// TODO(b/150301488): Support more protocols as needed.
			return nil, fmt.Errorf("can't deduce the ip header's next protocol: %#v", n)
		}
	}
	if l.SrcAddr != nil {
		fields.SrcAddr = *l.SrcAddr
	}
	if l.DstAddr != nil {
		fields.DstAddr = *l.DstAddr
	}
	if l.Checksum != nil {
		fields.Checksum = *l.Checksum
	}
	h.Encode(fields)
	if l.Checksum == nil {
		h.SetChecksum(^h.CalculateChecksum())
	}
	return h, nil
}

// Uint16 is a helper routine that allocates a new
// uint16 value to store v and returns a pointer to it.
func Uint16(v uint16) *uint16 {
	return &v
}

// Uint8 is a helper routine that allocates a new
// uint8 value to store v and returns a pointer to it.
func Uint8(v uint8) *uint8 {
	return &v
}

// Address is a helper routine that allocates a new tcpip.Address value to store
// v and returns a pointer to it.
func Address(v tcpip.Address) *tcpip.Address {
	return &v
}

// ParseIPv4 parses the bytes assuming that they start with an ipv4 header and
// continues parsing further encapsulations.
func ParseIPv4(b []byte) (Layers, error) {
	h := header.IPv4(b)
	tos, _ := h.TOS()
	ipv4 := IPv4{
		IHL:            Uint8(h.HeaderLength()),
		TOS:            &tos,
		TotalLength:    Uint16(h.TotalLength()),
		ID:             Uint16(h.ID()),
		Flags:          Uint8(h.Flags()),
		FragmentOffset: Uint16(h.FragmentOffset()),
		TTL:            Uint8(h.TTL()),
		Protocol:       Uint8(h.Protocol()),
		Checksum:       Uint16(h.Checksum()),
		SrcAddr:        Address(h.SourceAddress()),
		DstAddr:        Address(h.DestinationAddress()),
	}
	layers := Layers{&ipv4}
	switch h.TransportProtocol() {
	case header.TCPProtocolNumber:
		moreLayers, err := ParseTCP(b[ipv4.length():])
		if err != nil {
			return nil, err
		}
		return append(layers, moreLayers...), nil
	case header.UDPProtocolNumber:
		moreLayers, err := ParseUDP(b[ipv4.length():])
		if err != nil {
			return nil, err
		}
		return append(layers, moreLayers...), nil
	}
	return nil, fmt.Errorf("can't deduce the IPv4 header's next protocol: %v", h.TransportProtocol())
}

func (l *IPv4) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *IPv4) length() int {
	if l.IHL == nil {
		return header.IPv4MinimumSize
	}
	return int(*l.IHL)
}

// IPv6 can construct and match an IPv6 encapsulation.
type IPv6 struct {
	LayerBase
	TrafficClass  *uint8
	FlowLabel     *uint32
	PayloadLength *uint16
	NextHeader    *uint8
	HopLimit      *uint8
	SrcAddr       *tcpip.Address
	DstAddr       *tcpip.Address
}

func (l *IPv6) String() string {
	return stringLayer(l)
}

func (l *IPv6) toBytes() ([]byte, error) {
	b := make([]byte, header.IPv6MinimumSize)
	h := header.IPv6(b)
	fields := &header.IPv6Fields{
		TrafficClass:  0,
		FlowLabel:     0,
		PayloadLength: 0,
		NextHeader:    0,
		HopLimit:      64,
		SrcAddr:       tcpip.Address(""),
		DstAddr:       tcpip.Address(""),
	}
	if l.TrafficClass != nil {
		fields.TrafficClass = *l.TrafficClass
	}
	if l.FlowLabel != nil {
		fields.FlowLabel = *l.FlowLabel
	}
	if l.PayloadLength != nil {
		fields.PayloadLength = *l.PayloadLength
	} else {
		for current := l.next(); current != nil; current = current.next() {
			fields.PayloadLength += uint16(current.length())
		}
	}
	if l.NextHeader != nil {
		fields.NextHeader = *l.NextHeader
	} else {
		switch n := l.next().(type) {
		case *TCP:
			fields.NextHeader = uint8(header.TCPProtocolNumber)
		case *UDP:
			fields.NextHeader = uint8(header.UDPProtocolNumber)
		case *ICMPv6:
			fields.NextHeader = uint8(header.ICMPv6ProtocolNumber)
		default:
			// TODO(b/150301488): Support more protocols as needed.
			return nil, fmt.Errorf("toBytes can't deduce the IPv6 header's next protocol: %#v", n)
		}
	}
	if l.HopLimit != nil {
		fields.HopLimit = *l.HopLimit
	}
	if l.SrcAddr != nil {
		fields.SrcAddr = *l.SrcAddr
	}
	if l.DstAddr != nil {
		fields.DstAddr = *l.DstAddr
	}
	h.Encode(fields)
	return h, nil
}

// ParseIPv6 parses the bytes assuming that they start with an ipv6 header and
// continues parsing further encapsulations.
func ParseIPv6(b []byte) (Layers, error) {
	h := header.IPv6(b)
	tos, flowLabel := h.TOS()
	ipv6 := IPv6{
		TrafficClass:  &tos,
		FlowLabel:     &flowLabel,
		PayloadLength: Uint16(h.PayloadLength()),
		NextHeader:    Uint8(h.NextHeader()),
		HopLimit:      Uint8(h.HopLimit()),
		SrcAddr:       Address(h.SourceAddress()),
		DstAddr:       Address(h.DestinationAddress()),
	}
	layers := Layers{&ipv6}
	switch h.TransportProtocol() {
	case header.TCPProtocolNumber:
		moreLayers, err := ParseTCP(b[ipv6.length():])
		if err != nil {
			return nil, err
		}
		return append(layers, moreLayers...), nil
	case header.UDPProtocolNumber:
		moreLayers, err := ParseUDP(b[ipv6.length():])
		if err != nil {
			return nil, err
		}
		return append(layers, moreLayers...), nil
	case header.ICMPv6ProtocolNumber:
		moreLayers, err := ParseICMPv6(b[ipv6.length():])
		if err != nil {
			return nil, err
		}
		return append(layers, moreLayers...), nil
	}
	return nil, fmt.Errorf("parser can't deduce the IPv6 header's next protocol: %v", h.TransportProtocol())
}

func (l *IPv6) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *IPv6) length() int {
	return header.IPv6MinimumSize
}

// merge overrides the values in l with the values from other but only in fields
// where the value is not nil.
func (l *IPv6) merge(other IPv6) error {
	return mergo.Merge(l, other, mergo.WithOverride)
}

// ICMPv6 can construct and match an ICMPv6 encapsulation.
type ICMPv6 struct {
	LayerBase
	Type       *header.ICMPv6Type
	Code       *byte
	Checksum   *uint16
	NDPPayload []byte
}

func (l *ICMPv6) String() string {
	// TODO(eyalsoha): Do something smarter here when *l.Type is ParameterProblem?
	// We could parse the contents of the Payload as if it were an IPv6 packet.
	return stringLayer(l)
}

func (l *ICMPv6) toBytes() ([]byte, error) {
	b := make([]byte, header.ICMPv6HeaderSize+len(l.NDPPayload))
	h := header.ICMPv6(b)
	if l.Type != nil {
		h.SetType(*l.Type)
	}
	if l.Code != nil {
		h.SetCode(*l.Code)
	}
	if l.NDPPayload != nil {
		copy(h.NDPPayload(), l.NDPPayload)
	}
	if l.Checksum != nil {
		h.SetChecksum(*l.Checksum)
		return h, nil
	}
	h.SetChecksum(header.ICMPv6Checksum(h, *l.prev().(*IPv6).SrcAddr, *l.prev().(*IPv6).DstAddr, buffer.VectorisedView{}))
	return h, nil
}

// ICMPv6Type is a helper routine that allocates a new ICMPv6Type value to store
// v and returns a pointer to it.
func ICMPv6Type(v header.ICMPv6Type) *header.ICMPv6Type {
	return &v
}

// Byte is a helper routine that allocates a new byte value to store
// v and returns a pointer to it.
func Byte(v byte) *byte {
	return &v
}

// ParseICMPv6 parses the bytes assuming that they start with an ICMPv6 header.
func ParseICMPv6(b []byte) (Layers, error) {
	h := header.ICMPv6(b)
	icmpv6 := ICMPv6{
		Type:       ICMPv6Type(h.Type()),
		Code:       Byte(h.Code()),
		Checksum:   Uint16(h.Checksum()),
		NDPPayload: h.NDPPayload(),
	}
	return Layers{&icmpv6}, nil
}

func (l *ICMPv6) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *ICMPv6) length() int {
	return header.ICMPv6HeaderSize + len(l.NDPPayload)
}

// TCP can construct and match a TCP encapsulation.
type TCP struct {
	LayerBase
	SrcPort       *uint16
	DstPort       *uint16
	SeqNum        *uint32
	AckNum        *uint32
	DataOffset    *uint8
	Flags         *uint8
	WindowSize    *uint16
	Checksum      *uint16
	UrgentPointer *uint16
}

func (l *TCP) String() string {
	return stringLayer(l)
}

func (l *TCP) toBytes() ([]byte, error) {
	b := make([]byte, header.TCPMinimumSize)
	h := header.TCP(b)
	if l.SrcPort != nil {
		h.SetSourcePort(*l.SrcPort)
	}
	if l.DstPort != nil {
		h.SetDestinationPort(*l.DstPort)
	}
	if l.SeqNum != nil {
		h.SetSequenceNumber(*l.SeqNum)
	}
	if l.AckNum != nil {
		h.SetAckNumber(*l.AckNum)
	}
	if l.DataOffset != nil {
		h.SetDataOffset(*l.DataOffset)
	} else {
		h.SetDataOffset(uint8(l.length()))
	}
	if l.Flags != nil {
		h.SetFlags(*l.Flags)
	}
	if l.WindowSize != nil {
		h.SetWindowSize(*l.WindowSize)
	} else {
		h.SetWindowSize(32768)
	}
	if l.UrgentPointer != nil {
		h.SetUrgentPoiner(*l.UrgentPointer)
	}
	if l.Checksum != nil {
		h.SetChecksum(*l.Checksum)
		return h, nil
	}
	if err := setTCPChecksum(&h, l); err != nil {
		return nil, err
	}
	return h, nil
}

// totalLength returns the length of the provided layer and all following
// layers.
func totalLength(l Layer) int {
	var totalLength int
	for ; l != nil; l = l.next() {
		totalLength += l.length()
	}
	return totalLength
}

// layerChecksum calculates the checksum of the Layer header, including the
// peusdeochecksum of the layer before it and all the bytes after it..
func layerChecksum(l Layer, protoNumber tcpip.TransportProtocolNumber) (uint16, error) {
	totalLength := uint16(totalLength(l))
	var xsum uint16
	switch s := l.prev().(type) {
	case *IPv4:
		xsum = header.PseudoHeaderChecksum(protoNumber, *s.SrcAddr, *s.DstAddr, totalLength)
	default:
		// TODO(b/150301488): Support more protocols, like IPv6.
		return 0, fmt.Errorf("can't get src and dst addr from previous layer: %#v", s)
	}
	var payloadBytes buffer.VectorisedView
	for current := l.next(); current != nil; current = current.next() {
		payload, err := current.toBytes()
		if err != nil {
			return 0, fmt.Errorf("can't get bytes for next header: %s", payload)
		}
		payloadBytes.AppendView(payload)
	}
	xsum = header.ChecksumVV(payloadBytes, xsum)
	return xsum, nil
}

// setTCPChecksum calculates the checksum of the TCP header and sets it in h.
func setTCPChecksum(h *header.TCP, tcp *TCP) error {
	h.SetChecksum(0)
	xsum, err := layerChecksum(tcp, header.TCPProtocolNumber)
	if err != nil {
		return err
	}
	h.SetChecksum(^h.CalculateChecksum(xsum))
	return nil
}

// Uint32 is a helper routine that allocates a new
// uint32 value to store v and returns a pointer to it.
func Uint32(v uint32) *uint32 {
	return &v
}

// ParseTCP parses the bytes assuming that they start with a tcp header and
// continues parsing further encapsulations.
func ParseTCP(b []byte) (Layers, error) {
	h := header.TCP(b)
	tcp := TCP{
		SrcPort:       Uint16(h.SourcePort()),
		DstPort:       Uint16(h.DestinationPort()),
		SeqNum:        Uint32(h.SequenceNumber()),
		AckNum:        Uint32(h.AckNumber()),
		DataOffset:    Uint8(h.DataOffset()),
		Flags:         Uint8(h.Flags()),
		WindowSize:    Uint16(h.WindowSize()),
		Checksum:      Uint16(h.Checksum()),
		UrgentPointer: Uint16(h.UrgentPointer()),
	}
	layers := Layers{&tcp}
	moreLayers, err := ParsePayload(b[tcp.length():])
	if err != nil {
		return nil, err
	}
	return append(layers, moreLayers...), nil
}

func (l *TCP) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *TCP) length() int {
	if l.DataOffset == nil {
		return header.TCPMinimumSize
	}
	return int(*l.DataOffset)
}

// merge overrides the values in l with the values from other but only in fields
// where the value is not nil.
func (l *TCP) merge(other TCP) error {
	return mergo.Merge(l, other, mergo.WithOverride)
}

// UDP can construct and match a UDP encapsulation.
type UDP struct {
	LayerBase
	SrcPort  *uint16
	DstPort  *uint16
	Length   *uint16
	Checksum *uint16
}

func (l *UDP) String() string {
	return stringLayer(l)
}

func (l *UDP) toBytes() ([]byte, error) {
	b := make([]byte, header.UDPMinimumSize)
	h := header.UDP(b)
	if l.SrcPort != nil {
		h.SetSourcePort(*l.SrcPort)
	}
	if l.DstPort != nil {
		h.SetDestinationPort(*l.DstPort)
	}
	if l.Length != nil {
		h.SetLength(*l.Length)
	} else {
		h.SetLength(uint16(totalLength(l)))
	}
	if l.Checksum != nil {
		h.SetChecksum(*l.Checksum)
		return h, nil
	}
	if err := setUDPChecksum(&h, l); err != nil {
		return nil, err
	}
	return h, nil
}

// setUDPChecksum calculates the checksum of the UDP header and sets it in h.
func setUDPChecksum(h *header.UDP, udp *UDP) error {
	h.SetChecksum(0)
	xsum, err := layerChecksum(udp, header.UDPProtocolNumber)
	if err != nil {
		return err
	}
	h.SetChecksum(^h.CalculateChecksum(xsum))
	return nil
}

// ParseUDP parses the bytes assuming that they start with a udp header and
// continues parsing further encapsulations.
func ParseUDP(b []byte) (Layers, error) {
	h := header.UDP(b)
	udp := UDP{
		SrcPort:  Uint16(h.SourcePort()),
		DstPort:  Uint16(h.DestinationPort()),
		Length:   Uint16(h.Length()),
		Checksum: Uint16(h.Checksum()),
	}
	layers := Layers{&udp}
	moreLayers, err := ParsePayload(b[udp.length():])
	if err != nil {
		return nil, err
	}
	return append(layers, moreLayers...), nil
}

func (l *UDP) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *UDP) length() int {
	if l.Length == nil {
		return header.UDPMinimumSize
	}
	return int(*l.Length)
}

// merge overrides the values in l with the values from other but only in fields
// where the value is not nil.
func (l *UDP) merge(other UDP) error {
	return mergo.Merge(l, other, mergo.WithOverride)
}

// Payload has bytes beyond OSI layer 4.
type Payload struct {
	LayerBase
	Bytes []byte
}

func (l *Payload) String() string {
	return stringLayer(l)
}

// ParsePayload parses the bytes assuming that they start with a payload and
// continue to the end. There can be no further encapsulations.
func ParsePayload(b []byte) (Layers, error) {
	payload := Payload{
		Bytes: b,
	}
	return Layers{&payload}, nil
}

func (l *Payload) toBytes() ([]byte, error) {
	return l.Bytes, nil
}

func (l *Payload) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *Payload) length() int {
	return len(l.Bytes)
}

// Layers is an array of Layer and supports similar functions to Layer.
type Layers []Layer

func (ls *Layers) toBytes() ([]byte, error) {
	for i, l := range *ls {
		if i > 0 {
			l.setPrev((*ls)[i-1])
		}
		if i+1 < len(*ls) {
			l.setNext((*ls)[i+1])
		}
	}
	outBytes := []byte{}
	for _, l := range *ls {
		layerBytes, err := l.toBytes()
		if err != nil {
			return nil, err
		}
		outBytes = append(outBytes, layerBytes...)
	}
	return outBytes, nil
}

func (ls *Layers) match(other Layers) bool {
	if len(*ls) > len(other) {
		return false
	}
	for i := 0; i < len(*ls); i++ {
		if !equalLayer((*ls)[i], other[i]) {
			return false
		}
	}
	return true
}
