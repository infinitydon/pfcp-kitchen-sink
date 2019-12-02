// Package pfcp implements subset of PFCP protocol
// as defined on 3GPP TS 29.244
package pfcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

//go:generate enumer -type=ApplyAction  -yaml
//go:generate enumer -type=Interface -yaml
//go:generate enumer -type=OuterHeaderCreationMask -yaml
//go:generate enumer -type=OuterHeaderRemoval -yaml
//go:generate enumer -type=MessageType -yaml

const (
	MaxSize       = 1024
	PFCP_VERSION  = 1
	PFCP_UDP_PORT = 8805
)

type IEType uint16

// IE types
const (
	NodeIDIEType               IEType = 60
	RecoveryTimestampIEType    IEType = 96
	CauseIEType                IEType = 19
	FSEIDIETYPE                IEType = 57
	CreatePDRIEType            IEType = 1
	PDRIDIEType                IEType = 56
	PrecedenceIEType           IEType = 29
	PDIIEType                  IEType = 2
	OuterHeaderRemovelIEType   IEType = 95
	FARIDIEType                IEType = 108
	SourceInterfaceIEType      IEType = 20
	FTEIDIEType                IEType = 21
	ApplicationIDIEType        IEType = 24
	NetworkInstanceIEType      IEType = 22
	SDFFilterIEType            IEType = 23
	UEIPAddressIEType          IEType = 93
	CreateFARIEType            IEType = 3
	ApplyActionIEType          IEType = 44
	ForwardingParametersIEType IEType = 4
	DestinationInterfaceIEType IEType = 42
	ForwardingPolicyIEType     IEType = 41
	RedirectInformationIEType  IEType = 38
	OuterHeaderCreationIEType  IEType = 84
)

type MessageType uint8

//Message types
const (
	HeartbeatRequest           MessageType = 1
	HeartbeatResponse          MessageType = 2
	AssociationSetupRequest    MessageType = 5
	AssociationSetupResponse   MessageType = 6
	SessionEtablismentRequest  MessageType = 50
	SessionEtablismentResponse MessageType = 51
)

func newTLVBuffer(tag IEType, length uint16) (b []byte, n int) {
	b = make([]byte, MaxSize)
	binary.BigEndian.PutUint16(b, uint16(tag))
	binary.BigEndian.PutUint16(b[2:], length)
	return b, 4
}

func setTLVLength(b []byte, n int) {
	binary.BigEndian.PutUint16(b[2:], uint16(n-4))
}

func newTLVUint8(tag IEType, v uint8) []byte {
	b := make([]byte, 5)
	binary.BigEndian.PutUint16(b, uint16(tag))
	binary.BigEndian.PutUint16(b[2:], 1)
	b[4] = v
	return b
}
func newTLVUint16(tag IEType, v uint16) []byte {
	b := make([]byte, 6)
	binary.BigEndian.PutUint16(b, uint16(tag))
	binary.BigEndian.PutUint16(b[2:], 2)
	binary.BigEndian.PutUint16(b[4:], v)
	return b
}

func newTLVUint32(tag IEType, v uint32) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b, uint16(tag))
	binary.BigEndian.PutUint16(b[2:], 4)
	binary.BigEndian.PutUint32(b[4:], v)
	return b
}

func newTLVString(tag IEType, s string) []byte {
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint16(b, uint16(tag))
	binary.BigEndian.PutUint16(b[2:], uint16(len(s)))
	copy(b[4:], s)
	return b
}

func encodeDNSName(name []byte, data []byte, offset int) int {
	l := 0
	for i := range name {
		if name[i] == '.' {
			data[offset+i-l] = byte(l)
			l = 0
		} else {
			// skip one to write the length
			data[offset+i+1] = name[i]
			l++
		}
	}

	if len(name) == 0 {
		data[offset] = 0x00 // terminal
		return 1
	}

	// length for final portion
	data[offset+len(name)-l] = byte(l)
	data[offset+len(name)+1] = 0x00 // terminal
	return len(name) + 1
}
func newTLVDNSName(tag IEType, s string) []byte {
	b := make([]byte, MaxSize)
	binary.BigEndian.PutUint16(b, uint16(tag))
	n := encodeDNSName([]byte(s), b, 4)
	binary.BigEndian.PutUint16(b[2:], uint16(n))
	return b[:n+4]
}

type PFCPInformationElement interface {
	String() string
	Marshal() []byte
	UnMarshal(in []byte)
}

type NodeID struct {
	ipAddr net.IP
	fqdn   string
}

func NewNodeID(ipAddr string) *NodeID {
	var n = NodeID{}
	n.ipAddr = net.ParseIP(ipAddr).To4()
	return &n
}

func (node *NodeID) String() string {
	return fmt.Sprintf("NodeID[%s]", node.ipAddr)
}

func (node *NodeID) Marshal() []byte {
	b, n := newTLVBuffer(NodeIDIEType, 5)
	b[n] = 0 //XX IPv4 address
	n++
	n += copy(b[n:], node.ipAddr)
	return b[:n]
}

func (node *NodeID) UnMarshal(b []byte) {
}

const (
	FSEID_V6 = 1 << 0
	FSEID_V4 = 1 << 1
)

type FSEID struct {
	ip4  net.IP
	ip6  net.IP
	seid uint64
}

func NewFSEID(ip string, seid uint64) *FSEID {
	return &FSEID{ip4: net.ParseIP(ip).To4(), seid: seid}
}

func (f *FSEID) String() string {
	return fmt.Sprintf("FSEID[seid=%d,ip=%s]", f.seid, f.ip4)
}

func (f *FSEID) Marshal() []byte {
	b, n := newTLVBuffer(FSEIDIETYPE, 0)
	if f.ip4 != nil {
		b[n] |= FSEID_V4
	}
	if f.ip6 != nil {
		b[n] |= FSEID_V6
	}
	n++
	binary.BigEndian.PutUint64(b[n:], f.seid)
	n += 8
	if f.ip4 != nil {
		n += copy(b[n:], f.ip4)
	}
	if f.ip6 != nil {
		n += copy(b[n:], f.ip6)
	}
	setTLVLength(b, n)
	return b[:n]
}

func (f *FSEID) UnMarshal(b []byte) {
}

type RecoveryTimestamp struct {
	timestamp time.Time
}

func NewRecoveryTimestamp(t time.Time) *RecoveryTimestamp {
	var rt = RecoveryTimestamp{timestamp: t}
	return &rt
}

func (r *RecoveryTimestamp) String() string {
	return fmt.Sprintf("RecoveryTimestamp[%s]", r.timestamp)
}

func (r *RecoveryTimestamp) Marshal() []byte {
	b, n := newTLVBuffer(RecoveryTimestampIEType, 4)
	binary.BigEndian.PutUint32(b[n:], uint32(r.timestamp.Unix()))
	n += 4
	return b[:n]
}

func (r *RecoveryTimestamp) UnMarshal(b []byte) {
}

type Cause uint8

// cause values
const (
	RequestAccepted                    Cause = 1
	RequestRejected                    Cause = 64
	SessionContextNotFound             Cause = 65
	MandatoryIEMissing                 Cause = 66
	ConditionalIEMissing               Cause = 67
	InvalidLength                      Cause = 68
	MandatoryIEIncorrect               Cause = 69
	InvalidForwardPolicy               Cause = 70
	InvalidFTEIDAllocationOption       Cause = 71
	NoEstablishedPFCPAssociation       Cause = 72
	RuleCreationOrModififcationFailure Cause = 73
	PFCPEntityInCongestion             Cause = 74
	NoResourcesAvailable               Cause = 75
	ServiceNotSupported                Cause = 76
	SystemFailure                      Cause = 77
	RedirectionRequested               Cause = 78
)

func (c Cause) String() string {
	switch c {
	case RequestAccepted:
		return "Request accepted"
	case RequestRejected:
		return "Request rejected"
	case SessionContextNotFound:
		return "Session context not found"
	case MandatoryIEMissing:
		return "Mandatory IE missing"
	case ConditionalIEMissing:
		return "Conditional IE missing"
	case InvalidLength:
		return "Invalid length"
	case MandatoryIEIncorrect:
		return "Mandatory IE incorrect"
	case InvalidForwardPolicy:
		return "Invalid forward policy"
	case InvalidFTEIDAllocationOption:
		return "Invalid F-TEID allocation option"
	case NoEstablishedPFCPAssociation:
		return "No established PFCP association"
	case RuleCreationOrModififcationFailure:
		return "Rule creation/modififcation failure"
	case PFCPEntityInCongestion:
		return "PFCP entity in congestion"
	case NoResourcesAvailable:
		return "No resources available"
	case ServiceNotSupported:
		return "Service not supported"
	case SystemFailure:
		return "System failure"
	case RedirectionRequested:
		return "Redirection requested"
	default:
		return "Unknown cause value"
	}
}

//CauseIE information element
type CauseIE struct {
	value Cause
}

func (c *CauseIE) String() string {
	return c.value.String()
}

func (c *CauseIE) Marshal() []byte {
	return nil
}

func (c *CauseIE) UnMarshal(b []byte) {
	c.value = Cause(b[0])
}

type OuterHeaderRemoval uint8

const (
	OUTER_HEADER_GTPU_UDP_IPV4 OuterHeaderRemoval = iota
	OUTER_HEADER_GTPU_UDP_IPV6
	OUTER_HEADER_UDP_IPV4
	OUTER_HEADER_UDP_IPV46
)

type CreatePdr struct {
	PdrID              uint16              `yaml:"pdrID"`
	Precedence         uint32              `yaml:"precedence"`
	Pdi                *PDI                `yaml:"pdi"`
	OuterHeaderRemoval *OuterHeaderRemoval `yaml:"outerHeaderRemoval,omitempty"`
	FarID              *uint32             `yaml:"farID"`
}

func NewCreatePdr(pdrID uint16, precedence uint32, pdi *PDI) *CreatePdr {
	return &CreatePdr{PdrID: pdrID, Precedence: precedence, Pdi: pdi}
}

func (c *CreatePdr) String() string {
	return "CreatePDR[]"
}

func (c *CreatePdr) SetOuterHeaderRemoval(f OuterHeaderRemoval) {
	c.OuterHeaderRemoval = &f
}

func (c *CreatePdr) SetFARID(id uint32) {
	c.FarID = &id
}

func (c *CreatePdr) Marshal() []byte {
	b, n := newTLVBuffer(CreatePDRIEType, 0)
	n += copy(b[n:], newTLVUint16(PDRIDIEType, c.PdrID))
	n += copy(b[n:], newTLVUint32(PrecedenceIEType, c.Precedence))
	n += copy(b[n:], c.Pdi.Marshal())
	if c.OuterHeaderRemoval != nil {
		n += copy(b[n:], newTLVUint8(OuterHeaderRemovelIEType, uint8(*c.OuterHeaderRemoval)))
	}
	if c.FarID != nil {
		n += copy(b[n:], newTLVUint32(FARIDIEType, *c.FarID))
	}
	setTLVLength(b, n)
	return b[:n]
}

func (c *CreatePdr) UnMarshal(b []byte) {
}

type PDI struct {
	SourceInterface Interface    `yaml:"sourceInterface"`
	LocalFTEID      *FTEID       `yaml:"localFTEID,omitempty"`
	NetworkInstance string       `yaml:"networkInstance,omitempty"`
	UeIPAddress     *UEIPAddress `yaml:"ueIPAddress,omitempty"`
	SdfFilter       *SDFFilter   `yaml:"sdfFilter,omitempty"`
	ApplicationID   string       `yaml:"applicationID,omitempty"`
}

func NewPDI(sourceInterface Interface) *PDI {
	return &PDI{SourceInterface: sourceInterface}
}

func (pdi *PDI) SetLocalFTEID(fteid *FTEID) {
	pdi.LocalFTEID = fteid
}

func (pdi *PDI) SetNetworkInstance(networkInstance string) {
	pdi.NetworkInstance = networkInstance
}

func (pdi *PDI) SetUeIPAddress(addr *UEIPAddress) {
	pdi.UeIPAddress = addr
}

func (pdi *PDI) SetSDFFilter(filter *SDFFilter) {
	pdi.SdfFilter = filter
}

func (pdi *PDI) SetApplicationID(appID string) {
	pdi.ApplicationID = appID
}

func (pdi *PDI) Marshal() []byte {
	b, n := newTLVBuffer(PDIIEType, 0)
	n += copy(b[n:], newTLVUint8(SourceInterfaceIEType, uint8(pdi.SourceInterface)))
	if pdi.LocalFTEID != nil {
		n += copy(b[n:], pdi.LocalFTEID.Marshal())
	}
	if pdi.NetworkInstance != "" {
		n += copy(b[n:], newTLVDNSName(NetworkInstanceIEType, pdi.NetworkInstance))
	}
	if pdi.UeIPAddress != nil {
		n += copy(b[n:], pdi.UeIPAddress.Marshal())
	}
	if pdi.SdfFilter != nil {
		n += copy(b[n:], pdi.SdfFilter.Marshal())
	}
	if pdi.ApplicationID != "" {
		n += copy(b[n:], newTLVString(ApplicationIDIEType, pdi.ApplicationID))
	}
	setTLVLength(b, n)
	return b[:n]
}

const (
	FTEID_IPV4 = 1 << 0
	FTEID_IPV6 = 1 << 1
	FTEID_CH   = 1 << 2
	FTEID_CHID = 1 << 3
)

type FTEID struct {
	flags    uint8
	Teid     uint32 `yaml:"teid"`
	Ip4      net.IP `yaml:"ip4"`
	ip6      net.IP
	chooseID uint8
}

func NewFTEID(ip4 net.IP, teid uint32) *FTEID {
	r := new(FTEID)
	r.Teid = teid
	r.Ip4 = ip4
	r.flags = FTEID_IPV4
	return r
}

func (f *FTEID) Marshal() []byte {
	b, n := newTLVBuffer(FTEIDIEType, 0)
	if f.flags == 0 && f.Ip4 != nil {
		f.flags = FTEID_IPV4
	}
	b[n] = f.flags
	n++
	binary.BigEndian.PutUint32(b[n:], f.Teid)
	n += 4
	if f.Ip4 != nil {
		n += copy(b[n:], f.Ip4.To4())
	}
	if f.ip6 != nil {
		n += copy(b[n:], f.ip6.To16())
	}
	if f.flags&FTEID_CHID != 0 {
		b[n] = f.chooseID
		n++
	}
	setTLVLength(b, n)
	return b[:n]
}

const (
	UE_IP_ADDRESS_V6             = 1 << 0
	UE_IP_ADDRESS_V4             = 1 << 1
	UE_IP_ADDRESS_IS_DESTINATION = 1 << 2
)

type UEIPAddress struct {
	IsDestination bool   `yaml:"isDestination"`
	Ip4           net.IP `yaml:",omitempty"`
	Ip6           net.IP `yaml:",omitempty"`
}

func NewUEIPAddress(ip4 net.IP, isDestination bool) *UEIPAddress {
	r := new(UEIPAddress)
	r.Ip4 = ip4
	r.IsDestination = isDestination
	return r
}

func (ueAddr *UEIPAddress) Marshal() []byte {
	b, n := newTLVBuffer(UEIPAddressIEType, 0)
	var flags uint8
	if ueAddr.IsDestination {
		flags |= UE_IP_ADDRESS_IS_DESTINATION
	}
	if ueAddr.Ip4 != nil {
		flags |= UE_IP_ADDRESS_V4
	}
	if ueAddr.Ip6 != nil {
		flags |= UE_IP_ADDRESS_V6
	}
	b[n] = flags
	n++
	if ueAddr.Ip4 != nil {
		n += copy(b[n:], ueAddr.Ip4.To4())
	}
	if ueAddr.Ip6 != nil {
		n += copy(b[n:], ueAddr.Ip6.To16())
	}
	setTLVLength(b, n)
	return b[:n]
}

const (
	SDF_FILTER_FD = 1 << 0
)

type SDFFilter struct {
	flags           uint8
	FlowDescription string `yaml:"flowDescription"`
}

func NewSDFFilter(flowDescription string) *SDFFilter {
	return &SDFFilter{flags: SDF_FILTER_FD, FlowDescription: flowDescription}
}

func (sdfFilter *SDFFilter) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var filter struct {
		FlowDescription string `yaml:"flowDescription"`
	}
	if err := unmarshal(&filter); err != nil {
		return err
	}
	sdfFilter.flags = SDF_FILTER_FD
	sdfFilter.FlowDescription = filter.FlowDescription
	return nil
}

func (sdfFilter *SDFFilter) Marshal() []byte {
	b, n := newTLVBuffer(SDFFilterIEType, 0)
	b[n] = sdfFilter.flags
	n += 2
	if sdfFilter.flags&SDF_FILTER_FD != 0 {
		binary.BigEndian.PutUint16(b[n:], uint16(len(sdfFilter.FlowDescription)))
		n += 2
		n += copy(b[n:], sdfFilter.FlowDescription)
	}
	setTLVLength(b, n)
	return b[:n]
}

// ApplyAction IE
type ApplyAction uint8

// actions the UP is required to apply to packets
const (
	Drop      ApplyAction = 1 << iota
	Forward   ApplyAction = 1 << iota
	Buffer    ApplyAction = 1 << iota
	NotifyCP  ApplyAction = 1 << iota
	Duplicate ApplyAction = 1 << iota
)

// CreateFAR IE
type CreateFAR struct {
	FarID                uint32                `yaml:"farID"`
	ApplyAction          ApplyAction           `yaml:"applyAction"`
	ForwardingParameters *ForwardingParameters `yaml:"forwardingParameters,omitempty"`
}

func NewCreateFar(id uint32, applyAction ApplyAction) *CreateFAR {
	r := &CreateFAR{FarID: id, ApplyAction: applyAction}
	return r
}
func (far *CreateFAR) String() string {
	return "CreateFar[]"
}

func (far *CreateFAR) SetForwardingParameters(params *ForwardingParameters) {
	far.ForwardingParameters = params
}

func (far *CreateFAR) Marshal() []byte {
	b, n := newTLVBuffer(CreateFARIEType, 0)
	n += copy(b[n:], newTLVUint32(FARIDIEType, far.FarID))
	n += copy(b[n:], newTLVUint8(ApplyActionIEType, uint8(far.ApplyAction)))
	if far.ForwardingParameters != nil {
		n += copy(b[n:], far.ForwardingParameters.Marshal())
	}
	setTLVLength(b, n)
	return b[:n]
}

func (ar *CreateFAR) UnMarshal(b []byte) {
}

type Interface uint8

const (
	Access     Interface = iota
	Core       Interface = iota
	SGiLAN     Interface = iota
	CPFuntion  Interface = iota
	LIFunction Interface = iota
)

type RedirectAddressType uint8

const (
	IPV4 RedirectAddressType = iota
	IPV6 RedirectAddressType = iota
	URL  RedirectAddressType = iota
	SIP  RedirectAddressType = iota
)

type RedirectInformation struct {
	RedirectAddressType RedirectAddressType `yaml:"redirectAddressType"`
	RedirectAddress     string              `yaml:"redirectAddress"`
}

func (ri *RedirectInformation) Marshal() []byte {
	b, n := newTLVBuffer(RedirectInformationIEType, 0)
	b[n] = uint8(ri.RedirectAddressType)
	n++
	binary.BigEndian.PutUint16(b[n:], uint16(len(ri.RedirectAddress)))
	n += 2
	n += copy(b[n:], ri.RedirectAddress)
	setTLVLength(b, n)
	return b[:n]
}

type OuterHeaderCreationMask uint16

const (
	OUTER_HEADER_CREATION_GTPU_UDP_IPV4 OuterHeaderCreationMask = 1 << 0
	OUTER_HEADER_CREATION_GTPU_UDP_IPV6 OuterHeaderCreationMask = 1 << 1
	OUTER_HEADER_CREATION_UDP_IPV4      OuterHeaderCreationMask = 1 << 2
	OUTER_HEADER_CREATION_UDP_IPV6      OuterHeaderCreationMask = 1 << 3
	OUTER_HEADER_CREATION_IPV4          OuterHeaderCreationMask = 1 << 4
	OUTER_HEADER_CREATION_IPV6          OuterHeaderCreationMask = 1 << 5
)

type OuterHeaderCreation struct {
	Desc OuterHeaderCreationMask `yaml:"desc"`
	Teid uint32                  `yaml:"teid"`
	Ip   net.IP                  `yaml:"ip"`
	Port *uint16                 `yaml:"port,omitempty"`
}

func NewOuterGTPIPV4HeaderCreation(teid uint32, ip net.IP) *OuterHeaderCreation {
	r := &OuterHeaderCreation{Desc: OUTER_HEADER_CREATION_GTPU_UDP_IPV4, Ip: ip, Teid: teid}
	return r
}

func (ohc *OuterHeaderCreation) Marshal() []byte {
	b, n := newTLVBuffer(OuterHeaderCreationIEType, 0)
	b[n] = uint8(ohc.Desc)
	n += 2
	if ohc.Desc&(OUTER_HEADER_CREATION_GTPU_UDP_IPV4|OUTER_HEADER_CREATION_GTPU_UDP_IPV6) != 0 {
		binary.BigEndian.PutUint32(b[n:], ohc.Teid)
		n += 4
	}
	if ohc.Desc&(OUTER_HEADER_CREATION_GTPU_UDP_IPV4|OUTER_HEADER_CREATION_UDP_IPV4) != 0 {
		n += copy(b[n:], ohc.Ip.To4())
	}
	if ohc.Desc&(OUTER_HEADER_CREATION_GTPU_UDP_IPV6|OUTER_HEADER_CREATION_UDP_IPV6) != 0 {
		n += copy(b[n:], ohc.Ip.To16())
	}
	if ohc.Desc&(OUTER_HEADER_CREATION_UDP_IPV4|OUTER_HEADER_CREATION_UDP_IPV6) != 0 {
		binary.BigEndian.PutUint16(b[n:], *ohc.Port)
		n += 2
	}
	setTLVLength(b, n)
	return b[:n]
}

type ForwardingParameters struct {
	DestinationInterface Interface            `yaml:"destinationInterface"`
	NetworkInstance      string               `yaml:"networkInstance,omitempty"`
	RedirectInformation  *RedirectInformation `yaml:"redirectInformation,omitempty"`
	OuterHeaderCreation  *OuterHeaderCreation `yaml:"outerHeaderCreation,omitempty"`
	ForwardingPolicy     string               `yaml:"forwardingPolicy,omitempty"`
}

func NewForwardingParameters(destInterface Interface) *ForwardingParameters {
	r := &ForwardingParameters{DestinationInterface: destInterface}
	return r
}

func (fp *ForwardingParameters) SetNetworkInstance(networkInstance string) {
	fp.NetworkInstance = networkInstance
}

func (fp *ForwardingParameters) SetOuterHeaderCreation(ohc *OuterHeaderCreation) {
	fp.OuterHeaderCreation = ohc
}

func (fp *ForwardingParameters) Marshal() []byte {
	b, n := newTLVBuffer(ForwardingParametersIEType, 0)
	n += copy(b[n:], newTLVUint8(DestinationInterfaceIEType, uint8(fp.DestinationInterface)))

	if fp.NetworkInstance != "" {
		n += copy(b[n:], newTLVDNSName(NetworkInstanceIEType, fp.NetworkInstance))
	}
	if fp.RedirectInformation != nil {
		n += copy(b[n:], fp.RedirectInformation.Marshal())
	}
	if fp.OuterHeaderCreation != nil {
		n += copy(b[n:], fp.OuterHeaderCreation.Marshal())
	}
	if fp.ForwardingPolicy != "" {
		n += copy(b[n:], newTLVString(ForwardingPolicyIEType, fp.ForwardingPolicy))
	}

	setTLVLength(b, n)
	return b[:n]
}

func DecodePFCPInformationElement(b []byte) (n int, ie PFCPInformationElement, err error) {
	var tag IEType = IEType(binary.BigEndian.Uint16(b[n:]))
	n += 2
	len := binary.BigEndian.Uint16(b[n:])
	n += 2
	switch tag {
	case NodeIDIEType:
		ie = new(NodeID)
		ie.UnMarshal(b[n:])
	case CauseIEType:
		ie = new(CauseIE)
		ie.UnMarshal(b[n:])
	}
	n += int(len)
	return n, ie, nil
}

const (
	HEADER_SEID = 1 << 0
	HEADER_MP   = 1 << 1
)

type PFCPMessageHeader struct {
	isSEIDSet            bool
	isMessagePrioritySet bool
	messageType          MessageType
	messageLength        uint16
	seid                 uint64
	sequenceNumber       uint32
	messagePriority      uint8
}

func (h *PFCPMessageHeader) String() string {
	s := "[type: " + h.messageType.String()
	if h.isSEIDSet {
		s += ",seid: " + strconv.FormatInt(int64(h.seid), 10)
	}
	return s + "]"
}

func (h *PFCPMessageHeader) SetSEID(seid uint64) {
	h.isSEIDSet = true
	h.seid = seid
}

func (h *PFCPMessageHeader) Marshal() ([]byte, error) {
	b := make([]byte, MaxSize)
	n := 0
	b[n] = (PFCP_VERSION << 5)
	if h.isSEIDSet {
		b[n] |= HEADER_SEID
	}
	if h.isMessagePrioritySet {
		b[n] |= HEADER_MP
	}
	n++
	b[n] = byte(h.messageType)
	n++
	binary.BigEndian.PutUint16(b[n:], h.messageLength)
	n += 2
	if h.isSEIDSet {
		binary.BigEndian.PutUint64(b[n:], h.seid)
		n += 8
	}
	b[n] = byte((h.sequenceNumber >> 16) & 0xFF)
	b[n+1] = byte((h.sequenceNumber >> 8) & 0xFF)
	b[n+2] = byte((h.sequenceNumber) & 0xFF)
	n += 3

	if h.isMessagePrioritySet {
		b[n] = h.messagePriority << 4
	}
	n++
	return b[:n], nil
}

func (h *PFCPMessageHeader) UnMarshal(b []byte) (n int, err error) {
	h.isSEIDSet = (b[n] & HEADER_SEID) != 0
	h.isMessagePrioritySet = (b[n] & HEADER_MP) != 0
	n++
	h.messageType = MessageType(b[n])
	n++
	h.messageLength = binary.BigEndian.Uint16(b[n:])
	n += 2
	if h.isSEIDSet {
		h.seid = binary.BigEndian.Uint64(b[n:])
		n += 8
	}
	h.sequenceNumber = (uint32(b[n]) << 16) | (uint32(b[n+1]) << 8) | uint32(b[n+2])
	n += 3
	if h.isMessagePrioritySet {
		h.messagePriority = b[n] >> 4
	}
	n++
	return n, err
}

type PFCPMessage struct {
	PFCPMessageHeader
	ies []PFCPInformationElement
}

func (m *PFCPMessage) String() string {
	s := "PFCP Message " + m.PFCPMessageHeader.String()
	if len(m.ies) > 0 {
		s = s + "\n"
	}
	for _, ie := range m.ies {
		s += "\t" + ie.String()
	}
	return s
}

func (h *PFCPMessage) Marshal() ([]byte, error) {
	b, err := h.PFCPMessageHeader.Marshal()
	if err != nil {
		return nil, err
	}
	for _, ie := range h.ies {
		b = append(b, ie.Marshal()...)
	}
	// patch message length
	setTLVLength(b, len(b))
	return b, nil
}

func (h *PFCPMessage) UnMarshal(b []byte) (n int, err error) {
	n, err = h.PFCPMessageHeader.UnMarshal(b)
	if err != nil {
		return 0, err
	}
	var msgLen uint16 = h.messageLength - 3 - 1 // seqnum + spare
	if h.isSEIDSet {
		msgLen -= 8
	}
	var iesLen uint16 = 0
	for {
		ieLen, ie, err := DecodePFCPInformationElement(b[n:])
		if err != nil {
			return 0, err
		}
		if ie != nil {
			iesLen += uint16(ieLen)
			h.ies = append(h.ies, ie)
		}
		n += ieLen
		if ie == nil || iesLen >= msgLen {
			break
		}
	}
	return n, nil
}

func (m *PFCPMessage) getCause() Cause {
	for _, ie := range m.ies {
		if causeIE, ok := ie.(*CauseIE); ok {
			return causeIE.value
		}
	}
	return 0
}

func newPFCPSessionDeleteRequestMessage(fseid *FSEID) (msg *PFCPMessage) {
	msg = new(PFCPMessage)
	msg.messageType = SessionEtablismentRequest
	msg.SetSEID(fseid.seid)
	return msg
}

type PFCPConnection struct {
	laddr, raddr    *net.UDPAddr
	localAddress    string
	conn            *net.UDPConn
	sequenceNumber  uint32
	startTime       time.Time
	nodeID          *NodeID
	nextSEID        uint64
	outMessages     chan *Request
	pendingRequests map[uint32]*Request
	done            chan struct{}
}

type Request struct {
	msg   *PFCPMessage
	reply chan Cause
}

func newRequest(msg *PFCPMessage) *Request {
	return &Request{msg: msg, reply: make(chan Cause, 1)}
}

func (r *Request) GetResponse() (Cause, bool) {
	select {
	case c := <-r.reply:
		return c, false
	case <-time.After(5 * time.Second):
		return 0, true
	}
}

func NewPCPFConnection(localAddr, remoteAddr string) (*PFCPConnection, error) {
	raddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, err
	}
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, err
	}
	idx := strings.IndexByte(localAddr, ':')
	if idx == -1 {
		idx = len(localAddr)
	}
	nodeID := NewNodeID(localAddr[:idx])
	ep := PFCPConnection{raddr: raddr, laddr: laddr, localAddress: string(localAddr[:idx]), nodeID: nodeID,
		outMessages: make(chan *Request), pendingRequests: make(map[uint32]*Request), done: make(chan struct{})}
	ep.startTime = time.Now()
	if err := ep.Start(); err != nil {
		return nil, err
	}
	return &ep, nil
}

func (ep *PFCPConnection) Start() error {
	var err error
	ep.conn, err = net.DialUDP("udp", ep.laddr, ep.raddr)
	if err != nil {
		return err
	}
	buffer := make([]byte, 1024)
	inMessages := make(chan *PFCPMessage)
	go func() {
	loop:
		for {
			select {
			case <-ep.done:
				break loop
			default:
			}
			if err := ep.conn.SetDeadline(
				time.Now().Add(2 * time.Second)); err != nil {
				fmt.Printf("Failed to det deadline %v\n", err)
			}
			n, _, err := ep.conn.ReadFrom(buffer)
			if err != nil {
				if nerr, ok := err.(net.Error); !ok || !nerr.Timeout() {
					fmt.Println(err)
				}
				continue
			}
			msg := new(PFCPMessage)
			if _, err := msg.UnMarshal(buffer[:n]); err != nil {
				fmt.Printf("Failed to unmarshall PFCP message %v\n", err)
				continue
			}
			inMessages <- msg
		}

	}()

	go func() {
		for {
			select {
			case req := <-ep.outMessages:
				req.msg.sequenceNumber = ep.sequenceNumber
				b, err := req.msg.Marshal()
				if err != nil {
					continue //XX
				}
				ep.pendingRequests[ep.sequenceNumber] = req
				_, err = ep.conn.Write(b)
				if err != nil {
					delete(ep.pendingRequests, ep.sequenceNumber)
					continue
				}
				ep.sequenceNumber++
			case msg := <-inMessages:
				// fmt.Printf("Received %s\n", msg)
				switch msg.messageType {
				case HeartbeatRequest:
					response := new(PFCPMessage)
					response.messageType = HeartbeatResponse
					response.sequenceNumber = msg.sequenceNumber
					response.ies = append(response.ies, NewRecoveryTimestamp(ep.startTime))
					if err := ep.sendResponse(response); err != nil {
						fmt.Printf("Failed to send response %s\n", err)
					}
				case HeartbeatResponse, AssociationSetupResponse, SessionEtablismentResponse:
					req := ep.pendingRequests[msg.sequenceNumber]
					if req == nil {
						fmt.Printf("Receive PFCP response message for unknown request, sequence number=%d\n", msg.sequenceNumber)
						continue
					}
					req.reply <- msg.getCause()
					delete(ep.pendingRequests, msg.sequenceNumber)
				default:
					fmt.Printf("Ignoring PFCP message with type %d\n", msg.messageType)
				}
			case <-ep.done:
				break
			}
		}

	}()
	return nil
}

func (ep *PFCPConnection) Close() {
	close(ep.done)
	ep.conn.Close() //XX
}

func (ep *PFCPConnection) sendRequest(msg *PFCPMessage) (*Request, error) {
	req := newRequest(msg)
	ep.outMessages <- req
	return req, nil
}

func (ep *PFCPConnection) SendSetupAssociationRequest() (*Request, error) {
	msg := new(PFCPMessage)
	msg.messageType = AssociationSetupRequest
	msg.ies = append(msg.ies, ep.nodeID, NewRecoveryTimestamp(ep.startTime))
	return ep.sendRequest(msg)
}

func (ep *PFCPConnection) SendSessionEstablishmentRequest(params *SessionParams) (*Request, error) {
	msg := new(PFCPMessage)
	msg.messageType = SessionEtablismentRequest
	msg.SetSEID(params.Seid)
	msg.ies = append(msg.ies, ep.nodeID)
	msg.ies = append(msg.ies, NewFSEID(ep.localAddress, params.Seid))
	for _, pdr := range params.Pdrs {
		msg.ies = append(msg.ies, pdr)
	}
	for _, far := range params.Fars {
		msg.ies = append(msg.ies, far)
	}
	return ep.sendRequest(msg)
}

func (ep *PFCPConnection) SendHeartbeatRequest() (*Request, error) {
	hb := new(PFCPMessage)
	hb.messageType = HeartbeatRequest
	hb.ies = append(hb.ies, NewRecoveryTimestamp(ep.startTime))
	return ep.sendRequest(hb)
}

func (ep *PFCPConnection) sendResponse(msg *PFCPMessage) error {
	b, err := msg.Marshal()
	if err != nil {
		return err
	}
	_, err = ep.conn.Write(b)
	if err != nil {
		return err
	}
	return nil
}

type SessionParams struct {
	Seid uint64       `yaml:"seid"`
	Pdrs []*CreatePdr `yaml:"pdrs"`
	Fars []*CreateFAR `yaml:"fars"`
}
