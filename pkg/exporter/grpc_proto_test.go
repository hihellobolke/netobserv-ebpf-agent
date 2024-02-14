package exporter

import (
	"net"
	"testing"
	"time"

	test2 "github.com/netobserv/netobserv-ebpf-agent/pkg/test"

	"github.com/mariomac/guara/pkg/test"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/grpc"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const timeout = 2 * time.Second

func TestIPv4GRPCProto_ExportFlows_AgentIP(t *testing.T) {
	// start remote ingestor
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	serverOut := make(chan *pbflow.Records)
	coll, err := grpc.StartCollector(port, serverOut)
	require.NoError(t, err)
	defer coll.Close()

	// Start GRPCProto exporter stage
	exporter, err := StartGRPCProto("127.0.0.1", port, 1000, "")
	require.NoError(t, err)

	// Send some flows to the input of the exporter stage
	flows := make(chan []*flow.Record, 10)
	flows <- []*flow.Record{
		{AgentIP: net.ParseIP("10.9.8.7")},
	}
	flows <- []*flow.Record{
		{RawRecord: flow.RawRecord{Id: ebpf.BpfFlowId{EthProtocol: flow.IPv6Type}},
			AgentIP: net.ParseIP("8888::1111")},
	}
	go exporter.ExportFlows(flows)

	rs := test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, 1)
	r := rs.Entries[0]
	assert.EqualValues(t, 0x0a090807, r.GetAgentIp().GetIpv4())

	rs = test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, 1)
	r = rs.Entries[0]
	assert.EqualValues(t, net.ParseIP("8888::1111"), r.GetAgentIp().GetIpv6())

	select {
	case rs = <-serverOut:
		assert.Failf(t, "shouldn't have received any flow", "Got: %#v", rs)
	default:
		//ok!
	}
}

func TestIPv6GRPCProto_ExportFlows_AgentIP(t *testing.T) {
	// start remote ingestor
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	serverOut := make(chan *pbflow.Records)
	coll, err := grpc.StartCollector(port, serverOut)
	require.NoError(t, err)
	defer coll.Close()

	// Start GRPCProto exporter stage
	exporter, err := StartGRPCProto("::1", port, 1000, "")
	require.NoError(t, err)

	// Send some flows to the input of the exporter stage
	flows := make(chan []*flow.Record, 10)
	flows <- []*flow.Record{
		{AgentIP: net.ParseIP("10.11.12.13")},
	}
	flows <- []*flow.Record{
		{RawRecord: flow.RawRecord{Id: ebpf.BpfFlowId{EthProtocol: flow.IPv6Type}},
			AgentIP: net.ParseIP("9999::2222")},
	}
	go exporter.ExportFlows(flows)

	rs := test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, 1)
	r := rs.Entries[0]
	assert.EqualValues(t, 0x0a0b0c0d, r.GetAgentIp().GetIpv4())

	rs = test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, 1)
	r = rs.Entries[0]
	assert.EqualValues(t, net.ParseIP("9999::2222"), r.GetAgentIp().GetIpv6())

	select {
	case rs = <-serverOut:
		assert.Failf(t, "shouldn't have received any flow", "Got: %#v", rs)
	default:
		//ok!
	}
}

func TestGRPCProto_SplitLargeMessages(t *testing.T) {
	// start remote ingestor
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	serverOut := make(chan *pbflow.Records)
	coll, err := grpc.StartCollector(port, serverOut)
	require.NoError(t, err)
	defer coll.Close()

	const msgMaxLen = 10000
	// Start GRPCProto exporter stage
	exporter, err := StartGRPCProto("127.0.0.1", port, msgMaxLen, "")
	require.NoError(t, err)

	// Send a message much longer than the limit length
	flows := make(chan []*flow.Record, 10)
	var input []*flow.Record
	for i := 0; i < 25000; i++ {
		input = append(input, &flow.Record{RawRecord: flow.RawRecord{Id: ebpf.BpfFlowId{
			EthProtocol: flow.IPv6Type,
		}}, AgentIP: net.ParseIP("1111::1111"), Interface: "12345678"})
	}
	flows <- input
	go exporter.ExportFlows(flows)

	// expect that the submitted message is split in chunks no longer than msgMaxLen
	rs := test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, msgMaxLen)
	rs = test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, msgMaxLen)
	rs = test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, 5000)

	// after all the operation, no more flows are sent
	select {
	case rs = <-serverOut:
		assert.Failf(t, "shouldn't have received any flow", "Got: %#v", rs)
	default:
		//ok!
	}
}

func TestGRPCProto_FilterIp(t *testing.T) {
	// start remote ingestor
	port, err := test.FreeTCPPort()
	require.NoError(t, err)

	serverOut := make(chan *pbflow.Records)
	coll, err := grpc.StartCollector(port, serverOut)
	require.NoError(t, err)
	defer coll.Close()

	const msgMaxLen = 10000

	r1 := flow.Record{}
	r1.Id.EthProtocol = 3
	r1.Id.Direction = 1
	r1.Id.SrcMac = [...]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	r1.Id.DstMac = [...]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	r1.Id.SrcIp = IPAddrFromNetIP(net.ParseIP("192.1.2.3"))
	r1.Id.DstIp = IPAddrFromNetIP(net.ParseIP("127.3.2.1"))
	r1.Id.SrcPort = 4321
	r1.Id.DstPort = 1234
	r1.Id.IcmpType = 8
	r1.Id.TransportProtocol = 210
	r1.TimeFlowStart = time.Now().Add(-5 * time.Second)
	r1.TimeFlowEnd = time.Now()
	r1.Metrics.Bytes = 789
	r1.Metrics.Packets = 987
	r1.Metrics.Flags = uint16(1)
	r1.Interface = "veth0"

	r2 := flow.Record{}
	r2.Id.EthProtocol = 3
	r2.Id.Direction = 1
	r2.Id.SrcMac = [...]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	r2.Id.DstMac = [...]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	r2.Id.SrcIp = IPAddrFromNetIP(net.ParseIP("192.1.2.3"))
	r2.Id.DstIp = IPAddrFromNetIP(net.ParseIP("128.3.2.1"))
	r2.Id.SrcPort = 4321
	r2.Id.DstPort = 1234
	r2.Id.IcmpType = 8
	r2.Id.TransportProtocol = 210
	r2.TimeFlowStart = time.Now().Add(-5 * time.Second)
	r2.TimeFlowEnd = time.Now()
	r2.Metrics.Bytes = 789
	r2.Metrics.Packets = 987
	r2.Metrics.Flags = uint16(1)
	r2.Interface = "veth0"

	// Start GRPCProto exporter stage
	exporter, err := StartGRPCProto("127.0.0.1", port, msgMaxLen, "127,192")
	require.NoError(t, err)

	records := []*flow.Record{&r1, &r2}
	r := exporter.FilterIPs(records)

	assert.Len(t, r, 1)
}
