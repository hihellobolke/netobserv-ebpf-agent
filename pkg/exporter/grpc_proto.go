package exporter

import (
	"context"
	"net"
	"strings"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/grpc"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/utils"
	"github.com/sirupsen/logrus"
)

var glog = logrus.WithField("component", "exporter/GRPCProto")

// GRPCProto flow exporter. Its ExportFlows method accepts slices of *flow.Record
// by its input channel, converts them to *pbflow.Records instances, and submits
// them to the collector.
type GRPCProto struct {
	hostIP     string
	hostPort   int
	clientConn *grpc.ClientConnection
	// maxFlowsPerMessage limits the maximum number of flows per GRPC message.
	// If a message contains more flows than this number, the GRPC message will be split into
	// multiple messages.
	maxFlowsPerMessage int
	excludeDestIPs     []string
}

func StartGRPCProto(hostIP string, hostPort int, maxFlowsPerMessage int, excludeDestIPs string) (*GRPCProto, error) {
	clientConn, err := grpc.ConnectClient(hostIP, hostPort)
	if err != nil {
		return nil, err
	}
	return &GRPCProto{
		hostIP:             hostIP,
		hostPort:           hostPort,
		clientConn:         clientConn,
		maxFlowsPerMessage: maxFlowsPerMessage,
		excludeDestIPs:     strings.Split(excludeDestIPs, ","),
	}, nil
}

// ExportFlows accepts slices of *flow.Record by its input channel, converts them
// to *pbflow.Records instances, and submits them to the collector.
func (g *GRPCProto) ExportFlows(input <-chan []*flow.Record) {
	socket := utils.GetSocket(g.hostIP, g.hostPort)
	log := glog.WithField("collector", socket)
	for inputRecords := range input {
		inputRecordsFiltered := g.FilterIPs(inputRecords)
		for _, pbRecords := range flowsToPB(inputRecordsFiltered, g.maxFlowsPerMessage) {
			log.Debugf("sending %d records", len(pbRecords.Entries))
			if _, err := g.clientConn.Client().Send(context.TODO(), pbRecords); err != nil {
				log.WithError(err).Error("couldn't send flow records to collector")
			}
		}
	}
	if err := g.clientConn.Close(); err != nil {
		log.WithError(err).Warn("couldn't close flow export client")
	}
}

func (g *GRPCProto) FilterIPs(records []*flow.Record) []*flow.Record {
	log := glog.WithField("filter", len(records))
	var filteredRecords []*flow.Record

	if len(g.excludeDestIPs) == 0 {
		return records
	}

	for _, record := range records {

		// can only filter ipv4 records
		if record.Id.EthProtocol != flow.IPv6Type {
			// convert 16uint8 to net.IP
			destIP := net.IP(record.Id.DstIp[12:16])
			destIPStr := destIP.String()
			exclude := false
			for _, destIPSubstr := range g.excludeDestIPs {
				if strings.HasPrefix(destIPStr, destIPSubstr) {
					exclude = true
					break
				}
			}
			if !exclude {
				log.Debug("++ ip:", destIPStr)
				filteredRecords = append(filteredRecords, record)
			}
		}
	}
	return filteredRecords
}
