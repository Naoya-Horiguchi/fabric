/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package minbft

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger-labs/minbft/api"
	"github.com/hyperledger-labs/minbft/client"
	mbft "github.com/hyperledger-labs/minbft/core"
	mbftauth "github.com/hyperledger-labs/minbft/sample/authentication"
	"github.com/hyperledger-labs/minbft/sample/config"
	"github.com/hyperledger-labs/minbft/sample/net/grpc/connector"
	"github.com/hyperledger-labs/minbft/sample/net/grpc/server"
	"github.com/hyperledger-labs/minbft/sample/requestconsumer"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/orderer/consensus/migration"
	cb "github.com/hyperledger/fabric/protos/common"
	logging "github.com/op/go-logging"
	"google.golang.org/grpc"
)

var logger = flogging.MustGetLogger("orderer.consensus.minbft")

type consenter struct{}

type chain struct {
	support         consensus.ConsenterSupport
	sendChan        chan *message
	exitChan        chan struct{}
	migrationStatus migration.Status
	client          client.Client
}

type message struct {
	configSeq uint64
	normalMsg *cb.Envelope
	configMsg *cb.Envelope
}

func New() consensus.Consenter {
	return &consenter{}
}

func (minbft *consenter) HandleChain(support consensus.ConsenterSupport, metadata *cb.Metadata) (consensus.Chain, error) {
	return newChain(support)
}

func newChain(support consensus.ConsenterSupport) (*chain, error) {
	// configure backend
	id2, _ := strconv.ParseUint(os.Getenv("MINBFT_REPLICA_ID"), 10, 64)
	id := uint32(id2)
	logger.Infof("Replica ID: %s", id)
	// TODO: making this configurable from orderer.yaml
	usigEnclaveFile := "/var/hyperledger/orderer/minbft-artifacts/libusig.signed.so"
	keysFile, err := os.Open("/var/hyperledger/orderer/minbft-artifacts/keys.yaml")
	if err != nil {
		logger.Warningf("Failed to open keysFile: %s", err)
		return nil, fmt.Errorf("failed in backend")
	}

	auth, err := mbftauth.NewWithSGXUSIG([]api.AuthenticationRole{api.ReplicaAuthen, api.USIGAuthen}, id, keysFile, usigEnclaveFile)
	if err != nil {
		logger.Warningf("Failed to create authenticator: %s - %v %v %v", err, id, keysFile, usigEnclaveFile)
		return nil, fmt.Errorf("failed in backend 2")
	}

	ledger := requestconsumer.NewSimpleLedger()

	// consensus
	cfg := config.New()
	cfg.LoadConfig("/var/hyperledger/orderer/minbft-artifacts/consensus.yaml")

	peerAddrs := make(map[uint32]string)
	var listenAddr string
	for _, p := range cfg.Peers() {
		// avoid connecting back to this replica
		if uint32(p.ID) == id {
			listenAddr = p.Addr
		} else {
			peerAddrs[uint32(p.ID)] = p.Addr
		}
	}
	logger.Infof("listenAddr: %+v", listenAddr)
	logger.Infof("peerAddrs: %+v", peerAddrs)

	opts := []mbft.Option{}
	loglevel, _ := logging.LogLevel("DEBUG")
	opts = append(opts, mbft.WithLogLevel(loglevel))
	// opts = append(opts, mbft.WithLogFile(logFile))
	replicaConnector := connector.New()
	if err := replicaConnector.ConnectManyReplicas(peerAddrs, grpc.WithInsecure()); err != nil {
		logger.Errorf("Failed to connect to peers: %s", err)
		return nil, fmt.Errorf("failed in backend 3")
	}
	logger.Infof("replicaConnector: %+v", replicaConnector)

	ch := &chain{
		support:         support,
		sendChan:        make(chan *message),
		exitChan:        make(chan struct{}),
		migrationStatus: migration.NewStatusStepper(support.IsSystemChannel(), support.ChainID()),
	}

	// initialize peer
	replica, err := mbft.New(id, cfg, &replicaStack{replicaConnector, auth, ledger}, opts...)
	if err != nil {
		logger.Errorf("Failed to create replica instance: %s", err)
		return nil, fmt.Errorf("failed in backend 4")
	}
	replicaServer := server.New(replica)
	srvErrChan := make(chan error)
	go func() {
		replicaServer.Stop()
		defer replicaServer.Stop()
		if err := replicaServer.ListenAndServe(listenAddr); err != nil {
			err = fmt.Errorf("Network server failed: %s", err)
			fmt.Println(err)
			srvErrChan <- err
			// TODO: error handling
		}
	}()

	// Newly opens keys.yaml. Without this mbftauth.New() below will fail.
	clkeysFile, err := os.Open("/var/hyperledger/orderer/minbft-artifacts/keys.yaml")
	if err != nil {
		logger.Warningf("Failed to open keysFile: %s", err)
		return nil, fmt.Errorf("failed in backend 5")
	}
	cid := uint32(0)
	clauth, err := mbftauth.New([]api.AuthenticationRole{api.ClientAuthen}, cid, clkeysFile)
	if err != nil {
		logger.Errorf("Failed to create authenticator: %s", err)
		return nil, fmt.Errorf("failed in backend 6")
	}
	clpeerAddrs := make(map[uint32]string)
	for _, p := range cfg.Peers() {
		clpeerAddrs[uint32(p.ID)] = p.Addr
	}
	clrc := connector.New()
	logger.Infof("connecting to replicas peers: %v", clpeerAddrs)
	err = clrc.ConnectManyReplicas(clpeerAddrs, grpc.WithInsecure())
	if err != nil {
		logger.Errorf("Failed to connect to peers: %s", err)
		return nil, fmt.Errorf("failed in backend 7")
	}

	client, err := client.New(cid, cfg.N(), cfg.F(), clientStack{clauth, clrc})
	if err != nil {
		logger.Errorf("Failed to create client instance: %s", err)
		return nil, fmt.Errorf("failed in backend 8")
	}

	ch.client = client

	return ch, nil
}

func (ch *chain) Start() {
	logger.Infof("Start MinBFT consensus algorithm")
	go ch.main()
}

func (ch *chain) Halt() {
	select {
	case <-ch.exitChan:
		// Allow multiple halts without panic
	default:
		close(ch.exitChan)
	}
}

func (ch *chain) WaitReady() error {
	return nil
}

// Order accepts normal messages for ordering
func (ch *chain) Order(env *cb.Envelope, configSeq uint64) error {
	select {
	case ch.sendChan <- &message{
		configSeq: configSeq,
		normalMsg: env,
	}:
		return nil
	case <-ch.exitChan:
		return fmt.Errorf("Exiting")
	}
}

// Configure accepts configuration update messages for ordering
func (ch *chain) Configure(config *cb.Envelope, configSeq uint64) error {
	select {
	case ch.sendChan <- &message{
		configSeq: configSeq,
		configMsg: config,
	}:
		return nil
	case <-ch.exitChan:
		return fmt.Errorf("Exiting")
	}
}

func (ch *chain) Errored() <-chan struct{} {
	return ch.exitChan
}

func (ch *chain) MigrationStatus() migration.Status {
	return ch.migrationStatus
}

type replicaStack struct {
	api.ReplicaConnector
	api.Authenticator
	api.RequestConsumer
}

type clientStack struct {
	api.Authenticator
	api.ReplicaConnector
}

func (ch *chain) main() {
	var timer <-chan time.Time
	var err error

	for {
		seq := ch.support.Sequence()
		err = nil
		select {
		case msg := <-ch.sendChan:
			// logger.Warningf("&&& message receive event"), msg.configMsg)
			if msg.configMsg == nil {
				// payload, _ := utils.UnmarshalPayload(msg.normalMsg.Payload)
				// NormalMsg
				if msg.configSeq < seq {
					_, err = ch.support.ProcessNormalMsg(msg.normalMsg)
					if err != nil {
						logger.Warningf("Discarding bad normal message: %s", err)
						continue
					}
				}
				batches, pending := ch.support.BlockCutter().Ordered(msg.normalMsg)

				// TODO: one block per one batch might be inefficient
				for _, batch := range batches {
					logger.Warningf("===> Submitting NormalMsg to MinBFT consensus")
					block := ch.support.CreateNextBlock(batch)
					buf, _ := proto.Marshal(block)
					<-ch.client.Request(buf)
					logger.Warningf("MinBFT for NormalMsg returns (that means that we successfully reach consensus.)")
					ch.support.WriteBlock(block, nil)
				}

				switch {
				case timer != nil && !pending:
					// Timer is already running but there are no messages pending, stop the timer
					timer = nil
				case timer == nil && pending:
					// Timer is not already running and there are messages pending, so start it
					timer = time.After(ch.support.SharedConfig().BatchTimeout())
					logger.Debugf("Just began %s batch timer", ch.support.SharedConfig().BatchTimeout().String())
				default:
					// Do nothing when:
					// 1. Timer is already running and there are messages pending
					// 2. Timer is not set and there are no messages pending
				}

			} else {
				// ConfigMsg
				if msg.configSeq < seq {
					msg.configMsg, _, err = ch.support.ProcessConfigMsg(msg.configMsg)
					if err != nil {
						logger.Warningf("Discarding bad config message: %s", err)
						continue
					}
				}
				batch := ch.support.BlockCutter().Cut()
				if batch != nil {
					block := ch.support.CreateNextBlock(batch)
					ch.support.WriteBlock(block, nil)
				}

				logger.Warningf("===> Submitting ConfigMsg to MinBFT consensus")
				block := ch.support.CreateNextBlock([]*cb.Envelope{msg.configMsg})
				buf, _ := proto.Marshal(block)
				<-ch.client.Request(buf)
				logger.Warningf("MinBFT for ConfigMsg returns (that means that we successfully reach consensus.)")
				ch.support.WriteConfigBlock(block, nil)
				timer = nil
			}
		case <-timer:
			//clear the timer
			timer = nil

			batch := ch.support.BlockCutter().Cut()
			if len(batch) == 0 {
				logger.Warningf("Batch timer expired with no pending requests, this might indicate a bug")
				continue
			}
			logger.Warningf("Batch timer expired, creating block")
			logger.Warningf("===> Submitting pending requests to MinBFT consensus")
			block := ch.support.CreateNextBlock(batch)
			buf, _ := proto.Marshal(block)
			<-ch.client.Request(buf)
			logger.Warningf("MinBFT returns (that means that we successfully reach consensus.)")
			ch.support.WriteBlock(block, nil)
		case <-ch.exitChan:
			logger.Debugf("Exiting")
			return
		}
	}
}
