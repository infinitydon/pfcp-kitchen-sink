// Copyright 2019-2020 Orange
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"

	"github.com/fdangtran/pfcp-kitchen-sink/pkg/pfcp"

	"gopkg.in/yaml.v2"
)

func waitForCtrlC() {
	var endWaiter sync.WaitGroup
	endWaiter.Add(1)
	var signalChannel chan os.Signal
	signalChannel = make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	go func() {
		<-signalChannel
		endWaiter.Done()
	}()
	endWaiter.Wait()
}

var localAddress = flag.String("l", "0.0.0.0:"+strconv.Itoa(pfcp.PFCP_UDP_PORT), "local address")
var remoteAddress = flag.String("r", "", "remote address")
var sessionFile = flag.String("s", "", "session yaml file")

func main() {
	fmt.Println("PFCP client v0.1")
	flag.Parse()
	if *remoteAddress == "" {
		flag.Usage()
		os.Exit(-1)
	}
	var sessions []*pfcp.SessionParams
	if *sessionFile != "" {
		if sessionData, err := ioutil.ReadFile(*sessionFile); err != nil {
			log.Fatal(err)
		} else {
			err = yaml.Unmarshal(sessionData, &sessions)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	conn, err := pfcp.NewPCPFConnection(*localAddress, *remoteAddress)
	if err != nil {
		log.Fatal(err)
	}

	req, err := conn.SendHeartbeatRequest()
	if _, timeout := req.GetResponse(); timeout {
		fmt.Println("Timeout waiting for heartbeat response")
	}

	req, err = conn.SendSetupAssociationRequest()
	if cause, timeout := req.GetResponse(); timeout {
		fmt.Println("Timeout waiting for setup association response")
	} else {
		if cause != pfcp.RequestAccepted {
			log.Fatalf("setup association failed: %s\n", cause)
		}
	}

	n := 0
	for _, sess := range sessions {
		req, err = conn.SendSessionEstablishmentRequest(sess)
		if cause, timeout := req.GetResponse(); timeout {
			fmt.Println("Timeout waiting for session establishment response")
		} else if cause != pfcp.RequestAccepted {
			log.Fatalf("session establishment failed: %s\n", cause)
		} else {
			n++
		}
	}
	fmt.Printf("%d sessions created successfully\n", n)
	waitForCtrlC()
	conn.Close()
}

func createTestSessions() []*pfcp.SessionParams {
	// UL session
	pdi := pfcp.NewPDI(pfcp.Access)
	fteid := pfcp.NewFTEID(net.ParseIP("172.20.16.105"), 1234)
	pdi.SetLocalFTEID(fteid)
	ueIP := pfcp.NewUEIPAddress(net.ParseIP("10.10.10.10"), false)
	pdi.SetUeIPAddress(ueIP)
	pdr := pfcp.NewCreatePdr(0, 0, pdi)
	pdr.SetOuterHeaderRemoval(pfcp.OUTER_HEADER_GTPU_UDP_IPV4)
	pdr.SetFARID(12)

	far := pfcp.NewCreateFar(12, pfcp.Forward)
	forwParams := pfcp.NewForwardingParameters(pfcp.SGiLAN)
	forwParams.SetNetworkInstance("sgi")
	far.SetForwardingParameters(forwParams)

	ulSession := &pfcp.SessionParams{Seid: 0, Pdrs: []*pfcp.CreatePdr{pdr}, Fars: []*pfcp.CreateFAR{far}}

	// DL session

	pdi = pfcp.NewPDI(pfcp.SGiLAN)
	pdi.SetNetworkInstance("sgi")
	ueIP = pfcp.NewUEIPAddress(net.ParseIP("10.10.10.10"), true)
	pdi.SetUeIPAddress(ueIP)
	filter := pfcp.NewSDFFilter("permit in ip from 0.0.0.0/0  to 0.0.0.0/0 ")
	pdi.SetSDFFilter(filter)
	pdr = pfcp.NewCreatePdr(1, 0, pdi)
	pdr.SetFARID(13)

	far = pfcp.NewCreateFar(13, pfcp.Forward)
	forwParams = pfcp.NewForwardingParameters(pfcp.Access)
	forwParams.SetNetworkInstance("access")
	ohc := pfcp.NewOuterGTPIPV4HeaderCreation(4321, net.ParseIP("172.20.16.99"))
	forwParams.SetOuterHeaderCreation(ohc)
	far.SetForwardingParameters(forwParams)

	dlSession := &pfcp.SessionParams{Seid: 1, Pdrs: []*pfcp.CreatePdr{pdr}, Fars: []*pfcp.CreateFAR{far}}

	res := []*pfcp.SessionParams{ulSession, dlSession}
	d, _ := yaml.Marshal(res)
	fmt.Println(string(d))
	return res
}
