// Copyright 2019 flannel authors
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
package wireguard

import (
	"encoding/json"
	"sync"

	log "github.com/golang/glog"
	"golang.org/x/net/context"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/subnet"
)

const (
	/*
		20-byte IPv4 header or 40 byte IPv6 header
		8-byte UDP header
		4-byte type
		4-byte key index
		8-byte nonce
		N-byte encrypted data
		16-byte authentication tag
	*/
	overhead = 80
)

type network struct {
	name     string
	extIface *backend.ExternalInterface
	lease    *subnet.Lease
	sm       subnet.Manager
	devAttrs *wgDeviceAttrs
	dev      *wgDevice
}

func (n *network) Lease() *subnet.Lease {
	return n.lease
}

func (n *network) MTU() int {
	return n.extIface.Iface.MTU - overhead
}

func (n *network) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	log.Info("Watching for new subnet leases")
	evts := make(chan []subnet.Event)
	wg.Add(1)
	go func() {
		subnet.WatchLeases(ctx, n.sm, n.lease, evts)
		wg.Done()
	}()

	defer wg.Wait()

	for {
		select {
		case evtBatch := <-evts:
			n.handleSubnetEvents(evtBatch)

		case <-ctx.Done():
			return
		}
	}
}

func (n *network) handleSubnetEvents(batch []subnet.Event) {
	for _, evt := range batch {
		switch evt.Type {
		case subnet.EventAdded:
			log.Infof("Subnet added: %v via %v", evt.Lease.Subnet, evt.Lease.Attrs.PublicIP)

			if evt.Lease.Attrs.BackendType != "wireguard" {
				log.Warningf("Ignoring non-wireguard subnet: type=%v", evt.Lease.Attrs.BackendType)
				continue
			}

			backendData := ""

			if len(evt.Lease.Attrs.BackendData) > 0 {
				if err := json.Unmarshal(evt.Lease.Attrs.BackendData, &backendData); err != nil {
					log.Errorf("failed to unmarshal BackendData: %v", err)
					continue
				}
			}

			if err := n.dev.addPeer(
				n.devAttrs,
				evt.Lease.Attrs.PublicIP.String(),
				backendData,
				&evt.Lease.Subnet,
			); err != nil {
				log.Errorf("failed to setup peer %v", err)
				continue
			}

		case subnet.EventRemoved:
			log.Info("Subnet removed: ", evt.Lease.Subnet)

			if evt.Lease.Attrs.BackendType != "wireguard" {
				log.Warningf("Ignoring non-wireguard subnet: type=%v", evt.Lease.Attrs.BackendType)
				continue
			}

			backendData := ""

			if len(evt.Lease.Attrs.BackendData) > 0 {
				if err := json.Unmarshal(evt.Lease.Attrs.BackendData, &backendData); err != nil {
					log.Errorf("failed to unmarshal BackendData: %v", err)
					continue
				}
			}

			if err := n.dev.removePeer(
				n.devAttrs,
				backendData,
			); err != nil {
				log.Errorf("failed to remove peer %v", err)
				continue
			}

		default:
			log.Error("Internal error: unknown event type: ", int(evt.Type))
		}
	}
}
