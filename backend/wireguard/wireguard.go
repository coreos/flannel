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
	"fmt"
	"time"

	"encoding/json"
	"sync"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	"golang.org/x/net/context"
)

func init() {
	backend.Register("wireguard", New)
}

type WireguardBackend struct {
	sm       subnet.Manager
	extIface *backend.ExternalInterface
	networks map[string]*network
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	be := &WireguardBackend{
		sm:       sm,
		extIface: extIface,
		networks: make(map[string]*network),
	}

	return be, nil
}

func (be *WireguardBackend) RegisterNetwork(ctx context.Context, wg *sync.WaitGroup, config *subnet.Config) (backend.Network, error) {
	n := &network{
		extIface: be.extIface,
		sm:       be.sm,
		devAttrs: &wgDeviceAttrs{},
	}

	// Parse out configuration
	if len(config.Backend) > 0 {
		cfg := struct {
			ListenPort                  int
			PSK                         string
			PersistentKeepaliveInterval time.Duration
		}{
			ListenPort:                  51820,
			PersistentKeepaliveInterval: 0,
		}
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding backend config: %v", err)
		}
		keepalive := cfg.PersistentKeepaliveInterval * time.Second
		n.devAttrs.listenPort = cfg.ListenPort
		n.devAttrs.deviceName = "flannel-wg"
		n.devAttrs.keepalive = &keepalive
		err := setupKeys(n.devAttrs, cfg.PSK)
		if err != nil {
			return nil, err
		}
	}

	publicKey := n.devAttrs.publicKey
	data, err := json.Marshal(publicKey.String())
	if err != nil {
		return nil, err
	}

	dev, err := newWGDevice(n.devAttrs, ctx, wg)
	if err != nil {
		return nil, err
	}
	n.dev = dev

	attrs := subnet.LeaseAttrs{
		PublicIP:    ip.FromIP(be.extIface.ExtAddr),
		BackendType: "wireguard",
		BackendData: data,
	}

	lease, err := be.sm.AcquireLease(ctx, &attrs)
	switch err {

	case nil:
		n.lease = lease
	case context.Canceled, context.DeadlineExceeded:
		return nil, err
	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)

	}

	err = n.dev.Configure(n.devAttrs, lease.Subnet.IP, config.Network.ToIPNet())
	if err != nil {
		return nil, err
	}

	return n, nil
}
