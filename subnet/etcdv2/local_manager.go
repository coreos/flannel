// Copyright 2015 flannel authors
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

package etcdv2

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	etcd "github.com/coreos/etcd/client"
	"github.com/coreos/flannel/pkg/ip"
	. "github.com/coreos/flannel/subnet"
	"golang.org/x/net/context"
	log "k8s.io/klog"
)

const (
	raceRetries = 10
	subnetTTL   = 24 * time.Hour
)

type LocalManager struct {
	registry       Registry
	previousSubnet ip.IP4Net
}

type watchCursor struct {
	index uint64
}

func isErrEtcdTestFailed(e error) bool {
	if e == nil {
		return false
	}
	etcdErr, ok := e.(etcd.Error)
	return ok && etcdErr.Code == etcd.ErrorCodeTestFailed
}

func isErrEtcdNodeExist(e error) bool {
	if e == nil {
		return false
	}
	etcdErr, ok := e.(etcd.Error)
	return ok || etcdErr.Code == etcd.ErrorCodeNodeExist
}

func isErrEtcdKeyNotFound(e error) bool {
	if e == nil {
		return false
	}
	etcdErr, ok := e.(etcd.Error)
	return ok || etcdErr.Code == etcd.ErrorCodeKeyNotFound
}

func (c watchCursor) String() string {
	return strconv.FormatUint(c.index, 10)
}

func NewLocalManager(config *EtcdConfig, prevSubnet ip.IP4Net) (Manager, error) {
	r, err := newEtcdSubnetRegistry(config, nil)
	if err != nil {
		return nil, err
	}
	return newLocalManager(r, prevSubnet), nil
}

func newLocalManager(r Registry, prevSubnet ip.IP4Net) Manager {
	return &LocalManager{
		registry:       r,
		previousSubnet: prevSubnet,
	}
}

func (m *LocalManager) GetNetworkConfig(ctx context.Context) (*Config, error) {
	cfg, err := m.registry.getNetworkConfig(ctx)
	if err != nil {
		return nil, err
	}

	return ParseConfig(cfg)
}

func (m *LocalManager) AcquireLease(ctx context.Context, attrs *LeaseAttrs) (*Lease, error) {
	config, err := m.GetNetworkConfig(ctx)
	if err != nil {
		return nil, err
	}

	for i := 0; i < raceRetries; i++ {
		l, err := m.tryAcquireLease(ctx, config, attrs.PublicIP, attrs)
		switch err {
		case nil:
			//TODO - temporarily compatible with dual stack,
			// only vxlan backend and kube subnet manager support dual stack now.
			l.EnableIPv4 = true
			l.EnableIPv6 = false
			return l, nil
		case errTryAgain:
			continue
		default:
			return nil, err
		}
	}

	return nil, errors.New("Max retries reached trying to acquire a subnet")
}

func findLeaseByIP(leases []Lease, pubIP ip.IP4) *Lease {
	for _, l := range leases {
		if pubIP == l.Attrs.PublicIP {
			return &l
		}
	}

	return nil
}

func findLeaseBySubnet(leases []Lease, subnet ip.IP4Net) *Lease {
	for _, l := range leases {
		if subnet.Equal(l.Subnet) {
			return &l
		}
	}

	return nil
}

func (m *LocalManager) tryAcquireLease(ctx context.Context, config *Config, extIaddr ip.IP4, attrs *LeaseAttrs) (*Lease, error) {
	leases, _, err := m.registry.getSubnets(ctx)
	if err != nil {
		return nil, err
	}

	// Try to reuse a subnet if there's one that matches our IP
	if l := findLeaseByIP(leases, extIaddr); l != nil {
		// Make sure the existing subnet is still within the configured network
		if isSubnetConfigCompat(config, l.Subnet) {
			log.Infof("Found lease (%v) for current IP (%v), reusing", l.Subnet, extIaddr)

			ttl := time.Duration(0)
			if !l.Expiration.IsZero() {
				// Not a reservation
				ttl = subnetTTL
			}
			exp, err := m.registry.updateSubnet(ctx, l.Subnet, attrs, ttl, 0)
			if err != nil {
				return nil, err
			}

			l.Attrs = *attrs
			l.Expiration = exp
			return l, nil
		} else {
			log.Infof("Found lease (%v) for current IP (%v) but not compatible with current config, deleting", l.Subnet, extIaddr)
			if err := m.registry.deleteSubnet(ctx, l.Subnet); err != nil {
				return nil, err
			}
		}
	}

	// no existing match, check if there was a previous subnet to use
	var sn ip.IP4Net
	if !m.previousSubnet.Empty() {
		// use previous subnet
		if l := findLeaseBySubnet(leases, m.previousSubnet); l != nil {
			// Make sure the existing subnet is still within the configured network
			if isSubnetConfigCompat(config, l.Subnet) {
				log.Infof("Found lease (%v) matching previously leased subnet, reusing", l.Subnet)

				ttl := time.Duration(0)
				if !l.Expiration.IsZero() {
					// Not a reservation
					ttl = subnetTTL
				}
				exp, err := m.registry.updateSubnet(ctx, l.Subnet, attrs, ttl, 0)
				if err != nil {
					return nil, err
				}

				l.Attrs = *attrs
				l.Expiration = exp
				return l, nil
			} else {
				log.Infof("Found lease (%v) matching previously leased subnet but not compatible with current config, deleting", l.Subnet)
				if err := m.registry.deleteSubnet(ctx, l.Subnet); err != nil {
					return nil, err
				}
			}
		} else {
			// Check if the previous subnet is a part of the network and of the right subnet length
			if isSubnetConfigCompat(config, m.previousSubnet) {
				log.Infof("Found previously leased subnet (%v), reusing", m.previousSubnet)
				sn = m.previousSubnet
			} else {
				log.Errorf("Found previously leased subnet (%v) that is not compatible with the Etcd network config, ignoring", m.previousSubnet)
			}
		}
	}

	if sn.Empty() {
		// no existing match, grab a new one
		sn, err = m.allocateSubnet(config, leases)
		if err != nil {
			return nil, err
		}
	}

	exp, err := m.registry.createSubnet(ctx, sn, attrs, subnetTTL)
	switch {
	case err == nil:
		log.Infof("Allocated lease (%v) to current node (%v) ", sn, extIaddr)
		return &Lease{
			Subnet:     sn,
			Attrs:      *attrs,
			Expiration: exp,
		}, nil
	case isErrEtcdNodeExist(err):
		return nil, errTryAgain
	default:
		return nil, err
	}
}

func (m *LocalManager) allocateSubnet(config *Config, leases []Lease) (ip.IP4Net, error) {
	log.Infof("Picking subnet in range %s ... %s", config.SubnetMin, config.SubnetMax)

	var bag []ip.IP4
	sn := ip.IP4Net{IP: config.SubnetMin, PrefixLen: config.SubnetLen}

OuterLoop:
	for ; sn.IP <= config.SubnetMax && len(bag) < 100; sn = sn.Next() {
		for _, l := range leases {
			if sn.Overlaps(l.Subnet) {
				continue OuterLoop
			}
		}
		bag = append(bag, sn.IP)
	}

	if len(bag) == 0 {
		return ip.IP4Net{}, errors.New("out of subnets")
	} else {
		i := randInt(0, len(bag))
		return ip.IP4Net{IP: bag[i], PrefixLen: config.SubnetLen}, nil
	}
}

func (m *LocalManager) RenewLease(ctx context.Context, lease *Lease) error {
	exp, err := m.registry.updateSubnet(ctx, lease.Subnet, &lease.Attrs, subnetTTL, 0)
	if err != nil {
		return err
	}

	lease.Expiration = exp
	return nil
}

func getNextIndex(cursor interface{}) (uint64, error) {
	nextIndex := uint64(0)

	if wc, ok := cursor.(watchCursor); ok {
		nextIndex = wc.index
	} else if s, ok := cursor.(string); ok {
		var err error
		nextIndex, err = strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse cursor: %v", err)
		}
	} else {
		return 0, fmt.Errorf("internal error: watch cursor is of unknown type")
	}

	return nextIndex, nil
}

func (m *LocalManager) leaseWatchReset(ctx context.Context, sn ip.IP4Net) (LeaseWatchResult, error) {
	l, index, err := m.registry.getSubnet(ctx, sn)
	if err != nil {
		return LeaseWatchResult{}, err
	}

	//TODO - temporarily compatible with dual stack,
	// only vxlan backend and kube subnet manager support dual stack now.
	l.EnableIPv4 = true
	l.EnableIPv6 = false

	return LeaseWatchResult{
		Snapshot: []Lease{*l},
		Cursor:   watchCursor{index},
	}, nil
}

func (m *LocalManager) WatchLease(ctx context.Context, sn ip.IP4Net, cursor interface{}) (LeaseWatchResult, error) {
	if cursor == nil {
		return m.leaseWatchReset(ctx, sn)
	}

	nextIndex, err := getNextIndex(cursor)
	if err != nil {
		return LeaseWatchResult{}, err
	}

	evt, index, err := m.registry.watchSubnet(ctx, nextIndex, sn)

	switch {
	case err == nil:
		//TODO - temporarily compatible with dual stack,
		// only vxlan backend and kube subnet manager support dual stack now.
		evt.Lease.EnableIPv4 = true
		evt.Lease.EnableIPv6 = false
		return LeaseWatchResult{
			Events: []Event{evt},
			Cursor: watchCursor{index},
		}, nil

	case isIndexTooSmall(err):
		log.Warning("Watch of subnet leases failed because etcd index outside history window")
		return m.leaseWatchReset(ctx, sn)

	default:
		return LeaseWatchResult{}, err
	}
}

func (m *LocalManager) WatchLeases(ctx context.Context, cursor interface{}) (LeaseWatchResult, error) {
	if cursor == nil {
		return m.leasesWatchReset(ctx)
	}

	nextIndex, err := getNextIndex(cursor)
	if err != nil {
		return LeaseWatchResult{}, err
	}

	evt, index, err := m.registry.watchSubnets(ctx, nextIndex)
	switch {
	case err == nil:
		//TODO - temporarily compatible with dual stack,
		// only vxlan backend and kube subnet manager support dual stack now.
		evt.Lease.EnableIPv4 = true
		evt.Lease.EnableIPv6 = false
		return LeaseWatchResult{
			Events: []Event{evt},
			Cursor: watchCursor{index},
		}, nil

	case isIndexTooSmall(err):
		log.Warning("Watch of subnet leases failed because etcd index outside history window")
		return m.leasesWatchReset(ctx)

	case index != 0:
		return LeaseWatchResult{Cursor: watchCursor{index}}, err

	default:
		return LeaseWatchResult{}, err
	}
}

func isIndexTooSmall(err error) bool {
	etcdErr, ok := err.(etcd.Error)
	return ok && etcdErr.Code == etcd.ErrorCodeEventIndexCleared
}

// leasesWatchReset is called when incremental lease watch failed and we need to grab a snapshot
func (m *LocalManager) leasesWatchReset(ctx context.Context) (LeaseWatchResult, error) {
	wr := LeaseWatchResult{}

	leases, index, err := m.registry.getSubnets(ctx)
	if err != nil {
		return wr, fmt.Errorf("failed to retrieve subnet leases: %v", err)
	}

	wr.Cursor = watchCursor{index}
	wr.Snapshot = leases
	return wr, nil
}

func isSubnetConfigCompat(config *Config, sn ip.IP4Net) bool {
	if sn.IP < config.SubnetMin || sn.IP > config.SubnetMax {
		return false
	}

	return sn.PrefixLen == config.SubnetLen
}

func (m *LocalManager) Name() string {
	previousSubnet := m.previousSubnet.String()
	if m.previousSubnet.Empty() {
		previousSubnet = "None"
	}
	return fmt.Sprintf("Etcd Local Manager with Previous Subnet: %s", previousSubnet)
}
