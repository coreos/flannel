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
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/coreos/flannel/pkg/ip"
	. "github.com/coreos/flannel/subnet"
	"github.com/jonboulle/clockwork"
	"golang.org/x/net/context"
)

func newDummyRegistry() *MockSubnetRegistry {
	attrs := LeaseAttrs{
		PublicIP: ip.MustParseIP4("1.1.1.1"),
	}

	exp := time.Time{}

	subnets := []Lease{
		// leases within SubnetMin-SubnetMax range
		{true, false, ip.IP4Net{ip.MustParseIP4("10.3.1.0"), 24}, ip.IP6Net{}, attrs, exp, 10},
		{true, false, ip.IP4Net{ip.MustParseIP4("10.3.2.0"), 24}, ip.IP6Net{}, attrs, exp, 11},
		{true, false, ip.IP4Net{ip.MustParseIP4("10.3.4.0"), 24}, ip.IP6Net{}, attrs, exp, 12},
		{true, false, ip.IP4Net{ip.MustParseIP4("10.3.5.0"), 24}, ip.IP6Net{}, attrs, exp, 13},

		// hand created lease outside the range of subnetMin-SubnetMax for testing removal
		{true, false, ip.IP4Net{ip.MustParseIP4("10.3.31.0"), 24}, ip.IP6Net{}, attrs, exp, 13},
	}

	config := `{ "Network": "10.3.0.0/16", "SubnetMin": "10.3.1.0", "SubnetMax": "10.3.25.0" }`
	return NewMockRegistry(config, subnets)
}

func TestAcquireLease(t *testing.T) {
	msr := newDummyRegistry()
	sm := NewMockManager(msr)

	extIaddr, _ := ip.ParseIP4("1.2.3.4")
	attrs := LeaseAttrs{
		PublicIP: extIaddr,
	}

	l, err := sm.AcquireLease(context.Background(), &attrs)
	if err != nil {
		t.Fatal("AcquireLease failed: ", err)
	}

	if !inAllocatableRange(context.Background(), sm, l.Subnet) {
		t.Fatal("Subnet mismatch: expected 10.3.3.0/24, got: ", l.Subnet)
	}

	// Acquire again, should reuse
	l2, err := sm.AcquireLease(context.Background(), &attrs)
	if err != nil {
		t.Fatal("AcquireLease failed: ", err)
	}

	if !l.Subnet.Equal(l2.Subnet) {
		t.Fatalf("AcquireLease did not reuse subnet; expected %v, got %v", l.Subnet, l2.Subnet)
	}

	// Test if a previous subnet will be used
	msr2 := newDummyRegistry()
	prevSubnet := ip.IP4Net{ip.MustParseIP4("10.3.6.0"), 24}
	sm2 := NewMockManagerWithSubnet(msr2, prevSubnet)
	prev, err := sm2.AcquireLease(context.Background(), &attrs)
	if err != nil {
		t.Fatal("AcquireLease failed: ", err)
	}
	if !prev.Subnet.Equal(prevSubnet) {
		t.Fatalf("AcquireLease did not reuse subnet from previous run; expected %v, got %v", prevSubnet, prev.Subnet)
	}

	// Test that a previous subnet will not be used if it does not match the registry config
	msr3 := newDummyRegistry()
	invalidSubnet := ip.IP4Net{ip.MustParseIP4("10.4.1.0"), 24}
	sm3 := NewMockManagerWithSubnet(msr3, invalidSubnet)
	l3, err := sm3.AcquireLease(context.Background(), &attrs)
	if err != nil {
		t.Fatal("AcquireLease failed: ", err)
	}
	if l3.Subnet.Equal(invalidSubnet) {
		t.Fatalf("AcquireLease reused invalid subnet from previous run; reused %v", l3.Subnet)
	}
}

func TestConfigChanged(t *testing.T) {
	msr := newDummyRegistry()
	sm := NewMockManager(msr)

	extIaddr, _ := ip.ParseIP4("1.2.3.4")
	attrs := LeaseAttrs{
		PublicIP: extIaddr,
	}

	l, err := sm.AcquireLease(context.Background(), &attrs)
	if err != nil {
		t.Fatal("AcquireLease failed: ", err)
	}

	if !inAllocatableRange(context.Background(), sm, l.Subnet) {
		t.Fatal("Acquired subnet outside of valid range: ", l.Subnet)
	}

	// Change config
	config := `{ "Network": "10.4.0.0/16" }`
	msr.setConfig(config)

	// Acquire again, should not reuse
	if l, err = sm.AcquireLease(context.Background(), &attrs); err != nil {
		t.Fatal("AcquireLease failed: ", err)
	}

	if !inAllocatableRange(context.Background(), sm, l.Subnet) {
		t.Fatal("Acquired subnet outside of valid range: ", l.Subnet)
	}
}

func newIP4Net(ipaddr string, prefix uint) ip.IP4Net {
	a, err := ip.ParseIP4(ipaddr)
	if err != nil {
		panic("failed to parse ipaddr")
	}
	return ip.IP4Net{
		IP:        a,
		PrefixLen: prefix,
	}
}

func acquireLease(ctx context.Context, t *testing.T, sm Manager) *Lease {
	extIaddr, _ := ip.ParseIP4("1.2.3.4")
	attrs := LeaseAttrs{
		PublicIP: extIaddr,
	}

	l, err := sm.AcquireLease(ctx, &attrs)
	if err != nil {
		t.Fatal("AcquireLease failed: ", err)
	}

	return l
}

func TestWatchLeaseAdded(t *testing.T) {
	msr := newDummyRegistry()
	sm := NewMockManager(msr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l := acquireLease(ctx, t, sm)

	events := make(chan []Event)
	go WatchLeases(ctx, sm, l, events)

	evtBatch := <-events
	for _, evt := range evtBatch {
		if evt.Lease.Key() == l.Key() {
			t.Errorf("WatchLeases returned our own lease")
		}
	}

	expected := ip.IP4Net{
		IP:        ip.MustParseIP4("10.3.30.0"),
		PrefixLen: 24,
	}
	// Sanity check to make sure acquired lease is not this.
	// It shouldn't be as SubnetMin/SubnetMax in config is [10.3.1.0/24 to 10.3.25.0/24]
	if l.Subnet.Equal(expected) {
		t.Fatalf("Acquired lease conflicts with one about to create")
	}

	attrs := &LeaseAttrs{
		PublicIP: ip.MustParseIP4("1.1.1.1"),
	}
	_, err := msr.createSubnet(ctx, expected, attrs, 0)
	if err != nil {
		t.Fatalf("createSubnet filed: %v", err)
	}

	evtBatch = <-events

	if len(evtBatch) != 1 {
		t.Fatalf("WatchLeases produced wrong sized event batch: got %v, expected 1", len(evtBatch))
	}

	evt := evtBatch[0]

	if evt.Type != EventAdded {
		t.Fatalf("WatchLeases produced wrong event type")
	}

	actual := evt.Lease.Subnet
	if !actual.Equal(expected) {
		t.Errorf("WatchSubnet produced wrong subnet: expected %s, got %s", expected, actual)
	}
}

func TestWatchLeaseRemoved(t *testing.T) {
	msr := newDummyRegistry()
	sm := NewMockManager(msr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l := acquireLease(ctx, t, sm)

	events := make(chan []Event)
	go WatchLeases(ctx, sm, l, events)

	evtBatch := <-events

	for _, evt := range evtBatch {
		if evt.Lease.Key() == l.Key() {
			t.Errorf("WatchLeases returned our own lease")
		}
	}

	expected := ip.IP4Net{ip.MustParseIP4("10.3.31.0"), 24}
	// Sanity check to make sure acquired lease is not this.
	// It shouldn't be as SubnetMin/SubnetMax in config is [10.3.1.0/24 to 10.3.25.0/24]
	if l.Subnet.Equal(expected) {
		t.Fatalf("Acquired lease conflicts with one about to create")
	}

	msr.expireSubnet("_", expected)

	evtBatch = <-events
	if len(evtBatch) != 1 {
		t.Fatalf("WatchLeases produced wrong sized event batch: %#v", evtBatch)
	}

	evt := evtBatch[0]

	if evt.Type != EventRemoved {
		t.Fatalf("WatchLeases produced wrong event type")
	}

	actual := evt.Lease.Subnet
	if !actual.Equal(expected) {
		t.Errorf("WatchSubnet produced wrong subnet: expected %s, got %s", expected, actual)
	}
}

type leaseData struct {
	Dummy string
}

func TestRenewLease(t *testing.T) {
	msr := newDummyRegistry()
	sm := NewMockManager(msr)
	now := time.Now()
	fakeClock := clockwork.NewFakeClockAt(now)
	clock = fakeClock

	// Create LeaseAttrs
	extIaddr, _ := ip.ParseIP4("1.2.3.4")
	attrs := LeaseAttrs{
		PublicIP:    extIaddr,
		BackendType: "vxlan",
	}

	ld, err := json.Marshal(&leaseData{Dummy: "test string"})
	if err != nil {
		t.Fatalf("Failed to marshal leaseData: %v", err)
	}
	attrs.BackendData = json.RawMessage(ld)

	// Acquire lease
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l, err := sm.AcquireLease(ctx, &attrs)
	if err != nil {
		t.Fatal("AcquireLease failed: ", err)
	}

	now = now.Add(subnetTTL)

	fakeClock.Advance(24 * time.Hour)

	if err := sm.RenewLease(ctx, l); err != nil {
		t.Fatal("RenewLease failed: ", err)
	}

	// check that it's still good
	n, err := msr.getNetwork(ctx)
	if err != nil {
		t.Errorf("Failed to renew lease: could not get networks: %v", err)
	}

	for _, sn := range n.subnets {
		if sn.Subnet.Equal(l.Subnet) {
			expected := now.Add(subnetTTL)
			if !sn.Expiration.Equal(expected) {
				t.Errorf("Failed to renew lease: bad expiration; expected %v, got %v", expected, sn.Expiration)
			}
			if !reflect.DeepEqual(sn.Attrs, attrs) {
				t.Errorf("LeaseAttrs changed: was %#v, now %#v", attrs, sn.Attrs)
			}
			return
		}
	}

	t.Fatal("Failed to find acquired lease")
}

func inAllocatableRange(ctx context.Context, sm Manager, ipn ip.IP4Net) bool {
	cfg, err := sm.GetNetworkConfig(ctx)
	if err != nil {
		panic(err)
	}

	return ipn.IP >= cfg.SubnetMin || ipn.IP <= cfg.SubnetMax
}
