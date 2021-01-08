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
// +build !windows

package vxlan

import (
	"bytes"
	"encoding/json"
	"net"
	"sync"
	"time"

	log "github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"

	"syscall"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
)

type network struct {
	backend.SimpleNetwork
	dev       *vxlanDevice
	subnetMgr subnet.Manager

	directRoutes []netlink.Route
	GetRoute     func(lease *subnet.Lease) *netlink.Route
}

const (
	encapOverhead = 50
)

func newNetwork(subnetMgr subnet.Manager, extIface *backend.ExternalInterface, dev *vxlanDevice, _ ip.IP4Net, lease *subnet.Lease) (*network, error) {
	nw := &network{
		SimpleNetwork: backend.SimpleNetwork{
			SubnetLease: lease,
			ExtIface:    extIface,
		},
		subnetMgr: subnetMgr,
		dev:       dev,
	}

	nw.GetRoute = func(lease *subnet.Lease) *netlink.Route {
		return &netlink.Route{
			Dst: lease.Subnet.ToIPNet(),
			Gw:  lease.Attrs.PublicIP.ToIP(),
		}
	}

	return nw, nil
}

func (nw *network) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	log.V(0).Info("watching for new subnet leases")
	events := make(chan []subnet.Event)
	wg.Add(1)
	go func() {
		subnet.WatchLeases(ctx, nw.subnetMgr, nw.SubnetLease, events)
		log.V(1).Info("WatchLeases exited")
		wg.Done()
	}()

	nw.directRoutes = make([]netlink.Route, 0, 10)
	wg.Add(1)
	go func() {
		nw.directRouteCheck(ctx)
		wg.Done()
	}()

	defer wg.Wait()

	for {
		select {
		case evtBatch := <-events:
			nw.handleSubnetEvents(evtBatch)

		case <-ctx.Done():
			return
		}
	}
}

func (nw *network) MTU() int {
	return nw.ExtIface.Iface.MTU - encapOverhead
}

type vxlanLeaseAttrs struct {
	VNI     uint16
	VtepMAC hardwareAddr
}

func (nw *network) handleSubnetEvents(batch []subnet.Event) {
	for _, event := range batch {
		sn := event.Lease.Subnet
		attrs := event.Lease.Attrs
		if attrs.BackendType != "vxlan" {
			log.Warningf("ignoring non-vxlan subnet(%s): type=%v", sn, attrs.BackendType)
			continue
		}

		var vxlanAttrs vxlanLeaseAttrs
		if err := json.Unmarshal(attrs.BackendData, &vxlanAttrs); err != nil {
			log.Error("error decoding subnet lease JSON: ", err)
			continue
		}

		// This route is used when traffic should be vxlan encapsulated
		vxlanRoute := netlink.Route{
			LinkIndex: nw.dev.link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       sn.ToIPNet(),
			Gw:        sn.IP.ToIP(),
		}
		vxlanRoute.SetFlag(syscall.RTNH_F_ONLINK)

		// directRouting is where the remote host is on the same subnet so vxlan isn't required.
		directRoute := netlink.Route{
			Dst: sn.ToIPNet(),
			Gw:  attrs.PublicIP.ToIP(),
		}
		var directRoutingOK = false
		if nw.dev.directRouting {
			if dr, err := ip.DirectRouting(attrs.PublicIP.ToIP()); err != nil {
				log.Error(err)
			} else {
				directRoutingOK = dr
			}
		}

		switch event.Type {
		case subnet.EventAdded:
			if directRoutingOK {
				log.V(2).Infof("Adding direct route to subnet: %s PublicIP: %s", sn, attrs.PublicIP)

				route := nw.GetRoute(&event.Lease)
				nw.addToDirectRouteList(*route)

				if err := netlink.RouteReplace(&directRoute); err != nil {
					log.Errorf("Error adding route to %v via %v: %v", sn, attrs.PublicIP, err)
					continue
				}
			} else {
				log.V(2).Infof("adding subnet: %s PublicIP: %s VtepMAC: %s", sn, attrs.PublicIP, net.HardwareAddr(vxlanAttrs.VtepMAC))
				if err := nw.dev.AddARP(neighbor{IP: sn.IP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
					log.Error("AddARP failed: ", err)
					continue
				}

				if err := nw.dev.AddFDB(neighbor{IP: attrs.PublicIP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
					log.Error("AddFDB failed: ", err)

					// Try to clean up the ARP entry then continue
					if err := nw.dev.DelARP(neighbor{IP: event.Lease.Subnet.IP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
						log.Error("DelARP failed: ", err)
					}

					continue
				}

				// Set the route - the kernel would ARP for the Gw IP address if it hadn't already been set above so make sure
				// this is done last.
				if err := netlink.RouteReplace(&vxlanRoute); err != nil {
					log.Errorf("failed to add vxlanRoute (%s -> %s): %v", vxlanRoute.Dst, vxlanRoute.Gw, err)

					// Try to clean up both the ARP and FDB entries then continue
					if err := nw.dev.DelARP(neighbor{IP: event.Lease.Subnet.IP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
						log.Error("DelARP failed: ", err)
					}

					if err := nw.dev.DelFDB(neighbor{IP: event.Lease.Attrs.PublicIP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
						log.Error("DelFDB failed: ", err)
					}

					continue
				}
			}
		case subnet.EventRemoved:
			if directRoutingOK {
				log.V(2).Infof("Removing direct route to subnet: %s PublicIP: %s", sn, attrs.PublicIP)

				route := nw.GetRoute(&event.Lease)
				nw.removeFromDirectRouteList(*route)

				if err := netlink.RouteDel(&directRoute); err != nil {
					log.Errorf("Error deleting route to %v via %v: %v", sn, attrs.PublicIP, err)
				}
			} else {
				log.V(2).Infof("removing subnet: %s PublicIP: %s VtepMAC: %s", sn, attrs.PublicIP, net.HardwareAddr(vxlanAttrs.VtepMAC))

				// Try to remove all entries - don't bail out if one of them fails.
				if err := nw.dev.DelARP(neighbor{IP: sn.IP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
					log.Error("DelARP failed: ", err)
				}

				if err := nw.dev.DelFDB(neighbor{IP: attrs.PublicIP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
					log.Error("DelFDB failed: ", err)
				}

				if err := netlink.RouteDel(&vxlanRoute); err != nil {
					log.Errorf("failed to delete vxlanRoute (%s -> %s): %v", vxlanRoute.Dst, vxlanRoute.Gw, err)
				}
			}
		default:
			log.Error("internal error: unknown event type: ", int(event.Type))
		}
	}
}

func (nw *network) directRouteCheck(ctx context.Context) {
	for {
		const directRouteCheckRetries = 10
		select {
		case <-ctx.Done():
			return
		case <-time.After(directRouteCheckRetries * time.Second):
			nw.checkSubnetExistInDirectRoutes()
		}
	}
}

func (nw *network) checkSubnetExistInDirectRoutes() {
	routeList, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err == nil {
		for _, route := range nw.directRoutes {
			exist := false
			for _, r := range routeList {
				if r.Dst == nil {
					continue
				}
				if routeEqual(r, route) {
					exist = true
					break
				}
			}

			if !exist {
				if err := netlink.RouteAdd(&route); err != nil {
					if nerr, ok := err.(net.Error); !ok {
						log.Errorf("Error recovering route to %v: %v, %v", route.Dst, route.Gw, nerr)
					}
					continue
				} else {
					log.Infof("Route recovered %v : %v", route.Dst, route.Gw)
				}
			}
		}
	} else {
		log.Errorf("Error fetching route list. Will automatically retry: %v", err)
	}
}

func (nw *network) addToDirectRouteList(route netlink.Route) {
	for _, r := range nw.directRoutes {
		if routeEqual(r, route) {
			return
		}
	}
	nw.directRoutes = append(nw.directRoutes, route)
}

func (nw *network) removeFromDirectRouteList(route netlink.Route) {
	for index, r := range nw.directRoutes {
		if routeEqual(r, route) {
			nw.directRoutes = append(nw.directRoutes[:index], nw.directRoutes[index+1:]...)
			return
		}
	}
}

func routeEqual(x, y netlink.Route) bool {
	if x.Dst.IP.Equal(y.Dst.IP) && x.Gw.Equal(y.Gw) && bytes.Equal(x.Dst.Mask, y.Dst.Mask) && x.LinkIndex == y.LinkIndex {
		return true
	}
	return false
}
