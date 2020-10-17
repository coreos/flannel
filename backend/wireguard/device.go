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
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/flannel/pkg/ip"
	log "github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wgDeviceAttrs struct {
	listenPort int
	privateKey *wgtypes.Key
	publicKey  *wgtypes.Key
	psk        *wgtypes.Key
	keepalive  *time.Duration
	deviceName string
}

type wgDevice struct {
	link   *netlink.GenericLink
	client *wgctrl.Client
}

func setupKeys(devAttrs *wgDeviceAttrs, psk string) error {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("could not generate private key: %v", err)
	}
	devAttrs.privateKey = &privateKey

	publicKey := privateKey.PublicKey()
	devAttrs.publicKey = &publicKey

	if psk != "" {
		presharedKey, err := wgtypes.ParseKey(psk)
		if err != nil {
			return fmt.Errorf("could not parse psk: %v", err)
		}
		devAttrs.psk = &presharedKey
	}

	return nil
}

func newWGDevice(devAttrs *wgDeviceAttrs, ctx context.Context, wg *sync.WaitGroup) (*wgDevice, error) {
	la := netlink.LinkAttrs{
		Name: devAttrs.deviceName,
	}
	link := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}

	link, err := ensureLink(link)
	if err != nil {
		return nil, err
	}

	dev := wgDevice{
		link: link,
	}

	// housekeeping
	wg.Add(1)
	go func() {
		select {
		case <-ctx.Done():
			dev.remove()
			log.Infof("Stopped wireguard")
			wg.Done()
		}
	}()

	return &dev, nil
}

func ensureLink(wglan *netlink.GenericLink) (*netlink.GenericLink, error) {
	err := netlink.LinkAdd(wglan)
	if err == syscall.EEXIST {
		existing, err := netlink.LinkByName(wglan.Name)
		if err != nil {
			return nil, err
		}

		log.Warningf("%q already exists; recreating device", wglan.Name)
		err = netlink.LinkDel(existing)
		if err != nil {
			return nil, err
		}

		err = netlink.LinkAdd(wglan)
		if err != nil {
			return nil, fmt.Errorf("could not create wireguard interface:  %v", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("could not create wireguard interface:  %v", err)
	}

	_, err = netlink.LinkByIndex(wglan.Index)
	if err != nil {
		return nil, fmt.Errorf("can't locate created wireguard device with index %v", wglan.Index)
	}

	return wglan, nil
}

func (dev *wgDevice) remove() error {
	dev.client.Close()
	err := netlink.LinkDel(dev.link)
	if err != nil {
		return fmt.Errorf("could not remove wireguard device: %v", err)
	}
	return nil
}

func (dev *wgDevice) Configure(devAttrs *wgDeviceAttrs, devIP ip.IP4, dst *net.IPNet) error {
	cfg := wgtypes.Config{
		PrivateKey:   devAttrs.privateKey,
		ListenPort:   &devAttrs.listenPort,
		ReplacePeers: true,
	}

	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl: %v", err)
	}
	dev.client = c

	err = dev.client.ConfigureDevice(devAttrs.deviceName, cfg)
	if err != nil {
		return fmt.Errorf("failed to configure device %v", err)
	}

	net := ip.IP4Net{IP: devIP, PrefixLen: 32}
	err = ip.EnsureV4AddressOnLink(net, dev.link)
	if err != nil {
		return fmt.Errorf("failed to ensure address of interface %s: %s", dev.link.Attrs().Name, err)
	}

	err = netlink.LinkSetUp(dev.link)
	if err != nil {
		return fmt.Errorf("failed to set interface %s to UP state: %s", dev.link.Attrs().Name, err)
	}

	route := netlink.Route{
		LinkIndex: dev.link.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       dst,
	}
	err = netlink.RouteAdd(&route)
	if err != nil {
		return fmt.Errorf("failed to add route %s: %s", dev.link.Attrs().Name, err)
	}

	return nil
}

func (dev *wgDevice) addPeer(devAttrs *wgDeviceAttrs, publicIP string, data string, subnet *ip.IP4Net) error {
	publicKey, err := wgtypes.ParseKey(data)
	if err != nil {
		return fmt.Errorf("failed to parse publicKey: %v", err)
	}

	publicEndpoint := fmt.Sprintf("%s:%d", publicIP, devAttrs.listenPort)
	udpEndpoint, err := net.ResolveUDPAddr("udp", publicEndpoint)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	allowedIP := subnet.ToIPNet()

	wgcfg := wgtypes.Config{
		PrivateKey:   devAttrs.privateKey,
		ListenPort:   &devAttrs.listenPort,
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:                   publicKey,
				PresharedKey:                devAttrs.psk,
				PersistentKeepaliveInterval: devAttrs.keepalive,
				Endpoint:                    udpEndpoint,
				ReplaceAllowedIPs:           true,
				AllowedIPs: []net.IPNet{
					*allowedIP,
				},
			},
		}}

	err = dev.client.ConfigureDevice(devAttrs.deviceName, wgcfg)
	if err != nil {
		return fmt.Errorf("failed to add peer %v", err)
	}

	// Remove peers with outdated PublicKeys for this endpoint
	dev.cleanupPeers(devAttrs, udpEndpoint, data)

	return nil
}

func (dev *wgDevice) cleanupPeers(devAttrs *wgDeviceAttrs, udpEndpoint *net.UDPAddr, publicKey string) error {
	currentDev, err := dev.client.Device(devAttrs.deviceName)
	if err != nil {
		return fmt.Errorf("failed to open device: %v", err)
	}

	peers := []wgtypes.PeerConfig{}
	for _, peer := range currentDev.Peers {
		if peer.Endpoint.IP.Equal(udpEndpoint.IP) {
			if peer.PublicKey.String() != publicKey {
				removePeer := wgtypes.PeerConfig{
					PublicKey: peer.PublicKey,
					Remove:    true,
				}
				peers = append(peers, removePeer)
			}
		}
	}

	wgcfg := wgtypes.Config{
		PrivateKey:   devAttrs.privateKey,
		ListenPort:   &devAttrs.listenPort,
		ReplacePeers: false,
		Peers:        peers,
	}

	err = dev.client.ConfigureDevice(devAttrs.deviceName, wgcfg)
	if err != nil {
		return fmt.Errorf("failed to cleanup peers %v", err)
	}

	return nil
}

func (dev *wgDevice) removePeer(devAttrs *wgDeviceAttrs, data string) error {
	publicKey, err := wgtypes.ParseKey(data)
	if err != nil {
		return fmt.Errorf("failed to parse publicKey: %v", err)
	}

	wgcfg := wgtypes.Config{
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: publicKey,
				Remove:    true,
			},
		}}

	err = dev.client.ConfigureDevice(devAttrs.deviceName, wgcfg)
	if err != nil {
		return fmt.Errorf("failed to remove peer %v", err)
	}
	return nil
}
