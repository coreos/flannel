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

package main

import (
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/pkg/flagutil"
	"golang.org/x/net/context"

	"github.com/coreos/flannel/network"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	"github.com/coreos/flannel/subnet/etcdv2"
	"github.com/coreos/flannel/subnet/kube"
	"github.com/coreos/flannel/version"
	log "k8s.io/klog"

	"github.com/joho/godotenv"

	// Backends need to be imported for their init() to get executed and them to register
	"github.com/coreos/flannel/backend"
	_ "github.com/coreos/flannel/backend/alivpc"
	_ "github.com/coreos/flannel/backend/alloc"
	_ "github.com/coreos/flannel/backend/awsvpc"
	_ "github.com/coreos/flannel/backend/extension"
	_ "github.com/coreos/flannel/backend/gce"
	_ "github.com/coreos/flannel/backend/hostgw"
	_ "github.com/coreos/flannel/backend/ipip"
	_ "github.com/coreos/flannel/backend/ipsec"
	_ "github.com/coreos/flannel/backend/udp"
	_ "github.com/coreos/flannel/backend/vxlan"
	"github.com/coreos/go-systemd/daemon"
)

type flagSlice []string

func (t *flagSlice) String() string {
	return fmt.Sprintf("%v", *t)
}

func (t *flagSlice) Set(val string) error {
	*t = append(*t, val)
	return nil
}

type CmdLineOpts struct {
	etcdEndpoints          string
	etcdPrefix             string
	etcdKeyfile            string
	etcdCertfile           string
	etcdCAFile             string
	etcdUsername           string
	etcdPassword           string
	help                   bool
	version                bool
	autoDetectIPv4         bool
	autoDetectIPv6         bool
	kubeSubnetMgr          bool
	kubeApiUrl             string
	kubeAnnotationPrefix   string
	kubeConfigFile         string
	iface                  flagSlice
	ifaceRegex             flagSlice
	ipMasq                 bool
	subnetFile             string
	subnetDir              string
	publicIP               string
	publicIPv6             string
	subnetLeaseRenewMargin int
	healthzIP              string
	healthzPort            int
	charonExecutablePath   string
	charonViciUri          string
	iptablesResyncSeconds  int
	iptablesForwardRules   bool
	netConfPath            string
}

var (
	opts           CmdLineOpts
	errInterrupted = errors.New("interrupted")
	errCanceled    = errors.New("canceled")
	flannelFlags   = flag.NewFlagSet("flannel", flag.ExitOnError)
)

const (
	ipv4Stack int = iota
	ipv6Stack
	dualStack
	noneStack
)

func init() {
	flannelFlags.StringVar(&opts.etcdEndpoints, "etcd-endpoints", "http://127.0.0.1:4001,http://127.0.0.1:2379", "a comma-delimited list of etcd endpoints")
	flannelFlags.StringVar(&opts.etcdPrefix, "etcd-prefix", "/coreos.com/network", "etcd prefix")
	flannelFlags.StringVar(&opts.etcdKeyfile, "etcd-keyfile", "", "SSL key file used to secure etcd communication")
	flannelFlags.StringVar(&opts.etcdCertfile, "etcd-certfile", "", "SSL certification file used to secure etcd communication")
	flannelFlags.StringVar(&opts.etcdCAFile, "etcd-cafile", "", "SSL Certificate Authority file used to secure etcd communication")
	flannelFlags.StringVar(&opts.etcdUsername, "etcd-username", "", "username for BasicAuth to etcd")
	flannelFlags.StringVar(&opts.etcdPassword, "etcd-password", "", "password for BasicAuth to etcd")
	flannelFlags.Var(&opts.iface, "iface", "interface to use (IP or name) for inter-host communication. Can be specified multiple times to check each option in order. Returns the first match found.")
	flannelFlags.Var(&opts.ifaceRegex, "iface-regex", "regex expression to match the first interface to use (IP or name) for inter-host communication. Can be specified multiple times to check each regex in order. Returns the first match found. Regexes are checked after specific interfaces specified by the iface option have already been checked.")
	flannelFlags.StringVar(&opts.subnetFile, "subnet-file", "/run/flannel/subnet.env", "filename where env variables (subnet, MTU, ... ) will be written to")
	flannelFlags.StringVar(&opts.publicIP, "public-ip", "", "IP accessible by other nodes for inter-host communication")
	flannelFlags.StringVar(&opts.publicIPv6, "public-ipv6", "", "IPv6 accessible by other nodes for inter-host communication")
	flannelFlags.IntVar(&opts.subnetLeaseRenewMargin, "subnet-lease-renew-margin", 60, "subnet lease renewal margin, in minutes, ranging from 1 to 1439")
	flannelFlags.BoolVar(&opts.ipMasq, "ip-masq", false, "setup IP masquerade rule for traffic destined outside of overlay network")
	flannelFlags.BoolVar(&opts.autoDetectIPv4, "auto-detect-ipv4", true, "auto detect ipv4 address of the iface")
	flannelFlags.BoolVar(&opts.autoDetectIPv6, "auto-detect-ipv6", false, "auto detect ipv6 address of the iface")
	flannelFlags.BoolVar(&opts.kubeSubnetMgr, "kube-subnet-mgr", false, "contact the Kubernetes API for subnet assignment instead of etcd.")
	flannelFlags.StringVar(&opts.kubeApiUrl, "kube-api-url", "", "Kubernetes API server URL. Does not need to be specified if flannel is running in a pod.")
	flannelFlags.StringVar(&opts.kubeAnnotationPrefix, "kube-annotation-prefix", "flannel.alpha.coreos.com", `Kubernetes annotation prefix. Can contain single slash "/", otherwise it will be appended at the end.`)
	flannelFlags.StringVar(&opts.kubeConfigFile, "kubeconfig-file", "", "kubeconfig file location. Does not need to be specified if flannel is running in a pod.")
	flannelFlags.BoolVar(&opts.version, "version", false, "print version and exit")
	flannelFlags.StringVar(&opts.healthzIP, "healthz-ip", "0.0.0.0", "the IP address for healthz server to listen")
	flannelFlags.IntVar(&opts.healthzPort, "healthz-port", 0, "the port for healthz server to listen(0 to disable)")
	flannelFlags.IntVar(&opts.iptablesResyncSeconds, "iptables-resync", 5, "resync period for iptables rules, in seconds")
	flannelFlags.BoolVar(&opts.iptablesForwardRules, "iptables-forward-rules", true, "add default accept rules to FORWARD chain in iptables")
	flannelFlags.StringVar(&opts.netConfPath, "net-config-path", "/etc/kube-flannel/net-conf.json", "path to the network configuration file")

	log.InitFlags(nil)

	// klog will log to tmp files by default. override so all entries
	// can flow into journald (if running under systemd)
	flag.Set("logtostderr", "true")

	// Only copy the non file logging options from klog
	copyFlag("v")
	copyFlag("vmodule")
	copyFlag("log_backtrace_at")

	// Define the usage function
	flannelFlags.Usage = usage

	// now parse command line args
	flannelFlags.Parse(os.Args[1:])
}

func copyFlag(name string) {
	flannelFlags.Var(flag.Lookup(name).Value, flag.Lookup(name).Name, flag.Lookup(name).Usage)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]...\n", os.Args[0])
	flannelFlags.PrintDefaults()
	os.Exit(0)
}

func getIPFamily(autoDetectIPv4, autoDetectIPv6 bool) (int, error) {
	if autoDetectIPv4 && !autoDetectIPv6 {
		return ipv4Stack, nil
	} else if !autoDetectIPv4 && autoDetectIPv6 {
		return ipv6Stack, nil
	} else if autoDetectIPv4 && autoDetectIPv6 {
		return dualStack, nil
	}
	return noneStack, errors.New("none defined stack")
}

func newSubnetManager(ctx context.Context) (subnet.Manager, error) {
	if opts.kubeSubnetMgr {
		return kube.NewSubnetManager(ctx, opts.kubeApiUrl, opts.kubeConfigFile, opts.kubeAnnotationPrefix, opts.netConfPath)
	}

	cfg := &etcdv2.EtcdConfig{
		Endpoints: strings.Split(opts.etcdEndpoints, ","),
		Keyfile:   opts.etcdKeyfile,
		Certfile:  opts.etcdCertfile,
		CAFile:    opts.etcdCAFile,
		Prefix:    opts.etcdPrefix,
		Username:  opts.etcdUsername,
		Password:  opts.etcdPassword,
	}

	// Attempt to renew the lease for the subnet specified in the subnetFile
	prevSubnet := ReadCIDRFromSubnetFile(opts.subnetFile, "FLANNEL_SUBNET")

	return etcdv2.NewLocalManager(cfg, prevSubnet)
}

func main() {
	if opts.version {
		fmt.Fprintln(os.Stderr, version.Version)
		os.Exit(0)
	}

	flagutil.SetFlagsFromEnv(flannelFlags, "FLANNELD")

	// Validate flags
	if opts.subnetLeaseRenewMargin >= 24*60 || opts.subnetLeaseRenewMargin <= 0 {
		log.Error("Invalid subnet-lease-renew-margin option, out of acceptable range")
		os.Exit(1)
	}

	// Get ip family stack
	ipStack, stackErr := getIPFamily(opts.autoDetectIPv4, opts.autoDetectIPv6)
	if stackErr != nil {
		log.Error(stackErr.Error())
		os.Exit(1)
	}
	// Work out which interface to use
	var extIface *backend.ExternalInterface
	var err error
	// Check the default interface only if no interfaces are specified
	if len(opts.iface) == 0 && len(opts.ifaceRegex) == 0 {
		extIface, err = LookupExtIface(opts.publicIP, "", ipStack)
		if err != nil {
			log.Error("Failed to find any valid interface to use: ", err)
			os.Exit(1)
		}
	} else {
		// Check explicitly specified interfaces
		for _, iface := range opts.iface {
			extIface, err = LookupExtIface(iface, "", ipStack)
			if err != nil {
				log.Infof("Could not find valid interface matching %s: %s", iface, err)
			}

			if extIface != nil {
				break
			}
		}

		// Check interfaces that match any specified regexes
		if extIface == nil {
			for _, ifaceRegex := range opts.ifaceRegex {
				extIface, err = LookupExtIface("", ifaceRegex, ipStack)
				if err != nil {
					log.Infof("Could not find valid interface matching %s: %s", ifaceRegex, err)
				}

				if extIface != nil {
					break
				}
			}
		}

		if extIface == nil {
			// Exit if any of the specified interfaces do not match
			log.Error("Failed to find interface to use that matches the interfaces and/or regexes provided")
			os.Exit(1)
		}
	}

	// This is the main context that everything should run in.
	// All spawned goroutines should exit when cancel is called on this context.
	// Go routines spawned from main.go coordinate using a WaitGroup. This provides a mechanism to allow the shutdownHandler goroutine
	// to block until all the goroutines return . If those goroutines spawn other goroutines then they are responsible for
	// blocking and returning only when cancel() is called.
	ctx, cancel := context.WithCancel(context.Background())

	sm, err := newSubnetManager(ctx)
	if err != nil {
		log.Error("Failed to create SubnetManager: ", err)
		os.Exit(1)
	}
	log.Infof("Created subnet manager: %s", sm.Name())

	// Register for SIGINT and SIGTERM
	log.Info("Installing signal handlers")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		shutdownHandler(ctx, sigs, cancel)
		wg.Done()
	}()

	if opts.healthzPort > 0 {
		// It's not super easy to shutdown the HTTP server so don't attempt to stop it cleanly
		go mustRunHealthz()
	}

	// Fetch the network config (i.e. what backend to use etc..).
	config, err := getConfig(ctx, sm)
	if err == errCanceled {
		wg.Wait()
		os.Exit(0)
	}

	// Create a backend manager then use it to create the backend and register the network with it.
	bm := backend.NewManager(ctx, sm, extIface)
	be, err := bm.GetBackend(config.BackendType)
	if err != nil {
		log.Errorf("Error fetching backend: %s", err)
		cancel()
		wg.Wait()
		os.Exit(1)
	}

	bn, err := be.RegisterNetwork(ctx, &wg, config)
	if err != nil {
		log.Errorf("Error registering network: %s", err)
		cancel()
		wg.Wait()
		os.Exit(1)
	}

	// Set up ipMasq if needed
	if opts.ipMasq {
		if config.EnableIPv4 {
			if err = recycleIPTables(config.Network, bn.Lease()); err != nil {
				log.Errorf("Failed to recycle IPTables rules, %v", err)
				cancel()
				wg.Wait()
				os.Exit(1)
			}
			log.Infof("Setting up masking rules")
			go network.SetupAndEnsureIPTables(network.MasqRules(config.Network, bn.Lease()), opts.iptablesResyncSeconds)

		}
		if config.EnableIPv6 {
			if err = recycleIP6Tables(config.IPv6Network, bn.Lease()); err != nil {
				log.Errorf("Failed to recycle IP6Tables rules, %v", err)
				cancel()
				wg.Wait()
				os.Exit(1)
			}
			log.Infof("Setting up masking ip6 rules")
			go network.SetupAndEnsureIP6Tables(network.MasqIP6Rules(config.IPv6Network, bn.Lease()), opts.iptablesResyncSeconds)
		}
	}

	// Always enables forwarding rules. This is needed for Docker versions >1.13 (https://docs.docker.com/engine/userguide/networking/default_network/container-communication/#container-communication-between-hosts)
	// In Docker 1.12 and earlier, the default FORWARD chain policy was ACCEPT.
	// In Docker 1.13 and later, Docker sets the default policy of the FORWARD chain to DROP.
	if opts.iptablesForwardRules {
		if config.EnableIPv4 {
			log.Infof("Changing default FORWARD chain policy to ACCEPT")
			go network.SetupAndEnsureIPTables(network.ForwardRules(config.Network.String()), opts.iptablesResyncSeconds)
		}
		if config.EnableIPv6 {
			log.Infof("IPv6: Changing default FORWARD chain policy to ACCEPT")
			go network.SetupAndEnsureIP6Tables(network.ForwardRules(config.IPv6Network.String()), opts.iptablesResyncSeconds)
		}
	}

	if err := WriteSubnetFile(opts.subnetFile, config, opts.ipMasq, bn); err != nil {
		// Continue, even though it failed.
		log.Warningf("Failed to write subnet file: %s", err)
	} else {
		log.Infof("Wrote subnet file to %s", opts.subnetFile)
	}

	// Start "Running" the backend network. This will block until the context is done so run in another goroutine.
	log.Info("Running backend.")
	wg.Add(1)
	go func() {
		bn.Run(ctx)
		wg.Done()
	}()

	daemon.SdNotify(false, "READY=1")

	// Kube subnet mgr doesn't lease the subnet for this node - it just uses the podCidr that's already assigned.
	if !opts.kubeSubnetMgr {
		err = MonitorLease(ctx, sm, bn, &wg)
		if err == errInterrupted {
			// The lease was "revoked" - shut everything down
			cancel()
		}
	}

	log.Info("Waiting for all goroutines to exit")
	// Block waiting for all the goroutines to finish.
	wg.Wait()
	log.Info("Exiting cleanly...")
	os.Exit(0)
}

func recycleIPTables(nw ip.IP4Net, lease *subnet.Lease) error {
	prevNetwork := ReadCIDRFromSubnetFile(opts.subnetFile, "FLANNEL_NETWORK")
	prevSubnet := ReadCIDRFromSubnetFile(opts.subnetFile, "FLANNEL_SUBNET")
	// recycle iptables rules only when network configured or subnet leased is not equal to current one.
	if prevNetwork != nw && prevSubnet != lease.Subnet {
		log.Infof("Current network or subnet (%v, %v) is not equal to previous one (%v, %v), trying to recycle old iptables rules", nw, lease.Subnet, prevNetwork, prevSubnet)
		lease := &subnet.Lease{
			Subnet: prevSubnet,
		}
		if err := network.DeleteIPTables(network.MasqRules(prevNetwork, lease)); err != nil {
			return err
		}
	}
	return nil
}

func recycleIP6Tables(nw ip.IP6Net, lease *subnet.Lease) error {
	prevNetwork := ReadIP6CIDRFromSubnetFile(opts.subnetFile, "FLANNEL_IPV6_NETWORK")
	prevSubnet := ReadIP6CIDRFromSubnetFile(opts.subnetFile, "FLANNEL_IPV6_SUBNET")
	// recycle iptables rules only when network configured or subnet leased is not equal to current one.
	if prevNetwork.String() != nw.String() && prevSubnet.String() != lease.IPv6Subnet.String() {
		log.Infof("Current ipv6 network or subnet (%v, %v) is not equal to previous one (%v, %v), trying to recycle old ip6tables rules", nw, lease.IPv6Subnet, prevNetwork, prevSubnet)
		lease := &subnet.Lease{
			IPv6Subnet: prevSubnet,
		}
		if err := network.DeleteIP6Tables(network.MasqIP6Rules(prevNetwork, lease)); err != nil {
			return err
		}
	}
	return nil
}

func shutdownHandler(ctx context.Context, sigs chan os.Signal, cancel context.CancelFunc) {
	// Wait for the context do be Done or for the signal to come in to shutdown.
	select {
	case <-ctx.Done():
		log.Info("Stopping shutdownHandler...")
	case <-sigs:
		// Call cancel on the context to close everything down.
		cancel()
		log.Info("shutdownHandler sent cancel signal...")
	}

	// Unregister to get default OS nuke behaviour in case we don't exit cleanly
	signal.Stop(sigs)
}

func getConfig(ctx context.Context, sm subnet.Manager) (*subnet.Config, error) {
	// Retry every second until it succeeds
	for {
		config, err := sm.GetNetworkConfig(ctx)
		if err != nil {
			log.Errorf("Couldn't fetch network config: %s", err)
		} else if config == nil {
			log.Warningf("Couldn't find network config: %s", err)
		} else {
			log.Infof("Found network config - Backend type: %s", config.BackendType)
			return config, nil
		}
		select {
		case <-ctx.Done():
			return nil, errCanceled
		case <-time.After(1 * time.Second):
			fmt.Println("timed out")
		}
	}
}

func MonitorLease(ctx context.Context, sm subnet.Manager, bn backend.Network, wg *sync.WaitGroup) error {
	// Use the subnet manager to start watching leases.
	evts := make(chan subnet.Event)

	wg.Add(1)
	go func() {
		subnet.WatchLease(ctx, sm, bn.Lease().Subnet, evts)
		wg.Done()
	}()

	renewMargin := time.Duration(opts.subnetLeaseRenewMargin) * time.Minute
	dur := bn.Lease().Expiration.Sub(time.Now()) - renewMargin

	for {
		select {
		case <-time.After(dur):
			err := sm.RenewLease(ctx, bn.Lease())
			if err != nil {
				log.Error("Error renewing lease (trying again in 1 min): ", err)
				dur = time.Minute
				continue
			}

			log.Info("Lease renewed, new expiration: ", bn.Lease().Expiration)
			dur = bn.Lease().Expiration.Sub(time.Now()) - renewMargin

		case e := <-evts:
			switch e.Type {
			case subnet.EventAdded:
				bn.Lease().Expiration = e.Lease.Expiration
				dur = bn.Lease().Expiration.Sub(time.Now()) - renewMargin
				log.Infof("Waiting for %s to renew lease", dur)

			case subnet.EventRemoved:
				log.Error("Lease has been revoked. Shutting down daemon.")
				return errInterrupted
			}

		case <-ctx.Done():
			log.Infof("Stopped monitoring lease")
			return errCanceled
		}
	}
}

func LookupExtIface(ifname string, ifregex string, ipStack int) (*backend.ExternalInterface, error) {
	var iface *net.Interface
	var ifaceAddr net.IP
	var ifaceV6Addr net.IP
	var err error

	// Check ip family stack
	if ipStack == noneStack {
		return nil, fmt.Errorf("none matched ip stack")
	}

	if len(ifname) > 0 {
		if ifaceAddr = net.ParseIP(ifname); ifaceAddr != nil {
			log.Infof("Searching for interface using %s", ifaceAddr)
			switch ipStack {
			case ipv4Stack:
				iface, err = ip.GetInterfaceByIP(ifaceAddr)
				if err != nil {
					return nil, fmt.Errorf("error looking up interface %s: %s", ifname, err)
				}
			case ipv6Stack:
				iface, err = ip.GetInterfaceByIP6(ifaceAddr)
				if err != nil {
					return nil, fmt.Errorf("error looking up v6 interface %s: %s", ifname, err)
				}
			case dualStack:
				iface, err = ip.GetInterfaceByIP(ifaceAddr)
				if err != nil {
					return nil, fmt.Errorf("error looking up interface %s: %s", ifname, err)
				}
				v6Iface, err := ip.GetInterfaceByIP6(ifaceAddr)
				if err != nil {
					return nil, fmt.Errorf("error looking up v6 interface %s: %s", ifname, err)
				}
				if iface.Name != v6Iface.Name {
					return nil, fmt.Errorf("v6 interface %s must be the same with v4 interface %s", v6Iface.Name, iface.Name)
				}
			}
		} else {
			iface, err = net.InterfaceByName(ifname)
			if err != nil {
				return nil, fmt.Errorf("error looking up interface %s: %s", ifname, err)
			}
		}
	} else if len(ifregex) > 0 {
		// Use the regex if specified and the iface option for matching a specific ip or name is not used
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("error listing all interfaces: %s", err)
		}

		// Check IP
		for _, ifaceToMatch := range ifaces {
			switch ipStack {
			case ipv4Stack:
				ifaceIP, err := ip.GetInterfaceIP4Addr(&ifaceToMatch)
				if err != nil {
					// Skip if there is no IPv4 address
					continue
				}

				matched, err := regexp.MatchString(ifregex, ifaceIP.String())
				if err != nil {
					return nil, fmt.Errorf("regex error matching pattern %s to %s", ifregex, ifaceIP.String())
				}

				if matched {
					ifaceAddr = ifaceIP
					iface = &ifaceToMatch
					break
				}
			case ipv6Stack:
				ifaceIP, err := ip.GetInterfaceIP6Addr(&ifaceToMatch)
				if err != nil {
					// Skip if there is no IPv6 address
					continue
				}

				matched, err := regexp.MatchString(ifregex, ifaceIP.String())
				if err != nil {
					return nil, fmt.Errorf("regex error matching pattern %s to %s", ifregex, ifaceIP.String())
				}

				if matched {
					ifaceV6Addr = ifaceIP
					iface = &ifaceToMatch
					break
				}
			case dualStack:
				ifaceIP, err := ip.GetInterfaceIP4Addr(&ifaceToMatch)
				if err != nil {
					// Skip if there is no IPv4 address
					continue
				}

				matched, err := regexp.MatchString(ifregex, ifaceIP.String())
				if err != nil {
					return nil, fmt.Errorf("regex error matching pattern %s to %s", ifregex, ifaceIP.String())
				}

				ifaceV6IP, err := ip.GetInterfaceIP6Addr(&ifaceToMatch)
				if err != nil {
					// Skip if there is no IPv6 address
					continue
				}

				v6Matched, err := regexp.MatchString(ifregex, ifaceV6IP.String())
				if err != nil {
					return nil, fmt.Errorf("regex error matching pattern %s to %s", ifregex, ifaceIP.String())
				}

				if matched && v6Matched {
					ifaceAddr = ifaceIP
					ifaceV6Addr = ifaceV6IP
					iface = &ifaceToMatch
					break
				}
			}
		}

		// Check Name
		if iface == nil && (ifaceAddr == nil || ifaceV6Addr == nil) {
			for _, ifaceToMatch := range ifaces {
				matched, err := regexp.MatchString(ifregex, ifaceToMatch.Name)
				if err != nil {
					return nil, fmt.Errorf("regex error matching pattern %s to %s", ifregex, ifaceToMatch.Name)
				}

				if matched {
					iface = &ifaceToMatch
					break
				}
			}
		}

		// Check that nothing was matched
		if iface == nil {
			var availableFaces []string
			for _, f := range ifaces {
				var ipaddr net.IP
				switch ipStack {
				case ipv4Stack, dualStack:
					ipaddr, _ = ip.GetInterfaceIP4Addr(&f) // We can safely ignore errors. We just won't log any ip
				case ipv6Stack:
					ipaddr, _ = ip.GetInterfaceIP6Addr(&f) // We can safely ignore errors. We just won't log any ip
				}
				availableFaces = append(availableFaces, fmt.Sprintf("%s:%s", f.Name, ipaddr))
			}

			return nil, fmt.Errorf("Could not match pattern %s to any of the available network interfaces (%s)", ifregex, strings.Join(availableFaces, ", "))
		}
	} else {
		log.Info("Determining IP address of default interface")
		switch ipStack {
		case ipv4Stack:
			if iface, err = ip.GetDefaultGatewayInterface(); err != nil {
				return nil, fmt.Errorf("failed to get default interface: %s", err)
			}
		case ipv6Stack:
			if iface, err = ip.GetDefaultV6GatewayInterface(); err != nil {
				return nil, fmt.Errorf("failed to get default v6 interface: %s", err)
			}
		case dualStack:
			if iface, err = ip.GetDefaultGatewayInterface(); err != nil {
				return nil, fmt.Errorf("failed to get default interface: %s", err)
			}
			v6Iface, err := ip.GetDefaultV6GatewayInterface()
			if err != nil {
				return nil, fmt.Errorf("failed to get default v6 interface: %s", err)
			}
			if iface.Name != v6Iface.Name {
				return nil, fmt.Errorf("v6 default route interface %s "+
					"must be the same with v4 default route interface %s", v6Iface.Name, iface.Name)
			}
		}
	}

	if ipStack == ipv4Stack && ifaceAddr == nil {
		ifaceAddr, err = ip.GetInterfaceIP4Addr(iface)
		if err != nil {
			return nil, fmt.Errorf("failed to find IPv4 address for interface %s", iface.Name)
		}
	} else if ipStack == ipv6Stack && ifaceV6Addr == nil {
		ifaceV6Addr, err = ip.GetInterfaceIP6Addr(iface)
		if err != nil {
			return nil, fmt.Errorf("failed to find IPv6 address for interface %s", iface.Name)
		}
	} else if ipStack == dualStack && ifaceAddr == nil && ifaceV6Addr == nil {
		ifaceAddr, err = ip.GetInterfaceIP4Addr(iface)
		if err != nil {
			return nil, fmt.Errorf("failed to find IPv4 address for interface %s", iface.Name)
		}
		ifaceV6Addr, err = ip.GetInterfaceIP6Addr(iface)
		if err != nil {
			return nil, fmt.Errorf("failed to find IPv6 address for interface %s", iface.Name)
		}
	}

	if ifaceAddr != nil {
		log.Infof("Using interface with name %s and address %s", iface.Name, ifaceAddr)
	}
	if ifaceV6Addr != nil {
		log.Infof("Using interface with name %s and v6 address %s", iface.Name, ifaceV6Addr)
	}

	if iface.MTU == 0 {
		return nil, fmt.Errorf("failed to determine MTU for %s interface", ifaceAddr)
	}

	var extAddr net.IP
	var extV6Addr net.IP

	if len(opts.publicIP) > 0 {
		extAddr = net.ParseIP(opts.publicIP)
		if extAddr == nil {
			return nil, fmt.Errorf("invalid public IP address: %s", opts.publicIP)
		}
		log.Infof("Using %s as external address", extAddr)
	}

	if extAddr == nil {
		log.Infof("Defaulting external address to interface address (%s)", ifaceAddr)
		extAddr = ifaceAddr
	}

	if len(opts.publicIPv6) > 0 {
		extV6Addr = net.ParseIP(opts.publicIPv6)
		if extV6Addr == nil {
			return nil, fmt.Errorf("invalid public IPv6 address: %s", opts.publicIPv6)
		}
		log.Infof("Using %s as external address", extV6Addr)
	}

	if extV6Addr == nil {
		log.Infof("Defaulting external v6 address to interface address (%s)", ifaceV6Addr)
		extV6Addr = ifaceV6Addr
	}

	return &backend.ExternalInterface{
		Iface:       iface,
		IfaceAddr:   ifaceAddr,
		IfaceV6Addr: ifaceV6Addr,
		ExtAddr:     extAddr,
		ExtV6Addr:   extV6Addr,
	}, nil
}

func WriteSubnetFile(path string, config *subnet.Config, ipMasq bool, bn backend.Network) error {
	dir, name := filepath.Split(path)
	os.MkdirAll(dir, 0755)
	tempFile := filepath.Join(dir, "."+name)
	f, err := os.Create(tempFile)
	if err != nil {
		return err
	}
	if config.EnableIPv4 {
		nw := config.Network
		// Write out the first usable IP by incrementing
		// sn.IP by one
		sn := bn.Lease().Subnet
		sn.IP += 1
		fmt.Fprintf(f, "FLANNEL_NETWORK=%s\n", nw)
		fmt.Fprintf(f, "FLANNEL_SUBNET=%s\n", sn)
	}
	if config.EnableIPv6 {
		ip6Nw := config.IPv6Network
		ip6Sn := bn.Lease().IPv6Subnet
		ip6Sn.IP = (*ip.IP6)(big.NewInt(0).Add((*big.Int)(ip6Sn.IP), big.NewInt(1)))
		fmt.Fprintf(f, "FLANNEL_IPV6_NETWORK=%s\n", ip6Nw)
		fmt.Fprintf(f, "FLANNEL_IPV6_SUBNET=%s\n", ip6Sn)
	}

	fmt.Fprintf(f, "FLANNEL_MTU=%d\n", bn.MTU())
	_, err = fmt.Fprintf(f, "FLANNEL_IPMASQ=%v\n", ipMasq)
	f.Close()
	if err != nil {
		return err
	}

	// rename(2) the temporary file to the desired location so that it becomes
	// atomically visible with the contents
	return os.Rename(tempFile, path)
	//TODO - is this safe? What if it's not on the same FS?
}

func mustRunHealthz() {
	address := net.JoinHostPort(opts.healthzIP, strconv.Itoa(opts.healthzPort))
	log.Infof("Start healthz server on %s", address)

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("flanneld is running"))
	})

	if err := http.ListenAndServe(address, nil); err != nil {
		log.Errorf("Start healthz server error. %v", err)
		panic(err)
	}
}

func ReadCIDRFromSubnetFile(path string, CIDRKey string) ip.IP4Net {
	var prevCIDR ip.IP4Net
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		prevSubnetVals, err := godotenv.Read(path)
		if err != nil {
			log.Errorf("Couldn't fetch previous %s from subnet file at %s: %s", CIDRKey, path, err)
		} else if prevCIDRString, ok := prevSubnetVals[CIDRKey]; ok {
			err = prevCIDR.UnmarshalJSON([]byte(prevCIDRString))
			if err != nil {
				log.Errorf("Couldn't parse previous %s from subnet file at %s: %s", CIDRKey, path, err)
			}
		}
	}
	return prevCIDR
}

func ReadIP6CIDRFromSubnetFile(path string, CIDRKey string) ip.IP6Net {
	var prevCIDR ip.IP6Net
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		prevSubnetVals, err := godotenv.Read(path)
		if err != nil {
			log.Errorf("Couldn't fetch previous %s from subnet file at %s: %s", CIDRKey, path, err)
		} else if prevCIDRString, ok := prevSubnetVals[CIDRKey]; ok {
			err = prevCIDR.UnmarshalJSON([]byte(prevCIDRString))
			if err != nil {
				log.Errorf("Couldn't parse previous %s from subnet file at %s: %s", CIDRKey, path, err)
			}
		}
	}
	return prevCIDR
}
