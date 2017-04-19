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
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/coreos/pkg/flagutil"
	log "github.com/golang/glog"
	"golang.org/x/net/context"

	"github.com/coreos/flannel/network"
	"github.com/coreos/flannel/subnet"
	"github.com/coreos/flannel/subnet/etcdv2"
	"github.com/coreos/flannel/subnet/kube"
	"github.com/coreos/flannel/version"

	// Backends need to be imported for their init() to get executed and them to register
	_ "github.com/coreos/flannel/backend/alivpc"
	_ "github.com/coreos/flannel/backend/alloc"
	_ "github.com/coreos/flannel/backend/awsvpc"
	_ "github.com/coreos/flannel/backend/gce"
	_ "github.com/coreos/flannel/backend/hostgw"
	_ "github.com/coreos/flannel/backend/udp"
	_ "github.com/coreos/flannel/backend/vxlan"
)

type CmdLineOpts struct {
	etcdEndpoints    string
	etcdPrefix       string
	etcdKeyfile      string
	etcdCertfile     string
	etcdCAFile       string
	etcdUsername     string
	etcdPassword     string
	help             bool
	version          bool
	kubeSubnetMgr    bool
	etcdDiscoverySRV string
}

var opts CmdLineOpts

func init() {
	flag.StringVar(&opts.etcdDiscoverySRV, "etcd-discovery-srv", "", "DNS domain to discover etcd nodes")
	flag.StringVar(&opts.etcdEndpoints, "etcd-endpoints", "http://127.0.0.1:4001,http://127.0.0.1:2379", "a comma-delimited list of etcd endpoints")
	flag.StringVar(&opts.etcdPrefix, "etcd-prefix", "/coreos.com/network", "etcd prefix")
	flag.StringVar(&opts.etcdKeyfile, "etcd-keyfile", "", "SSL key file used to secure etcd communication")
	flag.StringVar(&opts.etcdCertfile, "etcd-certfile", "", "SSL certification file used to secure etcd communication")
	flag.StringVar(&opts.etcdCAFile, "etcd-cafile", "", "SSL Certificate Authority file used to secure etcd communication")
	flag.StringVar(&opts.etcdUsername, "etcd-username", "", "Username for BasicAuth to etcd")
	flag.StringVar(&opts.etcdPassword, "etcd-password", "", "Password for BasicAuth to etcd")
	flag.BoolVar(&opts.kubeSubnetMgr, "kube-subnet-mgr", false, "Contact the Kubernetes API for subnet assignement instead of etcd or flannel-server.")
	flag.BoolVar(&opts.help, "help", false, "print this message")
	flag.BoolVar(&opts.version, "version", false, "print version and exit")
}

func newSubnetManager() (subnet.Manager, error) {
	if opts.kubeSubnetMgr {
		return kube.NewSubnetManager()
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

	return etcdv2.NewLocalManager(cfg)
}

func endpointsFromSRV(domain string) ([]string, error) {
	endpoints := make([]string, 0)

	// we lookup the version without ssl first to be consistent with etcd SRV discovery
	// https://coreos.com/etcd/docs/latest/clustering.html#dns-discovery
	_, addrs, err := net.LookupSRV("etcd-client", "tcp", domain)
	if err != nil {
		return nil, err
	}

	if len(addrs) > 0 {
		for _, addr := range addrs {
			endpoints = append(endpoints, fmt.Sprintf("http://%s:%d", addr.Target, addr.Port))
		}
		return endpoints, nil
	}

	_, addrs, err = net.LookupSRV("etcd-client-ssl", "tcp", domain)
	if err != nil {
		return nil, err
	}

	if len(addrs) > 0 {
		for _, addr := range addrs {
			endpoints = append(endpoints, fmt.Sprintf("https://%s:%d", addr.Target, addr.Port))
		}
		return endpoints, nil
	}

	return nil, errors.New("etcd SRV discovery failed: no SRV records were found")
}

func main() {
	// glog will log to tmp files by default. override so all entries
	// can flow into journald (if running under systemd)
	flag.Set("logtostderr", "true")

	// now parse command line args
	flag.Parse()

	if flag.NArg() > 0 || opts.help {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]...\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(0)
	}

	if opts.version {
		fmt.Fprintln(os.Stderr, version.Version)
		os.Exit(0)
	}

	flagutil.SetFlagsFromEnv(flag.CommandLine, "FLANNELD")

	endpoints := strings.Split(opts.etcdEndpoints, ",")
	domain := opts.etcdDiscoverySRV
	if domain != "" {
		log.Infof("etcd DNS discovery enabled on domain %s", domain)

		var err error
		endpoints, err = endpointsFromSRV(domain)
		if err != nil {
			log.Error("Failed to obtain etcd addresses: ", err)
			os.Exit(1)
		}
		log.Infof("%d etcd addresses discovered by DNS: %s",
			len(endpoints), strings.Join(endpoints, ", "))
	}

	sm, err := newSubnetManager(endpoints)
	if err != nil {
		log.Error("Failed to create SubnetManager: ", err)
		os.Exit(1)
	}

	// Register for SIGINT and SIGTERM
	log.Info("Installing signal handlers")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	var runFunc func(ctx context.Context)

	nm, err := network.NewNetworkManager(ctx, sm)
	if err != nil {
		log.Error("Failed to create NetworkManager: ", err)
		os.Exit(1)
	}

	runFunc = func(ctx context.Context) {
		nm.Run(ctx)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		runFunc(ctx)
		wg.Done()
	}()

	<-sigs
	// unregister to get default OS nuke behaviour in case we don't exit cleanly
	signal.Stop(sigs)

	log.Info("Exiting...")
	cancel()

	wg.Wait()
}
