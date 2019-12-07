# Backends

Flannel may be paired with several different backends. Once set, the backend should not be changed at runtime.

VXLAN is the recommended choice. host-gw is recommended for more experienced users who want the performance improvement and whose infrastructure support it (typically it can't be used in cloud environments). UDP is suggested for debugging only or for very old kernels that don't support VXLAN.

AWS, GCE, and AliVPC are experimental and unsupported. Proceed at your own risk.

For more information on configuration options for cloud components, see:
* [AliCloud VPC Backend for Flannel][alicloud-vpc]
* [Amazon VPC Backend for Flannel][amazon-vpc]
* [GCE Backend for Flannel][gce-backend]

## Recommended backends

### VXLAN

Use in-kernel VXLAN to encapsulate the packets.

Type and options:
* `Type` (string): `vxlan`
* `VNI` (number): VXLAN Identifier (VNI) to be used. On Linux, defaults to 1. On Windows should be greater than or equal to 4096. 
* `Port` (number): UDP port to use for sending encapsulated packets. On Linux, defaults to kernel default, currently 8472, but on Windows, must be 4789.
* `GBP` (Boolean): Enable [VXLAN Group Based Policy](https://github.com/torvalds/linux/commit/3511494ce2f3d3b77544c79b87511a4ddb61dc89).  Defaults to `false`. GBP is not supported on Windows
* `DirectRouting` (Boolean): Enable direct routes (like `host-gw`) when the hosts are on the same subnet. VXLAN will only be used to encapsulate packets to hosts on different subnets. Defaults to `false`. DirectRouting is not supported on Windows.
* `MacPrefix` (String): Only use on Windows, set to the MAC prefix. Defaults to `0E-2A`.

### host-gw

Use host-gw to create IP routes to subnets via remote machine IPs. Requires direct layer2 connectivity between hosts running flannel.

host-gw provides good performance, with few dependencies, and easy set up.

Type:
* `Type` (string): `host-gw`

### UDP

Use UDP only for debugging if your network and kernel prevent you from using VXLAN or host-gw.

Type and options:
* `Type` (string): `udp`
* `Port` (number): UDP port to use for sending encapsulated packets. Defaults to 8285.

## Experimental backends

The following options are experimental and unsupported at this time.

### AliVPC

Use AliVPC to create IP routes in a [alicloud VPC route table](https://vpc.console.aliyun.com) when running in an AliCloud VPC. This mitigates the need to create a separate flannel interface.

Requirements:
* Running on an ECS instance that is in an AliCloud VPC.
* Permission require `accessid` and `keysecret`.
    * `Type` (string): `ali-vpc`
    * `AccessKeyID` (string): API access key ID. Can also be configured with environment ACCESS_KEY_ID.
    * `AccessKeySecret` (string): API access key secret. Can also be configured with environment ACCESS_KEY_SECRET.

Route Limits: AliCloud VPC limits the number of entries per route table to 50.

### Alloc

Alloc performs subnet allocation with no forwarding of data packets.

Type:
* `Type` (string): `alloc`

### AWS VPC

Recommended when running within an Amazon VPC, AWS VPC creates IP routes in an [Amazon VPC route table](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Route_Tables.html). Because AWS knows about the IP, it is possible to set up ELB to route directly to that container.

Requirements:
* Running on an EC2 instance that is in an Amazon VPC.
* Permissions required: `CreateRoute`, `DeleteRoute`,`DescribeRouteTables`, `ModifyNetworkInterfaceAttribute`, `DescribeInstances` (optional)

Type and options:
* `Type` (string): `aws-vpc`
* `RouteTableID` (string): [optional] The ID of the VPC route table to add routes to.
    * The route table must be in the same region as the EC2 instance that flannel is running on.
    * Flannel can automatically detect the ID of the route table if the optional `DescribeInstances` is granted to the EC2 instance.

Authentication is handled via either environment variables or the node's IAM role. If the node has insufficient privileges to modify the VPC routing table specified, ensure that appropriate `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_SECURITY_TOKEN` environment variables are set when running the `flanneld` process.

Route Limits: AWS [limits](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_Limits.html) the number of entries per route table to 50.

### GCE

Use the GCE backend When running on [Google Compute Engine Network](https://cloud.google.com/compute/docs/networking#networks). Instead of using encapsulation, GCE manipulates IP routes to achieve maximum performance. Because of this, a separate flannel interface is not created.

Requirements:
* [Enable IP forwarding for the instances](https://cloud.google.com/compute/docs/networking#canipforward).
* [Instance service account](https://cloud.google.com/compute/docs/authentication#using) with read-write compute permissions.

Type:
* `Type` (string): `gce`

Command to create a compute instance with the correct permissions and IP forwarding enabled:
```sh
  $ gcloud compute instances create INSTANCE --can-ip-forward --scopes compute-rw
```

Route Limits: GCE [limits](https://cloud.google.com/compute/docs/resource-quotas) the number of routes for every *project* to 100 by default.


[alicloud-vpc]: https://github.com/coreos/flannel/blob/master/Documentation/alicloud-vpc-backend.md
[amazon-vpc]: https://github.com/coreos/flannel/blob/master/Documentation/aws-vpc-backend.md
[gce-backend]: https://github.com/coreos/flannel/blob/master/Documentation/gce-backend.md


### IPIP

Use in-kernel IPIP to encapsulate the packets.

IPIP kind of tunnels is the simplest one. It has the lowest overhead, but can incapsulate only IPv4 unicast traffic, so you will not be able to setup OSPF, RIP or any other multicast-based protocol.

Type:
* `Type` (string): `ipip`
* `DirectRouting` (Boolean): Enable direct routes (like `host-gw`) when the hosts are on the same subnet. IPIP will only be used to encapsulate packets to hosts on different subnets. Defaults to `false`.

Note that there may exist two ipip tunnel device `tunl0` and `flannel.ipip`, this is expected and it's not a bug.
`tunl0` is automatically created per network namespace by ipip kernel module on modprobe ipip module. It is the namespace default IPIP device with attributes local=any and remote=any.
When receiving IPIP protocol packets, kernel will forward them to tunl0 as a fallback device if it can't find an option whose local/remote attribute matches their src/dst ip address more precisely.
`flannel.ipip` is created by flannel to achieve one to many ipip network.

### IPSec

Use in-kernel IPSec to encapsulate and encrypt the packets.

[Strongswan](https://www.strongswan.org) is used at the IKEv2 daemon. A single pre-shared key is used for the initial key exchange between hosts and then Strongswan ensures that keys are rotated at regular intervals. 

Type:
* `Type` (string): `ipsec`
* `PSK` (string): Required. The pre shared key to use. It needs to be at least 96 characters long. One method for generating this key is to run `dd if=/dev/urandom count=48 bs=1 status=none | xxd -p -c 48`
* `UDPEncap` (Boolean): Optional, defaults to false. Forces the use UDP encapsulation of packets which can help with some NAT gateways.
* `ESPProposal` (string): Optional, defaults to `aes128gcm16-sha256-prfsha256-ecp256`. Change this string to choose another ESP Proposal.

Hint: 
Add rules to your firewall: Open ports 50 (for ESP protocol), UDP 500 (for IKE, to manage encryption keys) and UDP 4500 (for IPSEC NAT-Traversal mode).

#### Troubleshooting
Logging
* When flannel is run from a container, the Strongswan tools are installed. `swanctl` can be used for interacting with the charon and it provides a logs command.. 
* Charon logs are also written to the stdout of the flannel process. 

Troubleshooting
* `ip xfrm state` can be used to interact with the kernel's security association database. This can be used to show the current security associations (SA) and whether a host is successfully establishing ipsec connections to other hosts.
* `ip xfrm policy` can be used to show the installed policies. Flannel installs three policies for each host it connects to. 

Flannel will not restore policies that are manually deleted (unless flannel is restarted). It will also not delete stale policies on startup. They can be removed by rebooting your host or by removing all ipsec state with `ip xfrm state flush && ip xfrm policy flush` and restarting flannel.

### WireGuard

Use in-kernel [WireGuard](https://www.wireguard.com) to encapsulate and encrypt the packets.

Type:
* `Type` (string): `wireguard`
* `PSK` (string): Optional. The pre shared key to use. Use `wg genpsk` to generate a key.
* `ListenPort` (int): Optional. The udp port to listen on. Default is `51820`.
* `PersistentKeepaliveInterval` (int): Optional. Default is 0 (disabled).

The static name of the interface is `flannel-wg`. WireGuard tools like `wg show` can be used to debug interface and peers.
