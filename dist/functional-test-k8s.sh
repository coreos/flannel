#!/bin/bash

ARCH="${ARCH:-amd64}"
ETCD_IMG="${ETCD_IMG:-quay.io/coreos/etcd:v3.2.7}"
ETCD_LOCATION="${ETCD_LOCATION:-etcd}"
FLANNEL_NET="${FLANNEL_NET:-10.10.0.0/16}"
TAG=`git describe --tags --dirty`
FLANNEL_DOCKER_IMAGE="${FLANNEL_DOCKER_IMAGE:-quay.io/coreos/flannel:$TAG}"
K8S_VERSION="${K8S_VERSION:-1.13.2}"
HYPERKUBE_IMG="gcr.io/google_containers/hyperkube-${ARCH}"
HYPERKUBE_CMD="${HYPERKUBE_CMD:-/hyperkube}"
HYPERKUBE_APISERVER_CMD="${HYPERKUBE_APISERVER_CMD:-apiserver}"

docker_ip=$(ip -o -f inet addr show docker0 | grep -Po 'inet \K[\d.]+')
etcd_endpt="http://$docker_ip:2379"
k8s_endpt="http://$docker_ip:8080"

# Set the proper imagename according to architecture
if [[ ${ARCH} == "ppc64le" ]]; then
    ETCD_IMG+="-ppc64le"
elif [[ ${ARCH} == "arm64" ]]; then
    ETCD_IMG+="-arm64"
fi

setup_suite() {
    # Run etcd, killing any existing one that was running

    # Start etcd
    docker rm -f flannel-e2e-test-etcd >/dev/null 2>/dev/null
    docker run --name=flannel-e2e-test-etcd -d -p 2379:2379 $ETCD_IMG etcd --listen-client-urls http://0.0.0.0:2379 --advertise-client-urls $etcd_endpt >/dev/null
    sleep 1

    # Start a kubernetes API server
    docker rm -f flannel-e2e-k8s-apiserver >/dev/null 2>/dev/null
    docker run -d --net=host --name flannel-e2e-k8s-apiserver ${HYPERKUBE_IMG}:v$K8S_VERSION \
      ${HYPERKUBE_CMD} ${HYPERKUBE_APISERVER_CMD} --etcd-servers=$etcd_endpt \
      --service-cluster-ip-range=10.101.0.0/16 --insecure-bind-address=0.0.0.0 --allow-privileged >/dev/null
    sleep 1

    while ! cat <<EOF |  docker run -i --rm --net=host ${HYPERKUBE_IMG}:v$K8S_VERSION ${HYPERKUBE_CMD} kubectl create -f - >/dev/null 2>/dev/null
apiVersion: v1
kind: Node
metadata:
  name: flannel1
  annotations:
    dummy: value
spec:
  podCIDR: 10.10.1.0/24
EOF
do
    sleep 1
done

cat <<EOF |  docker run -i --rm --net=host ${HYPERKUBE_IMG}:v$K8S_VERSION ${HYPERKUBE_CMD} kubectl create -f - >/dev/null 2>/dev/null
apiVersion: v1
kind: Node
metadata:
  name: flannel2
  annotations:
    dummy: value
spec:
  podCIDR: 10.10.2.0/24
EOF
}

teardown_suite() {
    # Teardown the etcd server
    docker rm -f flannel-e2e-test-etcd >/dev/null
    docker rm -f flannel-e2e-k8s-apiserver >/dev/null
}

teardown() {
	docker rm -f flannel-e2e-test-flannel1 >/dev/null 2>/dev/null
	docker rm -f flannel-e2e-test-flannel2 >/dev/null 2>/dev/null
}

start_flannel() {
    local backend=$1

	flannel_conf="{ \"Network\": \"$FLANNEL_NET\", \"Backend\": { \"Type\": \"${backend}\" } }"
    for host_num in 1 2; do
       docker rm -f flannel-e2e-test-flannel$host_num >/dev/null 2>/dev/null
       docker run -e NODE_NAME=flannel$host_num --privileged --name flannel-e2e-test-flannel$host_num -id --entrypoint /bin/sh $FLANNEL_DOCKER_IMAGE >/dev/null
       docker exec flannel-e2e-test-flannel$host_num /bin/sh -c 'mkdir -p /etc/kube-flannel'
       echo $flannel_conf | docker exec -i flannel-e2e-test-flannel$host_num /bin/sh -c 'cat > /etc/kube-flannel/net-conf.json'
       docker exec -d flannel-e2e-test-flannel$host_num /opt/bin/flanneld --kube-subnet-mgr --ip-masq --kube-api-url $k8s_endpt
       while ! docker exec flannel-e2e-test-flannel$host_num ls /run/flannel/subnet.env >/dev/null 2>&1; do
         sleep 0.1
       done
    done
}

create_ping_dest() {
    # add a dummy interface with $FLANNEL_SUBNET so we have a known working IP to ping
    for host_num in 1 2; do

       # Use declare to allow the host_num variable to be part of the ping_dest variable name. -g is needed to make it global
       declare -g ping_dest$host_num=$(docker "exec" --privileged flannel-e2e-test-flannel$host_num /bin/sh -c '\
		source /run/flannel/subnet.env && \
		ip link add name dummy0 type dummy && \
		ip addr add $FLANNEL_SUBNET dev dummy0 && ip link set dummy0 up && \
		echo $FLANNEL_SUBNET | cut -f 1 -d "/" ')
    done
}

test_vxlan() {
    start_flannel vxlan
    create_ping_dest # creates ping_dest1 and ping_dest2 variables
    pings
    check_iptables
}

if [[ ${ARCH} == "amd64" ]]; then
test_udp() {
    start_flannel udp
    create_ping_dest # creates ping_dest1 and ping_dest2 variables
    pings
    check_iptables
}
fi

test_host-gw() {
    start_flannel host-gw
    create_ping_dest # creates ping_dest1 and ping_dest2 variables
    pings
    check_iptables
}

test_ipip() {
    start_flannel ipip
    create_ping_dest # creates ping_dest1 and ping_dest2 variables
    pings
    check_iptables
}

test_public-ip-overwrite(){
  docker exec flannel-e2e-k8s-apiserver kubectl annotate node flannel1 \
    flannel.alpha.coreos.com/public-ip-overwrite=172.18.0.2 >/dev/null 2>&1
  start_flannel vxlan
  assert_equals "172.18.0.2" \
    "$(docker exec flannel-e2e-k8s-apiserver kubectl get node/flannel1 -o \
    jsonpath='{.metadata.annotations.flannel\.alpha\.coreos\.com/public-ip}' 2>/dev/null)" \
    "Overwriting public IP via annotation does not work"
  # Remove annotation to not break all other tests
  docker exec flannel-e2e-k8s-apiserver kubectl annotate node flannel1 \
    flannel.alpha.coreos.com/public-ip-overwrite- >/dev/null 2>&1
}

pings() {
    # ping in both directions
	assert "docker exec --privileged flannel-e2e-test-flannel1 /bin/ping -c 5 $ping_dest2" "Host 1 cannot ping host 2"
	assert "docker exec --privileged flannel-e2e-test-flannel2 /bin/ping -c 5 $ping_dest1" "Host 2 cannot ping host 1"
}

check_iptables() {
  read -r -d '' POSTROUTING_RULES_FLANNEL1 << EOM
-P POSTROUTING ACCEPT
-A POSTROUTING -s 10.10.0.0/16 -d 10.10.0.0/16 -j RETURN
-A POSTROUTING -s 10.10.0.0/16 ! -d 224.0.0.0/4 -j MASQUERADE --random-fully
-A POSTROUTING ! -s 10.10.0.0/16 -d 10.10.1.0/24 -j RETURN
-A POSTROUTING ! -s 10.10.0.0/16 -d 10.10.0.0/16 -j MASQUERADE --random-fully
EOM
  read -r -d '' POSTROUTING_RULES_FLANNEL2 << EOM
-P POSTROUTING ACCEPT
-A POSTROUTING -s 10.10.0.0/16 -d 10.10.0.0/16 -j RETURN
-A POSTROUTING -s 10.10.0.0/16 ! -d 224.0.0.0/4 -j MASQUERADE --random-fully
-A POSTROUTING ! -s 10.10.0.0/16 -d 10.10.2.0/24 -j RETURN
-A POSTROUTING ! -s 10.10.0.0/16 -d 10.10.0.0/16 -j MASQUERADE --random-fully
EOM
  read -r -d '' FORWARD_RULES << EOM
-P FORWARD ACCEPT
-A FORWARD -s 10.10.0.0/16 -j ACCEPT
-A FORWARD -d 10.10.0.0/16 -j ACCEPT
EOM
  # check masquerade & forward rules
  assert_equals "$POSTROUTING_RULES_FLANNEL1" \
                "$(docker exec --privileged flannel-e2e-test-flannel1 /sbin/iptables -t nat -S POSTROUTING)" "Host 1 has not expected postrouting rules"
  assert_equals "$POSTROUTING_RULES_FLANNEL2" \
                "$(docker exec --privileged flannel-e2e-test-flannel2 /sbin/iptables -t nat -S POSTROUTING)" "Host 2 has not expected postrouting rules"
  assert_equals "$FORWARD_RULES" \
                "$(docker exec --privileged flannel-e2e-test-flannel1 /sbin/iptables -t filter -S FORWARD)" "Host 1 has not expected forward rules"
  assert_equals "$FORWARD_RULES" \
                "$(docker exec --privileged flannel-e2e-test-flannel2 /sbin/iptables -t filter -S FORWARD)" "Host 2 has not expected forward rules"
}

test_manifest() {
    # This just tests that the API server accepts the manifest, not that it actually acts on it correctly.
    assert "cat ../Documentation/kube-flannel.yml |  docker run -i --rm --net=host ${HYPERKUBE_IMG}:v$K8S_VERSION ${HYPERKUBE_CMD} kubectl create -f -"
}
