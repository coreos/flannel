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

package ip

import (
	"encoding/json"
	"net"
	"testing"
)

func mkIP6Net(s string, plen uint) IP6Net {
	ip, err := ParseIP6(s)
	if err != nil {
		panic(err)
	}
	return IP6Net{ip, plen}
}

func mkIP6(s string) *IP6 {
	ip, err := ParseIP6(s)
	if err != nil {
		panic(err)
	}
	return ip
}

func TestIP6(t *testing.T) {
	nip := net.ParseIP("fc00::1")
	ip := FromIP6(nip)
	ipStr := ip.String()
	if ipStr != "fc00::1" {
		t.Error("FromIP6 failed")
	}

	ip, err := ParseIP6("fc00::1")
	if err != nil {
		t.Error("ParseIP6 failed with: ", err)
	} else {
		ipStr := ip.String()
		if ipStr != "fc00::1" {
			t.Error("ParseIP6 failed")
		}
	}

	if ip.ToIP().String() != "fc00::1" {
		t.Error("ToIP failed")
	}

	j, err := json.Marshal(ip)
	if err != nil {
		t.Error("Marshal of IP6 failed: ", err)
	} else if string(j) != `"fc00::1"` {
		t.Error("Marshal of IP6 failed with unexpected value: ", j)
	}
}

func TestIP6Net(t *testing.T) {
	n1 := mkIP6Net("fc00:1::", 64)

	if n1.ToIPNet().String() != "fc00:1::/64" {
		t.Error("ToIPNet failed")
	}

	if !n1.Overlaps(n1) {
		t.Errorf("%s does not overlap %s", n1, n1)
	}

	n2 := mkIP6Net("fc00::", 16)
	if !n1.Overlaps(n2) {
		t.Errorf("%s does not overlap %s", n1, n2)
	}

	n2 = mkIP6Net("fc00:2::", 64)
	if n1.Overlaps(n2) {
		t.Errorf("%s overlaps %s", n1, n2)
	}

	n2 = mkIP6Net("fb00:2::", 48)
	if n1.Overlaps(n2) {
		t.Errorf("%s overlaps %s", n1, n2)
	}

	if !n1.Contains(mkIP6("fc00:1::")) {
		t.Error("Contains failed")
	}

	if !n1.Contains(mkIP6("fc00:1::1")) {
		t.Error("Contains failed")
	}

	if n1.Contains(mkIP6("fc00:2::")) {
		t.Error("Contains failed")
	}

	j, err := json.Marshal(n1)
	if err != nil {
		t.Error("Marshal of IP6Net failed: ", err)
	} else if string(j) != `"fc00:1::/64"` {
		t.Error("Marshal of IP6Net failed with unexpected value: ", j)
	}
}
