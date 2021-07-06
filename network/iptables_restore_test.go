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

package network

import "testing"

func TestRules(t *testing.T) {
	baseRules := IPTablesRestoreRules{
		"filter": []IPTablesRestoreRuleSpec{
			IPTablesRestoreRuleSpec{"-A", "INPUT", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"},
			IPTablesRestoreRuleSpec{"-A", "INPUT", "-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"},
		},
		"nat": []IPTablesRestoreRuleSpec{
			IPTablesRestoreRuleSpec{"-A", "INPUT", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"},
			IPTablesRestoreRuleSpec{"-A", "INPUT", "-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"},
		},
	}
	expectedPayload := `*filter
-A INPUT -s 127.0.0.1 -d 127.0.0.1 -j RETURN
-A INPUT -s 127.0.0.1 ! -d 224.0.0.0/4 -j MASQUERADE --random-fully
COMMIT
*nat
-A INPUT -s 127.0.0.1 -d 127.0.0.1 -j RETURN
-A INPUT -s 127.0.0.1 ! -d 224.0.0.0/4 -j MASQUERADE --random-fully
COMMIT
`
	payload := buildIPTablesRestorePayload(baseRules)
	if payload != expectedPayload {
		t.Errorf("iptables-restore payload not as expected. Expected: %#v, Actual: %#v", expectedPayload, payload)
	}
}
