// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package gatewayapi

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/gatewayapi/resource"
)

func TestPolicyIndexLookup(t *testing.T) {
	routeKind := gwapiv1.Kind("HTTPRoute")
	routeNN := types.NamespacedName{Namespace: "default", Name: "route-1"}
	gatewayNN := types.NamespacedName{Namespace: "default", Name: "gateway-1"}
	listenerName := gwapiv1.SectionName("http")
	ruleName := gwapiv1.SectionName("rule-1")
	strategicMerge := egv1a1.StrategicMerge

	ruleKey := policyTargetKey{Kind: string(routeKind), Namespace: routeNN.Namespace, Name: routeNN.Name, SectionName: string(ruleName)}
	routeKey := policyTargetKey{Kind: string(routeKind), Namespace: routeNN.Namespace, Name: routeNN.Name}
	listenerKey := policyTargetKey{Kind: resource.KindGateway, Namespace: gatewayNN.Namespace, Name: gatewayNN.Name, SectionName: string(listenerName)}
	gatewayKey := policyTargetKey{Kind: resource.KindGateway, Namespace: gatewayNN.Namespace, Name: gatewayNN.Name}

	cases := []struct {
		name          string
		nilIndex      bool
		ruleEntry     *policyIndexEntry[bool]
		routeEntry    *policyIndexEntry[bool]
		listenerEntry *policyIndexListenerEntry[bool]
		gatewayValue  bool
		omitRuleName  bool // Lookup called with routeRuleName: nil
		omitListener  bool // Lookup called with listenerName: nil
		wantValue     bool
		wantPinned    bool
	}{
		{name: "nil index falls through to zero value, not pinned", nilIndex: true},
		{name: "no entry anywhere falls through to zero value, not pinned"},
		{
			name:      "rule-level non-zero value wins outright and is pinned, regardless of MergeType",
			ruleEntry: &policyIndexEntry[bool]{value: true, mergeType: &strategicMerge},
			// gatewayValue: false must be ignored - an explicit value is pinned outright.
			wantValue: true, wantPinned: true,
		},
		{
			name:         "rule-level zero value with MergeType nil is pinned, does not inherit",
			ruleEntry:    &policyIndexEntry[bool]{value: false, mergeType: nil},
			gatewayValue: true, // must be ignored - pinned with nothing to inherit
			wantPinned:   true,
		},
		{
			name:         "rule-level zero value with MergeType set falls through to gateway, not pinned",
			ruleEntry:    &policyIndexEntry[bool]{value: false, mergeType: &strategicMerge},
			gatewayValue: true,
			wantValue:    true,
		},
		{
			name:          "rule-level presence shields route-level entirely",
			ruleEntry:     &policyIndexEntry[bool]{value: false, mergeType: &strategicMerge},
			routeEntry:    &policyIndexEntry[bool]{value: true, mergeType: nil}, // must be ignored - shielded
			listenerEntry: &policyIndexListenerEntry[bool]{value: false, hasValue: true},
		},
		{
			name:         "no rule-level entry falls to route-level, which falls through to gateway",
			routeEntry:   &policyIndexEntry[bool]{value: false, mergeType: &strategicMerge},
			gatewayValue: true,
			wantValue:    true,
		},
		{
			name:         "routeRuleName nil skips rule-level check even if an entry exists",
			ruleEntry:    &policyIndexEntry[bool]{value: true, mergeType: nil}, // must be ignored - name nil skips it
			routeEntry:   &policyIndexEntry[bool]{value: false, mergeType: nil},
			omitRuleName: true,
			wantPinned:   true, // from the route-level entry, whose own MergeType is nil
		},
		{
			name:          "no rule/route entry falls to listener",
			listenerEntry: &policyIndexListenerEntry[bool]{value: true, hasValue: true},
			// gatewayValue: false must be ignored - the listener entry is final.
			wantValue: true,
		},
		{
			name:          "listener entry present but zero value is still final, does not fall through",
			listenerEntry: &policyIndexListenerEntry[bool]{value: false, hasValue: true},
			gatewayValue:  true, // must be ignored - the listener entry is still final
		},
		{
			name:         "no listener entry at all falls through to gateway",
			gatewayValue: true,
			wantValue:    true,
		},
		{
			name:          "listener entry with hasValue false transparently falls through to gateway",
			listenerEntry: &policyIndexListenerEntry[bool]{value: true, hasValue: false}, // e.g. policy doesn't address this field
			gatewayValue:  true,
			wantValue:     true,
		},
		{
			name:          "listenerName nil skips listener check, falls to gateway",
			listenerEntry: &policyIndexListenerEntry[bool]{value: true, hasValue: true}, // must be ignored - name nil skips it
			gatewayValue:  true,
			omitListener:  true,
			wantValue:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var idx *policyIndex[bool]
			if !tc.nilIndex {
				idx = newPolicyIndex[bool]()
				if tc.ruleEntry != nil {
					idx.routeRuleLevel[ruleKey] = *tc.ruleEntry
				}
				if tc.routeEntry != nil {
					idx.routeLevel[routeKey] = *tc.routeEntry
				}
				if tc.listenerEntry != nil {
					idx.listenerLevel[listenerKey] = *tc.listenerEntry
				}
				idx.gatewayLevel[gatewayKey] = tc.gatewayValue
			}

			wantRuleName, wantListenerName := &ruleName, &listenerName
			if tc.omitRuleName {
				wantRuleName = nil
			}
			if tc.omitListener {
				wantListenerName = nil
			}

			value, pinned := idx.Lookup(routeKind, routeNN, gatewayNN, wantListenerName, wantRuleName)
			require.Equal(t, tc.wantPinned, pinned)
			require.Equal(t, tc.wantValue, value)
		})
	}
}

func TestPolicyIndexListenerAndGatewayLookups(t *testing.T) {
	gatewayNN := types.NamespacedName{Namespace: "default", Name: "gateway-1"}
	listenerName := gwapiv1.SectionName("http")
	listenerKey := policyTargetKey{Kind: resource.KindGateway, Namespace: gatewayNN.Namespace, Name: gatewayNN.Name, SectionName: string(listenerName)}
	gatewayKey := policyTargetKey{Kind: resource.KindGateway, Namespace: gatewayNN.Namespace, Name: gatewayNN.Name}

	t.Run("LookupListenerOrGateway reuses the same listener/gateway fallback", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.listenerLevel[listenerKey] = policyIndexListenerEntry[bool]{value: true, hasValue: true}
		idx.gatewayLevel[gatewayKey] = false
		require.True(t, idx.LookupListenerOrGateway(gatewayNN, &listenerName))
	})

	t.Run("LookupGateway resolves only the gateway level", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.listenerLevel[listenerKey] = policyIndexListenerEntry[bool]{value: true, hasValue: true} // must be ignored
		idx.gatewayLevel[gatewayKey] = true
		require.True(t, idx.LookupGateway(gatewayNN))
	})
}

func TestPolicyIndexLookupPointerType(t *testing.T) {
	routeKind := gwapiv1.Kind("HTTPRoute")
	routeNN := types.NamespacedName{Namespace: "default", Name: "route-1"}
	gatewayNN := types.NamespacedName{Namespace: "default", Name: "gateway-1"}
	listenerName := gwapiv1.SectionName("http")
	ruleName := gwapiv1.SectionName("rule-1")
	ruleKey := policyTargetKey{Kind: string(routeKind), Namespace: routeNN.Namespace, Name: routeNN.Name, SectionName: string(ruleName)}
	gatewayKey := policyTargetKey{Kind: resource.KindGateway, Namespace: gatewayNN.Namespace, Name: gatewayNN.Name}

	endpoint := egv1a1.RoutingType("Endpoint")
	idx := newPolicyIndex[*egv1a1.RoutingType]()
	idx.routeRuleLevel[ruleKey] = policyIndexEntry[*egv1a1.RoutingType]{value: nil, mergeType: nil}
	idx.gatewayLevel[gatewayKey] = &endpoint

	value, _ := idx.Lookup(routeKind, routeNN, gatewayNN, &listenerName, &ruleName)
	require.Nil(t, value)
}

func TestPolicyIndexSetters(t *testing.T) {
	key := policyTargetKey{Kind: "HTTPRoute", Namespace: "default", Name: "route-1", SectionName: "rule-1"}
	strategicMerge := egv1a1.StrategicMerge

	t.Run("setRouteRuleLevel keeps the first entry recorded for a key", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setRouteRuleLevel(key, true, &strategicMerge)
		idx.setRouteRuleLevel(key, false, nil)
		require.Equal(t, policyIndexEntry[bool]{value: true, mergeType: &strategicMerge}, idx.routeRuleLevel[key])
	})

	t.Run("setRouteLevel keeps the first entry recorded for a key", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setRouteLevel(key, true, nil)
		idx.setRouteLevel(key, false, &strategicMerge)
		require.Equal(t, policyIndexEntry[bool]{value: true, mergeType: nil}, idx.routeLevel[key])
	})

	t.Run("setListenerLevel keeps the first entry recorded for a key", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setListenerLevel(key, true, true)
		idx.setListenerLevel(key, false, true)
		require.Equal(t, policyIndexListenerEntry[bool]{value: true, hasValue: true}, idx.listenerLevel[key])
	})

	t.Run("setListenerLevel with hasValue false still claims the slot", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setListenerLevel(key, true, false) // e.g. a policy that doesn't address this field
		require.Equal(t, policyIndexListenerEntry[bool]{value: true, hasValue: false}, idx.listenerLevel[key])
	})

	t.Run("setListenerLevel with hasValue false blocks a later, hasValue true call from a different policy", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setListenerLevel(key, true, false) // oldest, accepted policy - doesn't address this field
		idx.setListenerLevel(key, true, true)  // younger, to-be-Conflicted policy - does
		require.Equal(t, policyIndexListenerEntry[bool]{value: true, hasValue: false}, idx.listenerLevel[key])
	})

	t.Run("setGatewayLevel keeps the first value recorded for a key", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setGatewayLevel(key, true)
		idx.setGatewayLevel(key, false)
		require.True(t, idx.gatewayLevel[key])
	})
}
