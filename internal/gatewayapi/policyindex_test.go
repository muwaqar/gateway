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

	ruleKey := routeRuleScope(routeNN, string(routeKind), ruleName)
	routeKey := routeScope(routeNN, string(routeKind))
	listenerKey := gatewayListenerScope(gatewayNN, listenerName)
	gatewayKey := gatewayScope(gatewayNN)

	cases := []struct {
		name          string
		nilIndex      bool
		ruleEntry     *policyIndexEntry[bool]
		routeEntry    *policyIndexEntry[bool]
		listenerEntry *policyIndexEntry[bool]
		gatewayValue  bool
		omitRuleName  bool // Lookup called with routeRuleName: nil
		omitListener  bool // Lookup called with listenerName: nil
		wantValue     bool
		wantPinned    bool
	}{
		{
			name:     "nil index falls through to zero value, not pinned",
			nilIndex: true,
		},
		{
			name: "no entry anywhere falls through to zero value, not pinned",
		},
		{
			name:      "rule-level non-zero value wins outright and is pinned, regardless of MergeType",
			ruleEntry: &policyIndexEntry[bool]{value: true, effective: true},
			// gatewayValue: false must be ignored - an explicit value is pinned outright.
			wantValue:  true,
			wantPinned: true,
		},
		{
			name:         "rule-level zero value with MergeType nil is pinned, does not inherit",
			ruleEntry:    &policyIndexEntry[bool]{value: false, effective: true},
			gatewayValue: true, // must be ignored - pinned with nothing to inherit
			wantPinned:   true,
		},
		{
			name:         "rule-level zero value with MergeType set falls through to gateway, not pinned",
			ruleEntry:    &policyIndexEntry[bool]{value: false, effective: false},
			gatewayValue: true,
			wantValue:    true,
		},
		{
			name:          "rule-level presence shields route-level entirely",
			ruleEntry:     &policyIndexEntry[bool]{value: false, effective: false},
			routeEntry:    &policyIndexEntry[bool]{value: true, effective: true}, // must be ignored - shielded
			listenerEntry: &policyIndexEntry[bool]{value: false, effective: true},
		},
		{
			name:         "no rule-level entry falls to route-level, which falls through to gateway",
			routeEntry:   &policyIndexEntry[bool]{value: false, effective: false},
			gatewayValue: true,
			wantValue:    true,
		},
		{
			name:         "routeRuleName nil skips rule-level check even if an entry exists",
			ruleEntry:    &policyIndexEntry[bool]{value: true, effective: true}, // must be ignored - name nil skips it
			routeEntry:   &policyIndexEntry[bool]{value: false, effective: true},
			omitRuleName: true,
			wantPinned:   true, // from the route-level entry, whose own MergeType is nil
		},
		{
			name:          "no rule/route entry falls to listener",
			listenerEntry: &policyIndexEntry[bool]{value: true, effective: true},
			// gatewayValue: false must be ignored - the listener entry is final.
			wantValue: true,
		},
		{
			name:          "listener entry present but zero value is still final, does not fall through",
			listenerEntry: &policyIndexEntry[bool]{value: false, effective: true},
			gatewayValue:  true, // must be ignored - the listener entry is still final
		},
		{
			name:         "no listener entry at all falls through to gateway",
			gatewayValue: true,
			wantValue:    true,
		},
		{
			name:          "listener entry with hasValue false transparently falls through to gateway",
			listenerEntry: &policyIndexEntry[bool]{value: true, effective: false}, // e.g. policy doesn't address this field
			gatewayValue:  true,
			wantValue:     true,
		},
		{
			name:          "listenerName nil skips listener check, falls to gateway",
			listenerEntry: &policyIndexEntry[bool]{value: true, effective: true}, // must be ignored - name nil skips it
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
					idx.entries[ruleKey] = *tc.ruleEntry
				}
				if tc.routeEntry != nil {
					idx.entries[routeKey] = *tc.routeEntry
				}
				if tc.listenerEntry != nil {
					idx.entries[listenerKey] = *tc.listenerEntry
				}
				idx.entries[gatewayKey] = policyIndexEntry[bool]{value: tc.gatewayValue, effective: true}
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

func TestPolicyIndexLookupExact(t *testing.T) {
	routeNN := types.NamespacedName{Namespace: "default", Name: "route-1"}
	gatewayNN := types.NamespacedName{Namespace: "default", Name: "gateway-1"}
	listenerSetNN := types.NamespacedName{Namespace: "default", Name: "listener-set-1"}
	listenerName := gwapiv1.SectionName("http")
	ruleName := gwapiv1.SectionName("rule-1")

	ruleKey := routeRuleScope(routeNN, resource.KindHTTPRoute, ruleName)
	routeKey := routeScope(routeNN, resource.KindHTTPRoute)
	listenerKey := gatewayListenerScope(gatewayNN, listenerName)
	gatewayKey := gatewayScope(gatewayNN)
	listenerSetListenerKey := listenerSetListenerScope(listenerSetNN, listenerName)
	listenerSetKey := listenerSetScope(listenerSetNN)

	cases := []struct {
		name       string
		scope      policyScope
		entry      *policyIndexEntry[bool]
		extraScope policyScope
		extraEntry *policyIndexEntry[bool]
		wantValue  bool
		wantPinned bool
	}{
		{
			name:       "route-rule scope with a non-zero value pins outright",
			scope:      ruleKey,
			entry:      &policyIndexEntry[bool]{value: true, effective: true},
			wantValue:  true,
			wantPinned: true,
		},
		{
			name:       "route-rule scope with a zero value and MergeType nil still pins",
			scope:      ruleKey,
			entry:      &policyIndexEntry[bool]{value: false, effective: true},
			wantPinned: true,
		},
		{
			name:  "route-rule scope with a zero value and MergeType set does not pin",
			scope: ruleKey,
			entry: &policyIndexEntry[bool]{value: false, effective: false},
		},
		{
			name:  "route-rule scope with no entry does not pin",
			scope: ruleKey,
		},
		{
			name:       "route scope with a non-zero value pins outright",
			scope:      routeKey,
			entry:      &policyIndexEntry[bool]{value: true, effective: true},
			wantValue:  true,
			wantPinned: true,
		},
		{
			name:       "listener scope with hasValue true pins",
			scope:      listenerKey,
			entry:      &policyIndexEntry[bool]{value: true, effective: true},
			wantValue:  true,
			wantPinned: true,
		},
		{
			name:  "listener scope with hasValue false does not pin",
			scope: listenerKey,
			entry: &policyIndexEntry[bool]{value: true, effective: false},
		},
		{
			name:       "gateway scope pins whenever an entry exists",
			scope:      gatewayKey,
			entry:      &policyIndexEntry[bool]{value: true, effective: true},
			wantValue:  true,
			wantPinned: true,
		},
		{
			name:       "gateway scope ignores a coexisting listener-scope entry",
			scope:      gatewayKey,
			entry:      &policyIndexEntry[bool]{value: true, effective: true},
			extraScope: listenerKey,
			extraEntry: &policyIndexEntry[bool]{value: false, effective: true},
			wantValue:  true,
			wantPinned: true,
		},
		{
			name:       "listenerSet listener scope with hasValue true pins",
			scope:      listenerSetListenerKey,
			entry:      &policyIndexEntry[bool]{value: true, effective: true},
			wantValue:  true,
			wantPinned: true,
		},
		{
			name:  "listenerSet listener scope with hasValue false does not pin",
			scope: listenerSetListenerKey,
			entry: &policyIndexEntry[bool]{value: true, effective: false},
		},
		{
			name:       "listenerSet scope pins whenever an entry exists",
			scope:      listenerSetKey,
			entry:      &policyIndexEntry[bool]{value: true, effective: true},
			wantValue:  true,
			wantPinned: true,
		},
		{
			name:       "listenerSet scope ignores a coexisting listenerSet-listener-scope entry",
			scope:      listenerSetKey,
			entry:      &policyIndexEntry[bool]{value: true, effective: true},
			extraScope: listenerSetListenerKey,
			extraEntry: &policyIndexEntry[bool]{value: false, effective: true},
			wantValue:  true,
			wantPinned: true,
		},
		{
			name:       "gateway and listenerSet scopes sharing a NamespacedName don't collide",
			scope:      gatewayKey,
			entry:      &policyIndexEntry[bool]{value: true, effective: true},
			extraScope: listenerSetScope(gatewayNN),
			extraEntry: &policyIndexEntry[bool]{value: false, effective: true},
			wantValue:  true,
			wantPinned: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idx := newPolicyIndex[bool]()
			if tc.entry != nil {
				idx.entries[tc.scope] = *tc.entry
			}
			if tc.extraEntry != nil {
				idx.entries[tc.extraScope] = *tc.extraEntry
			}

			value, pinned := idx.LookupExact(tc.scope)
			require.Equal(t, tc.wantPinned, pinned)
			require.Equal(t, tc.wantValue, value)
		})
	}
}

func TestPolicyIndexLookupPointerType(t *testing.T) {
	routeKind := gwapiv1.Kind("HTTPRoute")
	routeNN := types.NamespacedName{Namespace: "default", Name: "route-1"}
	gatewayNN := types.NamespacedName{Namespace: "default", Name: "gateway-1"}
	listenerName := gwapiv1.SectionName("http")
	ruleName := gwapiv1.SectionName("rule-1")
	ruleKey := routeRuleScope(routeNN, string(routeKind), ruleName)
	gatewayKey := gatewayScope(gatewayNN)

	endpoint := egv1a1.RoutingType("Endpoint")
	idx := newPolicyIndex[*egv1a1.RoutingType]()
	idx.entries[ruleKey] = policyIndexEntry[*egv1a1.RoutingType]{value: nil, effective: true}
	idx.entries[gatewayKey] = policyIndexEntry[*egv1a1.RoutingType]{value: &endpoint, effective: true}

	value, _ := idx.Lookup(routeKind, routeNN, gatewayNN, &listenerName, &ruleName)
	require.Nil(t, value)
}

func TestPolicyIndexSetters(t *testing.T) {
	routeNN := types.NamespacedName{Namespace: "default", Name: "route-1"}
	gatewayNN := types.NamespacedName{Namespace: "default", Name: "gateway-1"}
	listenerSetNN := types.NamespacedName{Namespace: "default", Name: "listener-set-1"}
	ruleName := gwapiv1.SectionName("rule-1")
	listenerName := gwapiv1.SectionName("http")
	strategicMerge := egv1a1.StrategicMerge

	t.Run("setRouteRuleLevel keeps the first entry recorded for a key", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setRouteRuleLevel(routeNN, resource.KindHTTPRoute, ruleName, true, &strategicMerge)
		idx.setRouteRuleLevel(routeNN, resource.KindHTTPRoute, ruleName, false, nil)
		require.Equal(t, policyIndexEntry[bool]{value: true, effective: true}, idx.entries[routeRuleScope(routeNN, resource.KindHTTPRoute, ruleName)])
	})

	t.Run("setRouteLevel keeps the first entry recorded for a key", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setRouteLevel(routeNN, resource.KindHTTPRoute, true, nil)
		idx.setRouteLevel(routeNN, resource.KindHTTPRoute, false, &strategicMerge)
		require.Equal(t, policyIndexEntry[bool]{value: true, effective: true}, idx.entries[routeScope(routeNN, resource.KindHTTPRoute)])
	})

	t.Run("setGatewayListenerLevel keeps the first entry recorded for a key", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setGatewayListenerLevel(gatewayNN, listenerName, true, true)
		idx.setGatewayListenerLevel(gatewayNN, listenerName, false, true)
		require.Equal(t, policyIndexEntry[bool]{value: true, effective: true}, idx.entries[gatewayListenerScope(gatewayNN, listenerName)])
	})

	t.Run("setGatewayListenerLevel with hasValue false still claims the slot", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setGatewayListenerLevel(gatewayNN, listenerName, true, false) // e.g. a policy that doesn't address this field
		require.Equal(t, policyIndexEntry[bool]{value: true, effective: false}, idx.entries[gatewayListenerScope(gatewayNN, listenerName)])
	})

	t.Run("setGatewayListenerLevel with hasValue false blocks a later, hasValue true call from a different policy", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setGatewayListenerLevel(gatewayNN, listenerName, true, false) // oldest, accepted policy - doesn't address this field
		idx.setGatewayListenerLevel(gatewayNN, listenerName, true, true)  // younger, to-be-Conflicted policy - does
		require.Equal(t, policyIndexEntry[bool]{value: true, effective: false}, idx.entries[gatewayListenerScope(gatewayNN, listenerName)])
	})

	t.Run("setGatewayLevel keeps the first value recorded for a key", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setGatewayLevel(gatewayNN, true)
		idx.setGatewayLevel(gatewayNN, false)
		require.Equal(t, policyIndexEntry[bool]{value: true, effective: true}, idx.entries[gatewayScope(gatewayNN)])
	})

	t.Run("setListenerSetListenerLevel keeps the first entry recorded for a key", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setListenerSetListenerLevel(listenerSetNN, listenerName, true, true)
		idx.setListenerSetListenerLevel(listenerSetNN, listenerName, false, true)
		require.Equal(t, policyIndexEntry[bool]{value: true, effective: true}, idx.entries[listenerSetListenerScope(listenerSetNN, listenerName)])
	})

	t.Run("setListenerSetLevel keeps the first value recorded for a key", func(t *testing.T) {
		idx := newPolicyIndex[bool]()
		idx.setListenerSetLevel(listenerSetNN, true)
		idx.setListenerSetLevel(listenerSetNN, false)
		require.Equal(t, policyIndexEntry[bool]{value: true, effective: true}, idx.entries[listenerSetScope(listenerSetNN)])
	})
}
