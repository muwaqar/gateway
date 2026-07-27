// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package gatewayapi

import (
	"k8s.io/apimachinery/pkg/types"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/gatewayapi/resource"
)

// policyTargetKey identifies a BackendTrafficPolicy/ClientTrafficPolicy attachment target.
type policyTargetKey struct {
	Kind, Namespace, Name, SectionName string
}

// policyIndexEntry pairs a route-rule/route-level policy's value with its own MergeType, so
// resolution can decide whether to keep going toward a broader parent.
type policyIndexEntry[T comparable] struct {
	value     T
	mergeType *egv1a1.MergeType
}

// policyIndexListenerEntry pairs a listener-level policy's value with hasValue, since a
// policy that doesn't address a field must still transparently fall through to gateway for it.
type policyIndexListenerEntry[T comparable] struct {
	value    T
	hasValue bool
}

// policyIndex resolves a route-rule/route/listener/gateway target through the same
// attachment order a policy itself uses, including MergeType-driven inheritance.
type policyIndex[T comparable] struct {
	routeRuleLevel map[policyTargetKey]policyIndexEntry[T]
	routeLevel     map[policyTargetKey]policyIndexEntry[T]
	listenerLevel  map[policyTargetKey]policyIndexListenerEntry[T]
	gatewayLevel   map[policyTargetKey]T
}

// newPolicyIndex allocates a policyIndex's maps.
func newPolicyIndex[T comparable]() *policyIndex[T] {
	return &policyIndex[T]{
		routeRuleLevel: make(map[policyTargetKey]policyIndexEntry[T]),
		routeLevel:     make(map[policyTargetKey]policyIndexEntry[T]),
		listenerLevel:  make(map[policyTargetKey]policyIndexListenerEntry[T]),
		gatewayLevel:   make(map[policyTargetKey]T),
	}
}

// setRouteRuleLevel records a route-rule target's first-registered entry; later calls for the
// same key are ignored.
func (idx *policyIndex[T]) setRouteRuleLevel(key policyTargetKey, value T, mergeType *egv1a1.MergeType) {
	if _, exists := idx.routeRuleLevel[key]; !exists {
		idx.routeRuleLevel[key] = policyIndexEntry[T]{value: value, mergeType: mergeType}
	}
}

// setRouteLevel is setRouteRuleLevel's counterpart for a route (not route-rule) target.
func (idx *policyIndex[T]) setRouteLevel(key policyTargetKey, value T, mergeType *egv1a1.MergeType) {
	if _, exists := idx.routeLevel[key]; !exists {
		idx.routeLevel[key] = policyIndexEntry[T]{value: value, mergeType: mergeType}
	}
}

// setListenerLevel claims a listener key's first-registered slot unconditionally; hasValue decides
// whether Lookup uses value directly or falls through to gateway. This function needs to know
// which of three states value is in: not populated, populated with T's zero/default value, or
// populated with a non-default value - but the first two look identical by inspecting value alone.
// An Option[T] (Some(T) vs. None) would separate these for free; Go generics have no built-in
// optional, so hasValue is the caller-supplied Some/None signal instead.
func (idx *policyIndex[T]) setListenerLevel(key policyTargetKey, value T, hasValue bool) {
	if _, exists := idx.listenerLevel[key]; !exists {
		idx.listenerLevel[key] = policyIndexListenerEntry[T]{value: value, hasValue: hasValue}
	}
}

// setGatewayLevel records a gateway target's first-registered value, always unconditional: gateway
// is the last level, so there's no parent an unset value could ever wrongly block.
func (idx *policyIndex[T]) setGatewayLevel(key policyTargetKey, value T) {
	if _, exists := idx.gatewayLevel[key]; !exists {
		idx.gatewayLevel[key] = value
	}
}

// Lookup resolves the effective value for a route-rule/route/listener/gateway target. value alone
// is always correct; pinned reports whether a route-rule/route entry supplied it directly.
func (idx *policyIndex[T]) Lookup(
	routeKind gwapiv1.Kind,
	routeNN types.NamespacedName,
	gatewayNN types.NamespacedName,
	listenerName *gwapiv1.SectionName,
	routeRuleName *gwapiv1.SectionName,
) (value T, pinned bool) {
	if idx == nil {
		return value, false
	}

	if routeRuleName != nil {
		key := policyTargetKey{Kind: string(routeKind), Namespace: routeNN.Namespace, Name: routeNN.Name, SectionName: string(*routeRuleName)}
		if entry, found := idx.routeRuleLevel[key]; found {
			return idx.resolveEntry(entry, gatewayNN, listenerName)
		}
	}

	routeKey := policyTargetKey{Kind: string(routeKind), Namespace: routeNN.Namespace, Name: routeNN.Name}
	if entry, found := idx.routeLevel[routeKey]; found {
		return idx.resolveEntry(entry, gatewayNN, listenerName)
	}

	return idx.LookupListenerOrGateway(gatewayNN, listenerName), false
}

// LookupListenerOrGateway resolves just the listener/gateway levels, for callers with no
// route-rule/route context of their own. hasValue, not presence or zero-ness, decides fallthrough.
func (idx *policyIndex[T]) LookupListenerOrGateway(gatewayNN types.NamespacedName, listenerName *gwapiv1.SectionName) T {
	var zero T
	if idx == nil {
		return zero
	}
	if listenerName != nil {
		listenerKey := policyTargetKey{Kind: resource.KindGateway, Namespace: gatewayNN.Namespace, Name: gatewayNN.Name, SectionName: string(*listenerName)}
		if entry, found := idx.listenerLevel[listenerKey]; found && entry.hasValue {
			return entry.value
		}
	}
	return idx.LookupGateway(gatewayNN)
}

// LookupGateway resolves just the gateway-level value, for callers with no route/listener context.
func (idx *policyIndex[T]) LookupGateway(gatewayNN types.NamespacedName) T {
	var zero T
	if idx == nil {
		return zero
	}
	gatewayKey := policyTargetKey{Kind: resource.KindGateway, Namespace: gatewayNN.Namespace, Name: gatewayNN.Name}
	return idx.gatewayLevel[gatewayKey]
}

// LookupOwnerListenerLevel is LookupListenerOrGateway's counterpart for an owner kind other than
// Gateway (e.g. ListenerSet), with no gateway/listenerSet-wide fallback.
func (idx *policyIndex[T]) LookupOwnerListenerLevel(ownerKind string, ownerNN types.NamespacedName, listenerName gwapiv1.SectionName) (T, bool) {
	var zero T
	if idx == nil {
		return zero, false
	}
	key := policyTargetKey{Kind: ownerKind, Namespace: ownerNN.Namespace, Name: ownerNN.Name, SectionName: string(listenerName)}
	if entry, found := idx.listenerLevel[key]; found && entry.hasValue {
		return entry.value, true
	}
	return zero, false
}

// LookupOwnerLevel is LookupGateway's counterpart for an owner kind other than Gateway.
func (idx *policyIndex[T]) LookupOwnerLevel(ownerKind string, ownerNN types.NamespacedName) T {
	var zero T
	if idx == nil {
		return zero
	}
	key := policyTargetKey{Kind: ownerKind, Namespace: ownerNN.Namespace, Name: ownerNN.Name}
	return idx.gatewayLevel[key]
}

// resolveEntry reports pinned: true whenever entry itself supplies the final answer - an explicit
// value, or an unset value with MergeType nil - and false only when it falls through to a parent.
func (idx *policyIndex[T]) resolveEntry(entry policyIndexEntry[T], gatewayNN types.NamespacedName, listenerName *gwapiv1.SectionName) (T, bool) {
	var zero T
	if entry.value != zero {
		return entry.value, true
	}
	if entry.mergeType == nil {
		return zero, true
	}
	return idx.LookupListenerOrGateway(gatewayNN, listenerName), false
}
