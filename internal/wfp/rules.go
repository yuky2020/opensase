//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package wfp

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Known addresses.
var (
	linkLocal = wtFwpV6AddrAndMask{[16]uint8{0xfe, 0x80}, 10}

	linkLocalDHCPMulticast = wtFwpByteArray16{[16]uint8{0xFF, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x2}}
	siteLocalDHCPMulticast = wtFwpByteArray16{[16]uint8{0xFF, 0x05, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x3}}

	linkLocalRouterMulticast = wtFwpByteArray16{[16]uint8{0xFF, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}}
)

type filterAdder func(session uintptr, filter *wtFwpmFilter0, sd uintptr, id *uint64) error

func permitTunInterface(session uintptr, baseObjects *baseObjects, weight uint8, ifLUID uint64) error {
	return permitTunInterfaceWith(session, baseObjects, weight, ifLUID, fwpmFilterAdd0)
}

func permitTunInterfaceWith(session uintptr, baseObjects *baseObjects, weight uint8, ifLUID uint64, add filterAdder) error {
	luid := new(uint64)
	*luid = ifLUID
	ifaceCondition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT64,
			value: uintptr(unsafe.Pointer(luid)),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&ifaceCondition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound IPv4 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound IPv4 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound IPv6 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound IPv6 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	runtime.KeepAlive(luid)
	return nil
}

func permitOpenSASEService(session uintptr, baseObjects *baseObjects, weight uint8) error {
	//
	// First condition is the exe path of the current process.
	//
	appID, err := getCurrentProcessAppID()
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))

	appCondition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_BYTE_BLOB_TYPE,
			value: uintptr(unsafe.Pointer(appID)),
		},
	}

	// When running as a Windows service (configured with SERVICE_SID_TYPE_UNRESTRICTED),
	// the process token has a service SID. Restricting the permit rule by both App ID and
	// the service SID security descriptor ensures that only this service instance is permitted,
	// preventing other processes launched from the same executable from inheriting full network access.
	//
	// When running in the foreground as an elevated console application, the process token does not
	// contain a service SID. In that case, we fall back silently to an app-ID-only permit rule.
	// Note that this provides a weaker security guarantee because any process running the same binary
	// matches the permit filter.
	conditions := []wtFwpmFilterCondition0{appCondition}

	var (
		sd     *windows.SECURITY_DESCRIPTOR
		sdBlob wtFwpByteBlob
	)
	sd, err = getCurrentProcessSecurityDescriptor()
	if err == nil && sd != nil {
		sdBlob = wtFwpByteBlob{sd.Length(), (*byte)(unsafe.Pointer(sd))}
		conditions = append(conditions, wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_ALE_USER_ID,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_SECURITY_DESCRIPTOR_TYPE,
				value: uintptr(unsafe.Pointer(&sdBlob)),
			},
		})
	}

	//
	// Assemble the filter.
	//
	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions[0])),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted outbound traffic for OpenSASE service (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted inbound traffic for OpenSASE service (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted outbound traffic for OpenSASE service (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted inbound traffic for OpenSASE service (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	runtime.KeepAlive(conditions)
	runtime.KeepAlive(sdBlob)
	runtime.KeepAlive(sd)
	return nil
}

// permitBypass permits traffic to Edge and Control Plane addresses outside the tunnel.
func permitBypass(addresses []netip.Addr, session uintptr, baseObjects *baseObjects, weight uint8) error {
	return permitBypassWith(addresses, session, baseObjects, weight, fwpmFilterAdd0)
}

func permitBypassWith(addresses []netip.Addr, session uintptr, baseObjects *baseObjects, weight uint8, add filterAdder) error {
	seen := make(map[netip.Addr]bool)
	var v6Addrs []*wtFwpByteArray16

	for _, addr := range addresses {
		addr = addr.Unmap().WithZone("")
		if !addr.IsValid() || seen[addr] {
			continue
		}
		seen[addr] = true

		if addr.Is4() {
			v4Val := binary.BigEndian.Uint32(addr.AsSlice())
			condition := wtFwpmFilterCondition0{
				fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_UINT32,
					value: uintptr(v4Val),
				},
			}

			filter := wtFwpmFilter0{
				providerKey:         &baseObjects.provider,
				subLayerKey:         baseObjects.filters,
				weight:              filterWeight(weight),
				numFilterConditions: 1,
				filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
				action: wtFwpmAction0{
					_type: cFWP_ACTION_PERMIT,
				},
			}

			filterID := uint64(0)

			//
			// #1 Permit outbound IPv4 bypass traffic.
			//
			{
				displayData, err := createWtFwpmDisplayData0("Permit outbound bypass traffic (IPv4)", "")
				if err != nil {
					return wrapErr(err)
				}

				filter.displayData = *displayData
				filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

				err = add(session, &filter, 0, &filterID)
				if err != nil {
					return wrapErr(err)
				}
			}

			//
			// #2 Permit inbound IPv4 bypass traffic.
			//
			{
				displayData, err := createWtFwpmDisplayData0("Permit inbound bypass traffic (IPv4)", "")
				if err != nil {
					return wrapErr(err)
				}

				filter.displayData = *displayData
				filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

				err = add(session, &filter, 0, &filterID)
				if err != nil {
					return wrapErr(err)
				}
			}
		} else if addr.Is6() {
			v6Bytes := &wtFwpByteArray16{byteArray16: addr.As16()}
			v6Addrs = append(v6Addrs, v6Bytes)

			condition := wtFwpmFilterCondition0{
				fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_BYTE_ARRAY16_TYPE,
					value: uintptr(unsafe.Pointer(v6Bytes)),
				},
			}

			filter := wtFwpmFilter0{
				providerKey:         &baseObjects.provider,
				subLayerKey:         baseObjects.filters,
				weight:              filterWeight(weight),
				numFilterConditions: 1,
				filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
				action: wtFwpmAction0{
					_type: cFWP_ACTION_PERMIT,
				},
			}

			filterID := uint64(0)

			//
			// #3 Permit outbound IPv6 bypass traffic.
			//
			{
				displayData, err := createWtFwpmDisplayData0("Permit outbound bypass traffic (IPv6)", "")
				if err != nil {
					return wrapErr(err)
				}

				filter.displayData = *displayData
				filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

				err = add(session, &filter, 0, &filterID)
				if err != nil {
					return wrapErr(err)
				}
			}

			//
			// #4 Permit inbound IPv6 bypass traffic.
			//
			{
				displayData, err := createWtFwpmDisplayData0("Permit inbound bypass traffic (IPv6)", "")
				if err != nil {
					return wrapErr(err)
				}

				filter.displayData = *displayData
				filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

				err = add(session, &filter, 0, &filterID)
				if err != nil {
					return wrapErr(err)
				}
			}
		}
	}

	runtime.KeepAlive(v6Addrs)
	return nil
}

func permitLoopback(session uintptr, baseObjects *baseObjects, weight uint8) error {
	return permitLoopbackWith(session, baseObjects, weight, fwpmFilterAdd0)
}

func permitLoopbackWith(session uintptr, baseObjects *baseObjects, weight uint8, add filterAdder) error {
	condition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_FLAGS,
		matchType: cFWP_MATCH_FLAGS_ALL_SET,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT32,
			value: uintptr(cFWP_CONDITION_FLAG_IS_LOOPBACK),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound on loopback (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound on loopback (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound on loopback (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound on loopback (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitDHCPIPv4(session uintptr, baseObjects *baseObjects, weight uint8) error {
	//
	// #1 Outbound DHCP request on IPv4.
	//
	{
		var conditions [4]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(68)

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(67)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_UINT32
		conditions[3].conditionValue.value = uintptr(0xffffffff)

		displayData, err := createWtFwpmDisplayData0("Permit outbound DHCP request (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound DHCP response on IPv4.
	//
	{
		var conditions [3]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(68)

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(67)

		displayData, err := createWtFwpmDisplayData0("Permit inbound DHCP response (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitDHCPIPv6(session uintptr, baseObjects *baseObjects, weight uint8) error {
	return permitDHCPIPv6With(session, baseObjects, weight, fwpmFilterAdd0)
}

func permitDHCPIPv6With(session uintptr, baseObjects *baseObjects, weight uint8, add filterAdder) error {
	//
	// #1 Outbound DHCP request on IPv6.
	//
	{
		var conditions [6]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[1].conditionValue.value = uintptr(unsafe.Pointer(&linkLocalDHCPMulticast))

		// Repeat the condition type for logical OR.
		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[2].conditionValue.value = uintptr(unsafe.Pointer(&siteLocalDHCPMulticast))

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_UINT16
		conditions[3].conditionValue.value = uintptr(547)

		conditions[4].fieldKey = cFWPM_CONDITION_IP_LOCAL_ADDRESS
		conditions[4].matchType = cFWP_MATCH_EQUAL
		conditions[4].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[4].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		conditions[5].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[5].matchType = cFWP_MATCH_EQUAL
		conditions[5].conditionValue._type = cFWP_UINT16
		conditions[5].conditionValue.value = uintptr(546)

		displayData, err := createWtFwpmDisplayData0("Permit outbound DHCP request (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound DHCP response on IPv6.
	//
	{
		var conditions [5]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[1].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(547)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_LOCAL_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		conditions[4].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[4].matchType = cFWP_MATCH_EQUAL
		conditions[4].conditionValue._type = cFWP_UINT16
		conditions[4].conditionValue.value = uintptr(546)

		displayData, err := createWtFwpmDisplayData0("Permit inbound DHCP response (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitNdp(session uintptr, baseObjects *baseObjects, weight uint8) error {
	return permitNdpWith(session, baseObjects, weight, fwpmFilterAdd0)
}

func permitNdpWith(session uintptr, baseObjects *baseObjects, weight uint8, add filterAdder) error {
	/* TODO: actually handle the hop limit somehow! The rules should vaguely be:
	 *  - icmpv6 133: must be outgoing, dst must be FF02::2/128, hop limit must be 255
	 *  - icmpv6 134: must be incoming, src must be FE80::/10, hop limit must be 255
	 *  - icmpv6 135: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 136: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 137: must be incoming, src must be FE80::/10, hop limit must be 255
	 */

	type filterDefinition struct {
		displayData *wtFwpmDisplayData0
		conditions  []wtFwpmFilterCondition0
		layer       windows.GUID
	}

	var defs []filterDefinition

	//
	// Router Solicitation Message
	// ICMP type 133, code 0. Outgoing.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 4)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(133)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocalRouterMulticast))

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 133", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		})
	}

	//
	// Router Advertisement Message
	// ICMP type 134, code 0. Incoming.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 4)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(134)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 134", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	//
	// Neighbor Solicitation Message
	// ICMP type 135, code 0. Bi-directional.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 3)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(135)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 135", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		})

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	//
	// Neighbor Advertisement Message
	// ICMP type 136, code 0. Bi-directional.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 3)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(136)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 136", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		})

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	//
	// Redirect Message
	// ICMP type 137, code 0. Incoming.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 4)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(137)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 137", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	filter := wtFwpmFilter0{
		providerKey: &baseObjects.provider,
		subLayerKey: baseObjects.filters,
		weight:      filterWeight(weight),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	for _, definition := range defs {
		filter.displayData = *definition.displayData
		filter.layerKey = definition.layer
		filter.numFilterConditions = uint32(len(definition.conditions))
		filter.filterCondition = (*wtFwpmFilterCondition0)(unsafe.Pointer(&definition.conditions[0]))

		err := add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitHyperV(session uintptr, baseObjects *baseObjects, weight uint8) error {
	condition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_L2_FLAGS,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT32,
			value: uintptr(cFWP_CONDITION_L2_IS_VM2VM),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Outbound.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit Hyper-V => Hyper-V outbound", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit Hyper-V => Hyper-V inbound", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_INBOUND_MAC_FRAME_NATIVE

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

// Block all traffic except what is explicitly permitted by other rules.
func blockAll(session uintptr, baseObjects *baseObjects, weight uint8) error {
	return blockAllWith(session, baseObjects, weight, fwpmFilterAdd0)
}

func blockAllWith(session uintptr, baseObjects *baseObjects, weight uint8, add filterAdder) error {
	filter := wtFwpmFilter0{
		providerKey: &baseObjects.provider,
		subLayerKey: baseObjects.filters,
		weight:      filterWeight(weight),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
		},
	}

	filterID := uint64(0)

	//
	// #1 Block outbound traffic on IPv4.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Block inbound traffic on IPv4.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Block outbound traffic on IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Block inbound traffic on IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

// Block all plain DNS traffic (UDP/TCP port 53) on non-tunnel interfaces while
// permitting queries to the specified tunnel DNS servers on the tunnel interface.
// When tunLUID is non-zero, deny filters match only interfaces other than
// tunLUID so physical-interface port 53 stays blocked while third-party
// port-53 queries routed into the tunnel can reach the Edge (where
// dns.redirectQueries or builtin-dns-bypass handles them).
func blockDNS(except []netip.Addr, tunLUID uint64, session uintptr, baseObjects *baseObjects, weightAllow, weightDeny uint8) error {
	return blockDNSWith(except, tunLUID, session, baseObjects, weightAllow, weightDeny, fwpmFilterAdd0)
}

func blockDNSWith(except []netip.Addr, tunLUID uint64, session uintptr, baseObjects *baseObjects, weightAllow, weightDeny uint8, add filterAdder) error {
	if weightDeny >= weightAllow {
		return errors.New("The allow weight must be greater than the deny weight")
	}

	var tunLUIDPtr *uint64
	if tunLUID != 0 {
		tunLUIDPtr = new(uint64)
		*tunLUIDPtr = tunLUID
	}

	dnsBaseConditions := []wtFwpmFilterCondition0{
		{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT16,
				value: uintptr(53),
			},
		},
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_UDP),
			},
		},
		// Repeat the condition type for logical OR.
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_TCP),
			},
		},
	}

	denyConditions := make([]wtFwpmFilterCondition0, 0, len(dnsBaseConditions)+1)
	denyConditions = append(denyConditions, dnsBaseConditions...)
	if tunLUIDPtr != nil {
		denyConditions = append(denyConditions, wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
			matchType: cFWP_MATCH_NOT_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT64,
				value: uintptr(unsafe.Pointer(tunLUIDPtr)),
			},
		})
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weightDeny),
		numFilterConditions: uint32(len(denyConditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&denyConditions[0])),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
		},
	}

	filterID := uint64(0)

	//
	// #1 Block IPv4 outbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Block IPv4 inbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Block IPv6 outbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Block IPv6 inbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	allowBaseCap := len(dnsBaseConditions) + 1
	allowConditionsV4 := make([]wtFwpmFilterCondition0, 0, allowBaseCap+len(except))
	allowConditionsV4 = append(allowConditionsV4, dnsBaseConditions...)
	allowConditionsV6 := make([]wtFwpmFilterCondition0, 0, allowBaseCap+len(except))
	allowConditionsV6 = append(allowConditionsV6, dnsBaseConditions...)
	if tunLUIDPtr != nil {
		tunCond := wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT64,
				value: uintptr(unsafe.Pointer(tunLUIDPtr)),
			},
		}
		allowConditionsV4 = append(allowConditionsV4, tunCond)
		allowConditionsV6 = append(allowConditionsV6, tunCond)
	}

	seen := make(map[netip.Addr]bool, len(except))
	storedPointers := make([]*wtFwpByteArray16, 0, len(except))
	var v4Count, v6Count int
	for _, ip := range except {
		ip = ip.Unmap().WithZone("")
		if !ip.IsValid() || seen[ip] {
			continue
		}
		seen[ip] = true
		if ip.Is4() {
			allowConditionsV4 = append(allowConditionsV4, wtFwpmFilterCondition0{
				fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_UINT32,
					value: uintptr(binary.BigEndian.Uint32(ip.AsSlice())),
				},
			})
			v4Count++
		} else if ip.Is6() {
			address := &wtFwpByteArray16{byteArray16: ip.As16()}
			allowConditionsV6 = append(allowConditionsV6, wtFwpmFilterCondition0{
				fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_BYTE_ARRAY16_TYPE,
					value: uintptr(unsafe.Pointer(address)),
				},
			})
			storedPointers = append(storedPointers, address)
			v6Count++
		}
	}

	filter = wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weightAllow),
		numFilterConditions: uint32(len(allowConditionsV4)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&allowConditionsV4[0])),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID = uint64(0)

	//
	// #5 Allow IPv4 outbound DNS.
	//
	if v4Count > 0 {
		displayData, err := createWtFwpmDisplayData0("Allow DNS outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #6 Allow IPv4 inbound DNS.
	//
	if v4Count > 0 {
		displayData, err := createWtFwpmDisplayData0("Allow DNS inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	filter.filterCondition = (*wtFwpmFilterCondition0)(unsafe.Pointer(&allowConditionsV6[0]))
	filter.numFilterConditions = uint32(len(allowConditionsV6))

	//
	// #7 Allow IPv6 outbound DNS.
	//
	if v6Count > 0 {
		displayData, err := createWtFwpmDisplayData0("Allow DNS outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #8 Allow IPv6 inbound DNS.
	//
	if v6Count > 0 {
		displayData, err := createWtFwpmDisplayData0("Allow DNS inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = add(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	runtime.KeepAlive(tunLUIDPtr)
	runtime.KeepAlive(storedPointers)

	return nil
}
