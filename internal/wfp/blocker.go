//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package wfp

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wfpObjectInstaller func(uintptr) error

// Fundamental OpenSASE specific WFP objects.
type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

var (
	// Fixed GUID literals for OpenSASE WFP provider and sublayer.
	openSASEProviderGUID = windows.GUID{
		Data1: 0x4fa51d02,
		Data2: 0x6e91,
		Data3: 0x4b78,
		Data4: [8]byte{0x92, 0x5a, 0x8a, 0x3d, 0x76, 0xc4, 0x19, 0xb8},
	}
	openSASESublayerGUID = windows.GUID{
		Data1: 0x7e83bc14,
		Data2: 0x241d,
		Data3: 0x47e2,
		Data4: [8]byte{0xbb, 0x93, 0x41, 0x59, 0xd0, 0x82, 0x73, 0x6e},
	}
)

// wfpSession holds the engine handle to the single active dynamic WFP session.
// Closing the session automatically removes all associated filters, sublayers, and providers.
var wfpSession uintptr

// Options configures the OpenSASE Windows Filtering Platform kill switch.
type Options struct {
	TunLUID    uint64       // the Wintun adapter
	DNSServers []netip.Addr // the tunnel resolver addresses; plain DNS (port 53) elsewhere is blocked
	Bypass     []netip.Addr // Edge and Control Plane addresses reachable outside the tunnel
}

func createWfpSession() (uintptr, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("OpenSASE", "OpenSASE dynamic session")
	if err != nil {
		return 0, wrapErr(err)
	}

	session := wtFwpmSession0{
		displayData:          *sessionDisplayData,
		flags:                cFWPM_SESSION_FLAG_DYNAMIC,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}

	sessionHandle := uintptr(0)

	err = fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&sessionHandle))
	if err != nil {
		return 0, wrapErr(err)
	}

	return sessionHandle, nil
}

func registerBaseObjects(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{
		provider: openSASEProviderGUID,
		filters:  openSASESublayerGUID,
	}

	//
	// Register provider.
	//
	{
		displayData, err := createWtFwpmDisplayData0("OpenSASE", "OpenSASE provider")
		if err != nil {
			return nil, wrapErr(err)
		}
		provider := wtFwpmProvider0{
			providerKey: bo.provider,
			displayData: *displayData,
		}
		err = fwpmProviderAdd0(session, &provider, 0)
		if err != nil {
			return nil, wrapErr(err)
		}
	}

	//
	// Register filters sublayer.
	//
	{
		displayData, err := createWtFwpmDisplayData0("OpenSASE filters", "Permissive and blocking filters")
		if err != nil {
			return nil, wrapErr(err)
		}
		sublayer := wtFwpmSublayer0{
			subLayerKey: bo.filters,
			displayData: *displayData,
			providerKey: &bo.provider,
			weight:      ^uint16(0),
		}
		err = fwpmSubLayerAdd0(session, &sublayer, 0)
		if err != nil {
			return nil, wrapErr(err)
		}
	}

	return bo, nil
}

// Enable installs all firewall rules in a single transaction. Calling it again replaces the previous set.
func Enable(o Options) error {
	if wfpSession != 0 {
		Disable()
	}

	session, err := createWfpSession()
	if err != nil {
		return wrapErr(err)
	}

	objectInstaller := func(session uintptr) error {
		baseObjects, err := registerBaseObjects(session)
		if err != nil {
			return wrapErr(err)
		}

		err = permitOpenSASEService(session, baseObjects, 15)
		if err != nil {
			return wrapErr(err)
		}

		if len(o.Bypass) > 0 {
			err = permitBypass(o.Bypass, session, baseObjects, 14)
			if err != nil {
				return wrapErr(err)
			}
		}

		if len(o.DNSServers) > 0 {
			err = blockDNS(o.DNSServers, o.TunLUID, session, baseObjects, 15, 14)
			if err != nil {
				return wrapErr(err)
			}
		}

		err = permitLoopback(session, baseObjects, 13)
		if err != nil {
			return wrapErr(err)
		}

		err = permitTunInterface(session, baseObjects, 12, o.TunLUID)
		if err != nil {
			return wrapErr(err)
		}

		err = permitDHCPIPv4(session, baseObjects, 12)
		if err != nil {
			return wrapErr(err)
		}

		err = permitDHCPIPv6(session, baseObjects, 12)
		if err != nil {
			return wrapErr(err)
		}

		err = permitNdp(session, baseObjects, 12)
		if err != nil {
			return wrapErr(err)
		}

		err = permitHyperV(session, baseObjects, 12)
		if err != nil {
			return wrapErr(err)
		}

		err = blockAll(session, baseObjects, 0)
		if err != nil {
			return wrapErr(err)
		}

		return nil
	}

	err = runTransaction(session, objectInstaller)
	if err != nil {
		fwpmEngineClose0(session)
		return wrapErr(err)
	}

	wfpSession = session
	return nil
}

// Disable removes the dynamic WFP session and all installed filters.
func Disable() {
	if wfpSession != 0 {
		fwpmEngineClose0(wfpSession)
		wfpSession = 0
	}
}
