//go:build windows

package wfp

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/5vnetwork/vx-core/common"
	"github.com/rs/zerolog/log"
	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

type WFP struct {
	// If not empty, all ordinary(UDP, 53) dns requests that are not from the current process and destined for the
	// interfaces other than [tunName] will be blocked.
	tunName string
	session *wf.Session
}

const sessionName = "vx Disable Default DNS Provider Session"
const providerName = "vx Disable Default DNS Provider"
const sublayerName = "vx Disable Default DNS Sublayer"

var providerKey = windows.GUID{
	Data1: 0xf8645546,
	Data2: 0xe91b,
	Data3: 0x414a,
	Data4: [8]byte{0x9d, 0xee, 0x88, 0xa6, 0x7b, 0x87, 0xea, 0x91},
}
var sublayerKey = windows.GUID{
	Data1: 0x3582102e,
	Data2: 0xbe36,
	Data3: 0x4181,
	Data4: [8]byte{0x8e, 0x44, 0x92, 0xd9, 0x5c, 0xc7, 0xe7, 0xb0},
}
var blockDnsFilter4GUID = windows.GUID{
	Data1: 0x3583172e,
	Data2: 0xbe36,
	Data3: 0x4181,
	Data4: [8]byte{0x8e, 0x44, 0x92, 0xd9, 0x5c, 0xc7, 0xe7, 0xb0},
}
var blockDnsFilter6GUID = windows.GUID{
	Data1: 0x3583172e,
	Data2: 0xbe36,
	Data3: 0x3377,
	Data4: [8]byte{0x8e, 0x44, 0x92, 0xd9, 0x5c, 0xc7, 0xe7, 0xb0},
}
var allowNatFilter4GUID = windows.GUID{
	Data1: 0x3583172e,
	Data2: 0x3333,
	Data3: 0x4181,
	Data4: [8]byte{0x8e, 0x44, 0x92, 0xd9, 0x5c, 0xc7, 0xe7, 0xb0},
}
var allowNatFilter6GUID = windows.GUID{
	Data1: 0x3583172e,
	Data2: 0x7777,
	Data3: 0x3377,
	Data4: [8]byte{0x8e, 0x44, 0x92, 0xd9, 0x5c, 0xc7, 0xe7, 0xb0},
}

func New(tunName string) *WFP {
	return &WFP{tunName: tunName}
}

func (w *WFP) Start() error {
	session, err := AddSession(sessionName, providerName, sublayerName, providerKey, sublayerKey)
	if err != nil {
		return err
	}
	w.session = session

	// If DNS disabling is enabled, create the DNS blocking filters
	if w.tunName == "" {
		return errors.New("no tun name")
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get interfaces: %w", err)
	}
	var index int
	for _, iface := range interfaces {
		if iface.Name == w.tunName {
			index = iface.Index
			break
		}
	}
	err = w.allowTunNetwork(index)
	if err != nil {
		return fmt.Errorf("failed to allow nat: %w", err)
	}
	err = w.disableDns(index) // Use 0 as default interface index
	if err != nil {
		return fmt.Errorf("failed to disable DNS: %w", err)
	}

	return nil
}

// without this, tun system stack does not work becuase packets from nat ip are dropped
// this can ALSO be solved by adding
/*
New-NetFirewallRule -DisplayName "MyService Restricted" `
    -Direction Inbound -Protocol TCP `
    -RemoteAddress 192.168.1.0/24 `
    -Action Allow -Profile Any
*/
func (w *WFP) allowTunNetwork(index int) error {
	// Create filter conditions
	conditions := []*wf.Match{
		// Condition 1: Remote port = 53 (DNS)
		{
			Field: wf.FieldInterfaceIndex,
			Op:    wf.MatchTypeEqual,
			Value: uint32(index),
		},
	}

	// Create filter for IPv4
	filterV4 := &wf.Rule{
		ID:          wf.RuleID(allowNatFilter4GUID),
		Name:        "vx allow nat 4",
		Description: "vx allow nat 4",
		Layer:       wf.LayerALEAuthRecvAcceptV4,
		Action:      wf.ActionPermit,
		Provider:    wf.ProviderID(providerKey),
		Sublayer:    wf.SublayerID(sublayerKey),
		HardAction:  true,
		Persistent:  false,
		Conditions:  conditions,
	}

	err := w.session.AddRule(filterV4)
	if err != nil {
		return fmt.Errorf("failed to add IPv4 filter: %w", err)
	}

	// Create filter for IPv6
	filterV6 := &wf.Rule{
		ID:          wf.RuleID(allowNatFilter6GUID),
		Name:        "vx allow nat 6",
		Description: "vx allow nat 6",
		Layer:       wf.LayerALEAuthRecvAcceptV6,
		Action:      wf.ActionPermit,
		Provider:    wf.ProviderID(providerKey),
		Sublayer:    wf.SublayerID(sublayerKey),
		Persistent:  false,
		HardAction:  true,
		Conditions:  conditions,
	}

	err = w.session.AddRule(filterV6)
	if err != nil {
		return fmt.Errorf("failed to add IPv6 filter: %w", err)
	}

	return nil
}

// disableDns creates DNS blocking filters to prevent default DNS usage
func (w *WFP) disableDns(index int) error {
	// Get current process app ID
	appId, err := getCurrentProcessAppId()
	if err != nil {
		return fmt.Errorf("failed to get current process app ID: %w", err)
	}
	log.Info().Msgf("App ID path: %s", appId)

	// Create filter conditions
	conditions := []*wf.Match{
		// Condition 1: Remote port = 53 (DNS)
		{
			Field: wf.FieldIPRemotePort,
			Op:    wf.MatchTypeEqual,
			Value: uint16(53),
		},
		// Condition 2: App ID not equal to current process
		{
			Field: wf.FieldALEAppID,
			Op:    wf.MatchTypeNotEqual,
			Value: appId,
		},
		// Condition 3: Interface index not equal to specified index
		{
			Field: wf.FieldInterfaceIndex,
			Op:    wf.MatchTypeNotEqual,
			Value: uint32(index),
		},
	}

	// Create filter for IPv4
	filterV4 := &wf.Rule{
		ID:          wf.RuleID(blockDnsFilter4GUID),
		Name:        "vx block default dns nameserver 4",
		Description: "vx block default dns nameserver 4",
		Layer:       wf.LayerALEAuthConnectV4,
		Action:      wf.ActionBlock,
		Provider:    wf.ProviderID(providerKey),
		Sublayer:    wf.SublayerID(sublayerKey),
		Persistent:  false,
		Conditions:  conditions,
	}

	err = w.session.AddRule(filterV4)
	if err != nil {
		return fmt.Errorf("failed to add IPv4 filter: %w", err)
	}

	// Create filter for IPv6
	filterV6 := &wf.Rule{
		ID:          wf.RuleID(blockDnsFilter6GUID),
		Name:        "vx block default dns nameserver 6",
		Description: "vx block default dns nameserver 6",
		Layer:       wf.LayerALEAuthConnectV6,
		Action:      wf.ActionBlock,
		Provider:    wf.ProviderID(providerKey),
		Sublayer:    wf.SublayerID(sublayerKey),
		Persistent:  false,
		Conditions:  conditions,
	}

	err = w.session.AddRule(filterV6)
	if err != nil {
		return fmt.Errorf("failed to add IPv6 filter: %w", err)
	}

	return nil
}

// getCurrentProcessAppId gets the application ID for the current process
func getCurrentProcessAppId() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}

	// Convert to absolute path
	absPath, err := filepath.Abs(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	return wf.AppID(absPath)
}

func (w *WFP) Close() error {
	if w.session != nil {
		return w.session.Close()
	}
	return nil
}

// AddSession creates a WFP session with provider and sublayer
func AddSession(sessionName, providerName, sublayerName string, providerKey, sublayerKey windows.GUID) (*wf.Session, error) {
	// Create WFP session options
	opts := &wf.Options{
		Name:        sessionName,
		Description: sessionName,
		Dynamic:     true, // Equivalent to FWPM_SESSION_FLAG_DYNAMIC
	}

	// Create a new WFP session
	session, err := wf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create WFP session: %w", err)
	}

	// Add provider
	provider := &wf.Provider{
		ID:          wf.ProviderID(providerKey),
		Name:        providerName,
		Description: fmt.Sprintf("Provider for %s", providerName),
		Persistent:  false, // Dynamic session, so not persistent
	}

	err = session.AddProvider(provider)
	if err != nil {
		common.Must(session.Close())
		return nil, fmt.Errorf("failed to add provider: %w", err)
	}

	// Add sublayer
	subLayer := &wf.Sublayer{
		ID:          wf.SublayerID(sublayerKey),
		Name:        sublayerName,
		Description: sublayerName,
		Persistent:  false, // Dynamic session, so not persistent
		Provider:    wf.ProviderID(providerKey),
		Weight:      0, // Equivalent to FWP_EMPTY
	}

	err = session.AddSublayer(subLayer)
	if err != nil {
		common.Must(session.Close())
		return nil, fmt.Errorf("failed to add sublayer: %w", err)
	}

	return session, nil
}
