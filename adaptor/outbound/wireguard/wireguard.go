package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ido2021/light-proxy/adaptor/outbound"
	"math/rand"
	"net"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func init() {
	outbound.RegisterOutAdaptorFactory("wireguard", NewWireGuardOutAdaptor)
}

type PeerConfig struct {
	PublicKey    string         `json:"publicKey"`
	PreSharedKey string         `json:"preSharedKey,omitempty"`
	Endpoint     *string        `json:"endpoint,omitempty"`
	KeepAlive    int            `json:"keepAlive,omitempty"`
	AllowedIPs   []netip.Prefix `json:"allowedIPs,omitempty"`
}

// WireGuardConfig contains the information to initiate a wireguard connection
type WireGuardConfig struct {
	PrivateKey string         `json:"privateKey"`
	Address    []netip.Prefix `json:"address,omitempty"`
	Peers      []PeerConfig   `json:"peers"`
	DNS        []netip.Addr   `json:"DNS,omitempty"`
	MTU        int            `json:"MTU,omitempty"`
	ListenPort *int           `json:"listenPort,omitempty"`
}

type WireGuardOutAdaptor struct {
	Tnet      *netstack.Net
	SystemDNS bool
}

func NewWireGuardOutAdaptor(config json.RawMessage) (outbound.OutAdaptor, error) {
	conf := &WireGuardConfig{}
	err := json.Unmarshal(config, conf)
	if err != nil {
		return nil, err
	}
	return StartWireguard(conf, device.LogLevelError)
}

func (w *WireGuardOutAdaptor) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return w.Tnet.DialContext(ctx, network, addr)
}

func (w *WireGuardOutAdaptor) LookupAddr(ctx context.Context, name string) ([]string, error) {
	if w.SystemDNS {
		return net.DefaultResolver.LookupHost(ctx, name)
	} else {
		return w.Tnet.LookupContextHost(ctx, name)
	}
}

func (w *WireGuardOutAdaptor) Resolve(ctx context.Context, name string) (net.IP, error) {
	addrs, err := w.LookupAddr(ctx, name)
	if err != nil {
		return nil, err
	}

	size := len(addrs)
	if size == 0 {
		return nil, errors.New("no address found for: " + name)
	}

	rand.Shuffle(size, func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})

	var addr netip.Addr
	for _, saddr := range addrs {
		addr, err = netip.ParseAddr(saddr)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	return addr.AsSlice(), nil
}

// DeviceSetting contains the parameters for setting up a tun interface
type DeviceSetting struct {
	ipcRequest string
	dns        []netip.Addr
	deviceAddr []netip.Addr
	mtu        int
}

// serialize the config into an IPC request and DeviceSetting
func createIPCRequest(conf *WireGuardConfig) (*DeviceSetting, error) {
	var request strings.Builder

	privateKey, err := encodeBase64ToHex(conf.PrivateKey)
	if err != nil {
		return nil, err
	}
	request.WriteString(fmt.Sprintf("private_key=%s\n", privateKey))

	if conf.ListenPort != nil {
		request.WriteString(fmt.Sprintf("listen_port=%d\n", *conf.ListenPort))
	}

	for _, peer := range conf.Peers {
		publicKey, err := encodeBase64ToHex(peer.PublicKey)
		if err != nil {
			return nil, err
		}
		request.WriteString(fmt.Sprintf("public_key=%s\n", publicKey))
		request.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.KeepAlive))

		var sharedKey string
		if peer.PreSharedKey != "" {
			sharedKey, err = encodeBase64ToHex(sharedKey)
			if err != nil {
				return nil, err
			}
		} else {
			sharedKey = "0000000000000000000000000000000000000000000000000000000000000000"
		}
		request.WriteString(fmt.Sprintf("preshared_key=%s\n", sharedKey))
		if peer.Endpoint != nil {
			request.WriteString(fmt.Sprintf("endpoint=%s\n", *peer.Endpoint))
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip.String()))
			}
		} else {
			request.WriteString(
				"allowed_ip=0.0.0.0/0\n" +
					"allowed_ip=::0/0")
		}
	}

	var deviceAddr []netip.Addr
	for _, prefix := range conf.Address {
		deviceAddr = append(deviceAddr, prefix.Addr())
	}

	setting := &DeviceSetting{ipcRequest: request.String(), dns: conf.DNS, deviceAddr: deviceAddr, mtu: conf.MTU}
	return setting, nil
}

// StartWireguard creates a tun interface on netstack given a configuration
func StartWireguard(conf *WireGuardConfig, logLevel int) (outbound.OutAdaptor, error) {
	setting, err := createIPCRequest(conf)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(setting.deviceAddr, setting.dns, setting.mtu)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))
	err = dev.IpcSet(setting.ipcRequest)
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	return &WireGuardOutAdaptor{
		Tnet:      tnet,
		SystemDNS: len(setting.dns) == 0,
	}, nil
}
