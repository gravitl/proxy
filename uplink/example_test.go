package uplink_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/gravitl/proxy/uplink"
)

func ExampleClient() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c, err := uplink.NewClient(uplink.ClientOptions{
		Addr:       "relay.example.com:443",
		ServerName: "relay.example.com",
		TLSConfig:  &tls.Config{MinVersion: tls.VersionTLS12},
		HelloFactory: func() (uplink.ClientHello, error) {
			return uplink.ClientHello{
				Version: 1, NodeID: "node", RelayPeerID: "relay",
				PublicKey: "wg-pubkey", Proof: "proof",
				Timestamp: time.Now().Unix(),
			}, nil
		},
		PacketHandler: func(pkt []byte) error {
			// Inject pkt into the local WireGuard/TUN receive path.
			_ = pkt
			return nil
		},
	})
	if err != nil {
		panic(err)
	}
	_ = c.Start(ctx)
	out := []byte{0x01} // placeholder WG packet bytes
	_ = c.SendPacket(ctx, out)
	_ = c.Stop(context.Background())
	fmt.Println(c.State())
}
