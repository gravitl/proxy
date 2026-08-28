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
		Addr:       "wss://relay.example.com/uplink/v1",
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
			_ = pkt
			return nil
		},
	})
	if err != nil {
		panic(err)
	}
	_ = c.Start(ctx)
	out := []byte{0x01}
	_ = c.SendPacket(ctx, out)
	_ = c.Stop(context.Background())
	fmt.Println(c.State())
}
