package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/uuid"
	"github.com/luxfi/mpc/pkg/client"
	"github.com/luxfi/mpc/pkg/config"
	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/mpc/pkg/types"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

func main() {
	const environment = "dev"
	config.InitViperConfig()
	logger.Init(environment, true)

	natsURL := viper.GetString("nats.url")
	natsConn, err := nats.Connect(natsURL)
	if err != nil {
		logger.Fatal("Failed to connect to NATS", err)
	}
	defer natsConn.Drain()
	defer natsConn.Close()

	mpcClient := client.NewMPCClient(client.Options{
		NatsConn: natsConn,
		KeyPath:  "./event_initiator.key",
	})

	// 3) Listen for signing results
	err = mpcClient.OnResharingResult(func(evt event.ResharingResultEvent) {
		logger.Info("Resharing result received",
			"walletID", evt.WalletID,
			"pubKey", fmt.Sprintf("%x", evt.PubKey),
			"newThreshold", evt.NewThreshold,
			"keyType", evt.KeyType,
		)
	})
	if err != nil {
		logger.Fatal("Failed to subscribe to OnResharingResult", err)
	}

	resharingMsg := &types.ResharingMessage{
		SessionID: uuid.NewString(),
		WalletID:  "bf2cc849-8e55-47e4-ab73-e17fb1eb690c",
		NodeIDs:   []string{"d926fa75-72c7-4538-9052-4a064a84981d", "7b1090cd-ffe3-46ff-8375-594dd3204169"}, // new peer IDs

		NewThreshold: 2, // t+1 <= len(NodeIDs)
		KeyType:      types.KeyTypeEd25519,
	}
	err = mpcClient.Resharing(resharingMsg)
	if err != nil {
		logger.Fatal("Resharing failed", err)
	}
	fmt.Printf("Resharing(%q) sent, awaiting result...\n", resharingMsg.WalletID)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	fmt.Println("Shutting down.")
}
