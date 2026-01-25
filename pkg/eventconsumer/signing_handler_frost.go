package eventconsumer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/hanzoai/mpc/pkg/logger"
	"github.com/hanzoai/mpc/pkg/mpc"
	"github.com/hanzoai/mpc/pkg/types"
)

// handleSigningEventFROST handles signing events for FROST protocol (EdDSA/Ed25519)
func (ec *eventConsumer) handleSigningEventFROST(msg *types.SignTxMessage, natMsg *nats.Msg) {
	// Check for duplicate session and track if new
	if ec.checkDuplicateSession(msg.WalletID, msg.TxID) {
		duplicateErr := fmt.Errorf("duplicate signing request detected for walletID=%s txID=%s", msg.WalletID, msg.TxID)
		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			duplicateErr,
			"Duplicate session",
			natMsg,
		)
		return
	}

	// Get key info to determine signers
	keyInfo, err := ec.keyinfoStore.Get(msg.WalletID)
	if err != nil {
		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			err,
			"Failed to get key info",
			natMsg,
		)
		return
	}

	// Create FROST signing session for EdDSA
	session, err := ec.node.CreateEdDSASignSession(
		msg.TxID, // Use TxID as sessionID
		msg.WalletID,
		msg.Tx,                     // Use transaction bytes as message hash
		keyInfo.ParticipantPeerIDs, // Use all participants as signers
		ec.signingResultQueue,
		false, // Don't use broadcast
	)
	if err != nil {
		// Check if the error is due to node not being in participant list
		if errors.Is(err, mpc.ErrNotInParticipantList) {
			logger.Info("Node is not in participant list for this wallet, skipping signing",
				"walletID", msg.WalletID,
				"txID", msg.TxID,
				"nodeID", ec.node.ID(),
			)
			return // Skip signing instead of treating as error
		}

		logger.Error("Failed to create FROST signing session", err)
		ec.handleSigningSessionError(
			msg.WalletID,
			msg.TxID,
			msg.NetworkInternalCode,
			err,
			"Failed to create signing session",
			natMsg,
		)
		return
	}

	// Mark session as already processed
	ec.addSession(msg.WalletID, msg.TxID)

	// Initialize the session
	session.Init()

	ctx, done := context.WithCancel(context.Background())

	// Monitor for errors
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-session.ErrChan():
				if err != nil {
					ec.handleSigningSessionError(
						msg.WalletID,
						msg.TxID,
						msg.NetworkInternalCode,
						err,
						"Failed to sign tx",
						natMsg,
					)
					return
				}
			}
		}
	}()

	// Start listening to incoming messages
	session.ListenToIncomingMessageAsync()

	// Small delay to ensure all nodes are ready
	time.Sleep(DefaultSessionStartupDelay * time.Millisecond)

	// Start processing outbound messages
	go session.ProcessOutboundMessage()

	// Wait for completion
	go func() {
		logger.Info("Waiting for FROST signing session to finish", "sessionID", msg.TxID, "walletID", msg.WalletID)
		result := session.WaitForFinish()
		logger.Info("FROST signing session WaitForFinish returned", "sessionID", msg.TxID, "result", result)
		done()
		ec.sendReplyToRemoveMsg(natMsg)
		logger.Info("FROST signing session completed", "result", result)
	}()
}
