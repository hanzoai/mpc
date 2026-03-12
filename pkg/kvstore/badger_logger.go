package kvstore

import (
	"fmt"

	"github.com/luxfi/zapdb/v4"

	"github.com/hanzoai/mpc/pkg/logger"
)

// quietBadgerLogger is a custom logger that suppresses INFO and DEBUG messages
// but allows ERROR and WARNING messages to be logged
type quietBadgerLogger struct{}

func newQuietBadgerLogger() badger.Logger {
	return &quietBadgerLogger{}
}

func (ql *quietBadgerLogger) Errorf(format string, args ...interface{}) {
	logger.Error("[BADGER] ERROR", nil, "message", fmt.Sprintf(format, args...))
}

func (ql *quietBadgerLogger) Warningf(format string, args ...interface{}) {
	logger.Warn("[BADGER] WARN", "message", fmt.Sprintf(format, args...))
}

func (ql *quietBadgerLogger) Infof(format string, args ...interface{}) {
	// Suppress INFO messages - do nothing
}

func (ql *quietBadgerLogger) Debugf(format string, args ...interface{}) {
	// Suppress DEBUG messages - do nothing
}
