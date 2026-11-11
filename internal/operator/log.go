package operator

import (
	"log/slog"

	"github.com/go-logr/logr"
)

// slogr adapts slog to the logr interface controller-runtime logs through.
func slogr(l *slog.Logger) logr.Logger { return logr.FromSlogHandler(l.Handler()) }
