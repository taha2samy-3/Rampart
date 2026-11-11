package telemetry

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// SetupLogger initializes the process-wide slog logger per normative D6.
func SetupLogger(levelStr string, format string, out io.Writer) *slog.Logger {
	if out == nil {
		out = os.Stdout
	}

	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if strings.ToLower(format) == "text" {
		handler = slog.NewTextHandler(out, opts)
	} else {
		handler = slog.NewJSONHandler(out, opts)
	}

	logger := slog.New(CorrelatingHandler{handler})
	slog.SetDefault(logger)
	return logger
}
