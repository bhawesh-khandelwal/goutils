// Package logging provides structured logging via zerolog.
//
// Call Init() in main() to set up file rotation and console output.
// Then use the level functions with a component name:
//
//	logging.Info("api").Str("key", k).Msg("secret revealed")
//	logging.Error("scheduler").Err(err).Msg("job failed")
//
// For package-level constants to avoid typos:
//
//	const component = "api"
//	logging.Info(component).Msg("started")
package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"gopkg.in/natefinch/lumberjack.v2"
)

// ConsoleMode defines how logs are output to console.
type ConsoleMode int

const (
	ConsoleQuiet  ConsoleMode = iota // No console output
	ConsoleNormal                    // Colored console output to stderr
	ConsoleTUI                       // Route through TUI handler
)

// Config holds initialization parameters for the logging system.
type Config struct {
	Dir        string      // Log file directory
	Filename   string      // Log file name
	MaxSize    int         // Max size in MB before rotation
	MaxBackups int         // Number of rotated files to keep
	MaxAge     int         // Days to retain old files
	Compress   bool        // Compress rotated files
	Console    ConsoleMode // Console output mode
	Level      zerolog.Level

	// Audit, when true, also writes every Audit event to its own file,
	// AuditFilename in Dir, beside the main log. It rotates at least hourly
	// so audit events reach the archive within the hour however few there
	// are, and its rotated files archive under logs/audit/ (see ArchiveKey).
	Audit bool
}

// AuditFilename is the audit log's file name. Rotated copies are named
// audit-<timestamp>.txt.gz, which is how ArchiveKey recognizes them.
const AuditFilename = "audit.txt"

// auditRotateEvery bounds how long an audit event waits on disk before its
// file is rotated and becomes archivable.
const auditRotateEvery = time.Hour

// Root is the global logger. Set by Init(), defaults to stderr.
// Every line it writes passes Redact (see redact.go).
var Root = zerolog.New(RedactWriter(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})).
	With().Timestamp().Logger().Level(zerolog.InfoLevel)

var tuiHandler io.Writer

// auditRoot is the logger Audit writes to: Root plus the audit file when one
// is configured, otherwise Root itself.
var auditRoot *zerolog.Logger

// SetTUIHandler sets a custom writer for TUI mode console output.
// Must be called before Init.
func SetTUIHandler(w io.Writer) {
	tuiHandler = w
}

// Init sets up the global root logger with file rotation and optional console output.
// Must be called once from main(), before spawning goroutines.
func Init(cfg Config) error {
	if cfg.Dir != "" {
		if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
			return fmt.Errorf("logging: create dir: %w", err)
		}
	}

	rotator := &lumberjack.Logger{
		Filename:   filepath.Join(cfg.Dir, cfg.Filename),
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	}

	go reopenWhenMoved(rotator, reopenCheckEvery)

	writers := []io.Writer{rotator}

	switch cfg.Console {
	case ConsoleNormal:
		writers = append(writers, newConsoleWriter(os.Stderr))
	case ConsoleTUI:
		if tuiHandler != nil {
			writers = append(writers, newConsoleWriter(tuiHandler))
		}
	}

	zerolog.TimeFieldFormat = time.RFC3339Nano
	Root = zerolog.New(RedactWriter(zerolog.MultiLevelWriter(writers...))).
		With().Timestamp().Logger().
		Level(cfg.Level)

	auditRoot = nil
	if cfg.Audit {
		auditFile := &lumberjack.Logger{
			Filename: filepath.Join(cfg.Dir, AuditFilename),
			MaxSize:  cfg.MaxSize,
			MaxAge:   cfg.MaxAge,
			Compress: cfg.Compress,
		}
		l := zerolog.New(RedactWriter(zerolog.MultiLevelWriter(append(writers, auditFile)...))).
			With().Timestamp().Logger().
			Level(zerolog.InfoLevel)
		auditRoot = &l
		go rotateWhenWritten(auditFile, auditRotateEvery)
		go reopenWhenMoved(auditFile, reopenCheckEvery)
	}
	return nil
}

// reopenCheckEvery bounds how long a process writes to a log file another
// process rotated away before it is back on the live one.
const reopenCheckEvery = 10 * time.Second

// reopenWhenMoved closes f whenever the file at its path is no longer the one
// it was writing to, so the next write reopens the path. Two processes write
// one log file during a rolling deploy (both are the same instance): when one
// rotates, the other keeps writing to the renamed file, which is compressed
// and removed under it, and its lines are lost. A rotation of f's own moves
// the path too; closing then costs one reopen.
func reopenWhenMoved(f *lumberjack.Logger, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var seen os.FileInfo
	for range ticker.C {
		seen = reopenIfMoved(f, seen)
	}
}

// reopenIfMoved is one check of reopenWhenMoved: it returns the file now at
// f's path, and closes f when that is not the file seen last time.
func reopenIfMoved(f *lumberjack.Logger, seen os.FileInfo) os.FileInfo {
	now, err := os.Stat(f.Filename)
	if err != nil {
		now = nil
	}
	if seen != nil && (now == nil || !os.SameFile(seen, now)) {
		if err := f.Close(); err != nil {
			Error("logging").Err(err).Str("file", f.Filename).Msg("failed to reopen moved log file")
		}
	}
	return now
}

// rotateWhenWritten rotates f every interval when it holds anything, so a
// low-volume log still produces a file to archive.
func rotateWhenWritten(f *lumberjack.Logger, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if info, err := os.Stat(f.Filename); err == nil && info.Size() > 0 {
			if err := f.Rotate(); err != nil {
				Error("audit").Err(err).Msg("failed to rotate audit log")
			}
		}
	}
}

// Level functions — return a *zerolog.Event tagged with the component name.

func Trace(component string) *zerolog.Event { return Root.Trace().Str("component", component) }
func Debug(component string) *zerolog.Event { return Root.Debug().Str("component", component) }
func Info(component string) *zerolog.Event  { return Root.Info().Str("component", component) }
func Warn(component string) *zerolog.Event  { return Root.Warn().Str("component", component) }
func Error(component string) *zerolog.Event { return Root.Error().Str("component", component) }
func Fatal(component string) *zerolog.Event { return Root.Fatal().Str("component", component) }

// newConsoleWriter creates a colored console writer.
func newConsoleWriter(out io.Writer) zerolog.ConsoleWriter {
	return zerolog.ConsoleWriter{
		Out:        out,
		TimeFormat: "2006/01/02 15:04:05.000",
		NoColor:    false,
		PartsOrder: []string{
			zerolog.TimestampFieldName,
			zerolog.LevelFieldName,
			"component",
			zerolog.MessageFieldName,
		},
		FieldsExclude: []string{"component"},
		FormatLevel: func(i any) string {
			if ll, ok := i.(string); ok {
				switch ll {
				case "info":
					return "\033[36mINF\033[0m"
				case "warn":
					return "\033[33mWRN\033[0m"
				case "error":
					return "\033[31mERR\033[0m"
				case "debug":
					return "\033[35mDBG\033[0m"
				default:
					return ll
				}
			}
			return "???"
		},
		FormatFieldName: func(i any) string {
			return fmt.Sprintf("\033[2m%s=\033[0m", i)
		},
		FormatFieldValue: func(i any) string {
			return fmt.Sprintf("%s", i)
		},
	}
}
