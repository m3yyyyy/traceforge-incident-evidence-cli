package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/m3yyyyy/traceforge-incident-evidence-cli/internal/correlate"
	"github.com/m3yyyyy/traceforge-incident-evidence-cli/internal/evidence"
	"github.com/m3yyyyy/traceforge-incident-evidence-cli/internal/ingest"
	"github.com/m3yyyyy/traceforge-incident-evidence-cli/internal/model"
	"github.com/m3yyyyy/traceforge-incident-evidence-cli/internal/redact"
)

const usage = `TraceForge Incident Evidence CLI

Usage:
  traceforge analyze --incident ID --input PATH [--input PATH] --output DIR
  traceforge verify --bundle DIR
  traceforge version

Commands:
  analyze   Stream logs, redact credentials, correlate events and create a bundle
  verify    Recompute SHA-256 digests and detect missing or modified artifacts
  version   Print build version

Run "traceforge <command> --help" for command-specific options.
`

var incidentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type App struct {
	Version string
	Stdout  io.Writer
	Stderr  io.Writer
	Now     func() time.Time
}

func (app App) Run(args []string) int {
	if app.Stdout == nil {
		app.Stdout = io.Discard
	}
	if app.Stderr == nil {
		app.Stderr = io.Discard
	}
	if app.Now == nil {
		app.Now = time.Now
	}
	if len(args) == 0 {
		fmt.Fprint(app.Stdout, usage)
		return 0
	}

	var err error
	switch args[0] {
	case "analyze":
		err = app.analyze(args[1:])
	case "verify":
		err = app.verify(args[1:])
	case "version", "--version", "-version":
		fmt.Fprintf(app.Stdout, "traceforge %s\n", app.Version)
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(app.Stdout, usage)
		return 0
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(app.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func (app App) analyze(args []string) error {
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	flags.SetOutput(app.Stdout)
	flags.Usage = func() {
		fmt.Fprintln(app.Stdout, "Usage: traceforge analyze --incident ID --input PATH [--input PATH] --output DIR")
		flags.PrintDefaults()
	}
	var inputs stringList
	var incidentID, output, generatedAt string
	var maxEvents, maxLineBytes int
	flags.Var(&inputs, "input", "log file or directory; repeat for multiple inputs")
	flags.StringVar(&incidentID, "incident", "", "incident identifier (letters, numbers, dot, dash, underscore)")
	flags.StringVar(&output, "output", "", "new or empty evidence bundle directory")
	flags.StringVar(&generatedAt, "generated-at", "", "RFC3339 generation time for reproducible output (default: now)")
	flags.IntVar(&maxEvents, "max-events", ingest.DefaultMaxEvents, "maximum events accepted before failing closed")
	flags.IntVar(&maxLineBytes, "max-line-bytes", ingest.DefaultMaxLineBytes, "maximum bytes accepted for one log line")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	if !incidentPattern.MatchString(incidentID) {
		return errors.New("--incident must be 1-128 characters using letters, numbers, dot, dash or underscore")
	}
	if len(inputs) == 0 {
		return errors.New("at least one --input is required")
	}
	if strings.TrimSpace(output) == "" {
		return errors.New("--output is required")
	}

	createdAt := app.Now().UTC()
	if generatedAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, generatedAt)
		if err != nil {
			return fmt.Errorf("parse --generated-at: %w", err)
		}
		createdAt = parsed.UTC()
	}
	reader, err := ingest.New(ingest.Config{MaxEvents: maxEvents, MaxLineBytes: maxLineBytes}, redact.New())
	if err != nil {
		return err
	}
	result, err := reader.Read(inputs)
	if err != nil {
		return err
	}
	timelineEvents, correlations := correlate.Build(result.Events)
	timeline := model.Timeline{
		SchemaVersion: model.SchemaVersion,
		IncidentID:    incidentID,
		GeneratedAt:   createdAt,
		Sources:       result.Sources,
		EventCount:    len(timelineEvents),
		Correlations:  correlations,
		Events:        timelineEvents,
	}
	manifest, err := evidence.WriteBundle(output, timeline)
	if err != nil {
		return err
	}
	redactions := 0
	for _, source := range result.Sources {
		redactions += source.Redactions
	}
	fmt.Fprintf(app.Stdout, "bundle created: %s\n", output)
	fmt.Fprintf(app.Stdout, "incident: %s | sources: %d | events: %d | correlations: %d | redactions: %d\n", incidentID, len(result.Sources), len(timelineEvents), len(correlations), redactions)
	fmt.Fprintf(app.Stdout, "artifacts: %s, manifest.json\n", strings.Join(evidence.SortedArtifactNames(manifest), ", "))
	return nil
}

func (app App) verify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(app.Stdout)
	flags.Usage = func() {
		fmt.Fprintln(app.Stdout, "Usage: traceforge verify --bundle DIR")
		flags.PrintDefaults()
	}
	var bundle string
	flags.StringVar(&bundle, "bundle", "", "evidence bundle directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	if strings.TrimSpace(bundle) == "" {
		return errors.New("--bundle is required")
	}
	result, err := evidence.Verify(bundle)
	if err != nil {
		return err
	}
	fmt.Fprintf(app.Stdout, "verified: %s | incident: %s | artifacts: %d | algorithm: SHA-256\n", bundle, result.IncidentID, result.Artifacts)
	return nil
}

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("input path cannot be empty")
	}
	*values = append(*values, value)
	return nil
}
