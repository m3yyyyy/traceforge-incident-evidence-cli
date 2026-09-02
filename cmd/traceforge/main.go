package main

import (
	"os"

	"github.com/m3yyyyy/traceforge-incident-evidence-cli/internal/cli"
)

var version = "dev"

func main() {
	app := cli.App{Version: version, Stdout: os.Stdout, Stderr: os.Stderr}
	os.Exit(app.Run(os.Args[1:]))
}
