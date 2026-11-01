package main

import (
	"fmt"
	"os"

	"github.com/loowtime/netrivox/internal/app"
)

func main() {
	if err := app.NewCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
