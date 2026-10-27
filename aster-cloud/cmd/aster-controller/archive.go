package main

import (
	"aster/cloud/internal/controllerbackup"
	"encoding/json"
	"flag"
	"io"
	"os"
)

func inspectArchive(args []string) error {
	flags := flag.NewFlagSet("migration-inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	archive := flags.String("archive", "", "private encrypted input")
	key := flags.String("key-file", "", "private recovery key input")
	controller := flags.String("controller-id", "", "independently expected source identity")
	operation := flags.String("operation", "", "independently expected operation identity")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return controllerbackup.ErrInvalid
	}
	proof, err := controllerbackup.InspectFiles(*archive, *key, *controller, *operation)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(proof)
}
