package migrations

import (
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

//go:embed *.sql
var files embed.FS

// SQL is retained for the immutable version-one checksum contract.
var SQL = mustRead("001_controller.sql")

func mustRead(name string) string {
	b, e := files.ReadFile(name)
	if e != nil {
		panic(e)
	}
	return string(b)
}

type Migration struct {
	Version int
	SQL     string
}

func All() []Migration {
	entries, e := files.ReadDir(".")
	if e != nil {
		panic(e)
	}
	out := []Migration{}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			v, e := strconv.Atoi(strings.SplitN(entry.Name(), "_", 2)[0])
			if e != nil || v < 1 {
				panic("invalid migration name")
			}
			out = append(out, Migration{v, mustRead(entry.Name())})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != i+1 {
			panic(fmt.Sprintf("noncontiguous controller migrations at %d", m.Version))
		}
	}
	return out
}
