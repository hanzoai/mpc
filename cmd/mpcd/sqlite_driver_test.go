package main

import (
	"database/sql"
	"slices"
	"testing"
)

// TestSQLiteDriverRegisteredOnce pins the invariant that made this whole package
// unrunnable: mpcd links three SQLite-backed stores in one process — luxfi/mpc's
// pkg/infra SQLiteMeta, hanzoai/base's core, and hanzoai/tasks' shard store — and
// database/sql panics if two of them register the driver NAME "sqlite".
//
//	panic: sql: Register called twice for driver sqlite
//	modernc.org/sqlite.init.0()  modernc.org/sqlite@v1.51.0/sqlite.go:57
//
// pkg/infra used to blank-import modernc.org/sqlite while the others reach SQLite
// through github.com/hanzoai/sqlite, so the second init() killed the process
// before main — and `go test ./...` here could not even start. Every store now
// goes through hanzoai/sqlite, the one package that owns that name (it delegates
// to modernc under !cgo and hanzoai/csqlite+SQLCipher under cgo).
//
// The teeth are in the import graph, not the assertions: this file is compiled
// into the mpcd package, so a regression to a second registrar panics during
// init and takes the whole test binary down before any test runs. The assertions
// below just make the intent legible.
func TestSQLiteDriverRegisteredOnce(t *testing.T) {
	drivers := sql.Drivers()

	if !slices.Contains(drivers, "sqlite") {
		t.Fatalf("no %q driver registered; hanzoai/sqlite must register it: %v", "sqlite", drivers)
	}

	// sql.Drivers is deduplicated by construction (sql.Register panics on a
	// duplicate name), so reaching this line already proves single registration.
	var n int
	for _, d := range drivers {
		if d == "sqlite" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("driver %q registered %d times, want 1", "sqlite", n)
	}
}
