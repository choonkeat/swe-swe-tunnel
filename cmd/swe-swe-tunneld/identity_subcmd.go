package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/choonkeat/swe-swe-tunnel/internal/control"
	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
)

// identityDBPath is where the daemon keeps the (unique → pubkey) table.
// Must match the path main() opens.
func identityDBPath(stateDir string) string {
	return filepath.Join(stateDir, "identities.db")
}

// runIdentityList prints every claimed name with its owner key, so the
// operator can see who holds what before releasing a name.
//
//	swe-swe-tunneld identity-list
func runIdentityList(args []string, stateDir string, stdout io.Writer, logger *slog.Logger) int {
	fs := newSubcmdFlagSet("identity-list")
	if err := fs.Parse(args); err != nil {
		logger.Error("identity-list: parse args", "err", err)
		return 2
	}
	store, err := identity.Open(identityDBPath(stateDir))
	if err != nil {
		logger.Error("identity-list: open store", "err", err)
		return 1
	}
	defer store.Close()

	entries, err := store.List(context.Background())
	if err != nil {
		logger.Error("identity-list: list", "err", err)
		return 1
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "UNIQUE\tPUBKEY\tCREATED\tLAST_SEEN")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			e.Unique,
			base64.RawStdEncoding.EncodeToString(e.Pubkey),
			e.CreatedAt.Format(time.RFC3339),
			e.LastSeenAt.Format(time.RFC3339),
		)
	}
	return flushErr(tw.Flush(), logger)
}

// runIdentityDelete releases a claimed name so another key can register
// it. With --purge-cert it also deletes that name's certificate files.
//
//	swe-swe-tunneld identity-delete [--purge-cert] [--apex example.com] <unique>
//
// A live session for the name is not dropped; it keeps working until it
// disconnects. To stop it immediately, also remove its key from the
// allowlist and send SIGHUP.
func runIdentityDelete(args []string, stateDir string, stdout io.Writer, logger *slog.Logger) int {
	fs := newSubcmdFlagSet("identity-delete")
	purgeCert := fs.Bool("purge-cert", false, "also delete the *.{unique}-tunnel.{apex} certificate files")
	apex := fs.String("apex", os.Getenv("SWE_TUNNEL_APEX"), "DNS apex (needed for --purge-cert; default $SWE_TUNNEL_APEX)")
	if err := fs.Parse(args); err != nil {
		logger.Error("identity-delete: parse args", "err", err)
		return 2
	}
	if fs.NArg() != 1 {
		logger.Error("identity-delete: expected exactly one <unique> argument", "got", fs.NArg())
		return 2
	}
	unique := fs.Arg(0)
	// Same shape check as Register. Also keeps the cert path below from
	// escaping the cert directory.
	if err := control.ValidateUnique(unique); err != nil {
		logger.Error("identity-delete: invalid unique", "unique", unique, "err", err)
		return 2
	}
	if *purgeCert && *apex == "" {
		logger.Error("identity-delete: --purge-cert needs --apex (or SWE_TUNNEL_APEX)")
		return 2
	}

	store, err := identity.Open(identityDBPath(stateDir))
	if err != nil {
		logger.Error("identity-delete: open store", "err", err)
		return 1
	}
	defer store.Close()

	ctx := context.Background()
	if _, err := store.Get(ctx, unique); errors.Is(err, identity.ErrNotFound) {
		logger.Error("identity-delete: no such name", "unique", unique)
		return 1
	} else if err != nil {
		logger.Error("identity-delete: get", "err", err)
		return 1
	}
	if err := store.Delete(ctx, unique); err != nil {
		logger.Error("identity-delete: delete", "err", err)
		return 1
	}
	fmt.Fprintf(stdout, "released %s\n", unique)

	if *purgeCert {
		base := filepath.Join(stateDir, "lego", "certificates",
			"_."+control.TunnelLabel(unique)+"."+*apex)
		for _, p := range []string{base + ".crt", base + ".key"} {
			switch err := os.Remove(p); {
			case err == nil:
				fmt.Fprintf(stdout, "removed %s\n", p)
			case errors.Is(err, os.ErrNotExist):
				// Nothing issued yet (or already gone). Not an error.
			default:
				logger.Error("identity-delete: remove cert file", "path", p, "err", err)
				return 1
			}
		}
		fmt.Fprintln(stdout, "restart the daemon to drop the cert from memory")
	}
	return 0
}

func flushErr(err error, logger *slog.Logger) int {
	if err != nil {
		logger.Error("write output", "err", err)
		return 1
	}
	return 0
}
