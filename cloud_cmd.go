package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/yaltayeh/hasr/internal/cloud"
	"github.com/yaltayeh/hasr/internal/cloud/aws"
)

// runCloud is `hasr cloud <provider> --from RAW_DIR`: it converts a collector's
// raw folder into the provider-neutral inventory on stdout. It reads files
// only; it never calls a cloud API and never handles credentials.
// Exit codes: 0 ok, 1 converted but some collector calls had failed, 2 usage
// or input error.
func runCloud(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	provider := args[0]
	fs := flag.NewFlagSet("cloud "+provider, flag.ContinueOnError)
	from := fs.String("from", "", "folder written by the provider's collector (required)")
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage); fs.PrintDefaults() }
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *from == "" || fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	tool := cloud.Tool{Name: "hasr", Go: runtime.Version()}
	now := time.Now().UTC().Truncate(time.Second)

	var inv cloud.Inventory
	var err error
	switch provider {
	case aws.Provider:
		inv, err = aws.Convert(*from, tool, now)
	default:
		fmt.Fprintf(os.Stderr, "unknown cloud provider %q (supported: aws)\n", provider)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(inv); err != nil {
		fmt.Fprintln(os.Stderr, "encoding JSON:", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "%d endpoints from %d scope(s); %d of %d collector calls failed\n",
		len(inv.Endpoints), len(inv.Scopes), inv.Collection.FailedCalls, inv.Collection.Calls)
	if inv.Collection.FailedCalls > 0 {
		return 1
	}
	return 0
}
