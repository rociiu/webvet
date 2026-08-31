package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/rociiu/webvet/analyzer"
	"github.com/rociiu/webvet/report"
	"github.com/rociiu/webvet/rules"
)

const version = "0.1.0-dev"

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "version":
			fmt.Println("webvet", version)
			return 0
		case "rules":
			return printRules()
		case "routes":
			return runRoutes(args[1:])
		}
	}
	fs := flag.NewFlagSet("webvet", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "text", "output format: text or json")
	severity := fs.String("severity", "info", "minimum severity")
	disable := fs.String("disable", "", "comma-separated rule IDs to disable")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	min, err := report.ParseSeverity(*severity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "webvet:", err)
		return 2
	}
	result, err := analyzer.Run(fs.Args(), analyzer.Options{Disabled: parseDisable(*disable)})
	if err != nil {
		fmt.Fprintln(os.Stderr, "webvet:", err)
		return 2
	}
	filtered := result.Findings[:0]
	for _, f := range result.Findings {
		if f.Severity >= min {
			filtered = append(filtered, f)
		}
	}
	switch *format {
	case "text":
		err = report.WriteText(os.Stdout, filtered)
	case "json":
		err = report.WriteJSON(os.Stdout, filtered)
	default:
		fmt.Fprintf(os.Stderr, "webvet: unknown format %q\n", *format)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "webvet:", err)
		return 2
	}
	if len(filtered) > 0 {
		return 1
	}
	return 0
}
func runRoutes(args []string) int {
	fs := flag.NewFlagSet("webvet routes", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	result, err := analyzer.Run(fs.Args(), analyzer.Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "webvet:", err)
		return 2
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "METHOD\tROUTE\tFRAMEWORK\tHANDLER\tMIDDLEWARE")
	for _, r := range result.Routes {
		m := make([]string, len(r.Middleware))
		for i, x := range r.Middleware {
			m[i] = x.Name
		}
		if len(m) == 0 {
			m = []string{"-"}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Method, r.Path, r.Framework, r.Handler, strings.Join(m, ", "))
	}
	w.Flush()
	return 0
}
func printRules() int {
	m := rules.MetadataList()
	sort.Slice(m, func(i, j int) bool { return m[i].ID < m[j].ID })
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "RULE\tSEVERITY\tCONFIDENCE\tDESCRIPTION")
	for _, x := range m {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", x.ID, x.Severity, x.Confidence, x.Description)
	}
	w.Flush()
	return 0
}
func parseDisable(s string) map[string]bool {
	m := map[string]bool{}
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			m[x] = true
		}
	}
	return m
}
