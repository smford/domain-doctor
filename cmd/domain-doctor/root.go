package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	customResolver string
	globalTimeout  time.Duration
	servePort      string
	showVersion    bool
)

func sanitizeDomain(input string) string {
	raw := strings.TrimSpace(input)
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err == nil && u.Host != "" {
			raw = u.Host
		}
	}
	// Strip any path component if user typed domain.com/path
	if idx := strings.Index(raw, "/"); idx != -1 {
		raw = raw[:idx]
	}
	// Strip port if user typed domain.com:8080
	if idx := strings.Index(raw, ":"); idx != -1 {
		raw = raw[:idx]
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
}

var rootCmd = &cobra.Command{
	Use:   "domain-doctor [command|domain]",
	Short: "Comprehensive domain reliability, DNS delegation, and security audit tool",
	Long: `domain-doctor performs deep, authoritative-first diagnostics on internet domains.
Evaluates DNS delegation, RFC 2308 negative caching, mail authentication (SPF/DMARC/DKIM/STARTTLS),
transport security, BGP resilience, attack surface, and registration posture.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if showVersion {
			fmt.Println(formatVersion())
			return nil
		}

		if servePort != "" {
			return runDaemon(servePort)
		}

		if len(args) == 1 {
			// Default to scan mode if a single domain argument is passed
			return runScan(cmd.Context(), sanitizeDomain(args[0]), scanJSON, scanTUI, scanMermaid)
		}

		return cmd.Help()
	},
}

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion script",
	Long: `To load completions:

Bash:
  $ source <(domain-doctor completion bash)

Zsh:
  $ source <(domain-doctor completion zsh)

Fish:
  $ domain-doctor completion fish | source
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			return cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			return cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		default:
			return fmt.Errorf("unsupported shell: %s", args[0])
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&customResolver, "resolver", "r", "", "custom DNS resolver (ip:port)")
	rootCmd.PersistentFlags().DurationVarP(&globalTimeout, "timeout", "t", 25*time.Second, "global audit timeout")
	rootCmd.Flags().StringVarP(&servePort, "port", "p", "", "run background health daemon on port (for container checks)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "display version information")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(watchCmd)
	rootCmd.AddCommand(snapshotCmd)
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(lintCmd)
	rootCmd.AddCommand(diagramCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(auditDriftCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(completionCmd)
}

func runDaemon(port string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","app":"domain-doctor"}`))
	})

	addr := ":" + port
	fmt.Printf("domain-doctor health daemon running on %s\n", addr)
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start HTTP health daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		port := servePort
		if port == "" {
			port = "8080"
		}
		return runDaemon(port)
	},
}

func Execute() {
	if err := rootCmd.ExecuteContext(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
