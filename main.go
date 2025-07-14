package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/avast/retry-go/v4"
)

// PR represents a GitHub pull request with all relevant information
type PR struct {
	Number         int       `json:"number"`
	Title          string    `json:"title"`
	User           User      `json:"user"`
	State          string    `json:"state"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	HTMLURL        string    `json:"html_url"`
	Draft          bool      `json:"draft"`
	ReviewComments int       `json:"review_comments"`
	Comments       int       `json:"comments"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	RequestedReviewers []User `json:"requested_reviewers"`
}

// User represents a GitHub user
type User struct {
	Login string `json:"login"`
}

// Review represents a pull request review
type Review struct {
	User  User   `json:"user"`
	State string `json:"state"`
}

// SearchResult represents the GitHub search API response
type SearchResult struct {
	Items []PR `json:"items"`
}

const (
	defaultTimeout          = 30 * time.Second
	defaultWatchInterval    = 10
	maxPerPage              = 100
	retryAttempts           = 3
	retryDelay              = time.Second
	retryMaxDelay           = 10 * time.Second
	enrichRetryAttempts     = 2
	enrichRetryDelay        = 500 * time.Millisecond
	enrichRetryMaxDelay     = 2 * time.Second
	idleConnTimeout         = 30 * time.Second
	maxIdleConns            = 10
	maxIdleConnsPerHost     = 2
	maxTitleLength          = 60
	minPRURLParts           = 7
	apiUserEndpoint         = "https://api.github.com/user"
	apiSearchIssuesEndpoint = "https://api.github.com/search/issues"
	apiReposPullsEndpoint   = "https://api.github.com/repos/%s/%s/pulls/%d"
	acceptHeader            = "application/vnd.github.v3+json"
	userAgentHeader         = "github-pr-notifier-cli"
)

func main() {
	var (
		watch         = flag.Bool("watch", false, "Continuously watch for PR updates")
		watchInterval = flag.Int("watch-interval", defaultWatchInterval, "Watch interval in minutes (default: 10)")
		all           = flag.Bool("all", false, "Show all PRs (not just those blocking on you)")
		notify        = flag.Bool("notify", false, "Watch for PRs and notify when they become newly blocking")
		verbose       bool
	)
	flag.BoolVar(&verbose, "verbose", false, "Show log messages for API calls")
	flag.Parse()

	// Set up logger
	var logger *log.Logger
	if verbose {
		logger = log.New(os.Stderr, "[github-pr-notifier] ", log.Ltime)
	} else {
		logger = log.New(io.Discard, "", 0)
	}

	// Set up HTTP client with timeout
	httpClient := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        maxIdleConns,
			IdleConnTimeout:     idleConnTimeout,
			DisableKeepAlives:   false,
			DisableCompression:  false,
			MaxIdleConnsPerHost: maxIdleConnsPerHost,
		},
	}

	token, err := getGitHubToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting GitHub token: %v\n", err)
		os.Exit(1)
	}

	username, err := getCurrentUser(token, logger, httpClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting current user: %v\n", err)
		os.Exit(1)
	}

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupts gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Println("Received interrupt signal, shutting down...")
		cancel()
	}()

	// If either watch or notify is set, run in watch mode
	if *watch || *notify {
		runWatchMode(ctx, token, username, !*all, *notify, *watchInterval, logger, httpClient)
	} else {
		// One-time display
		prs, err := fetchPRsWithRetry(ctx, token, username, logger, httpClient)
		if err != nil {
			if err == context.Canceled {
				fmt.Fprintf(os.Stderr, "\nOperation cancelled\n")
			} else {
				fmt.Fprintf(os.Stderr, "Error fetching PRs: %v\n", err)
			}
			os.Exit(1)
		}
		displayPRs(prs, username, !*all)
	}
}

func getGitHubToken() (string, error) {
	cmd := exec.Command("gh", "auth", "token")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get auth token: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func getCurrentUser(token string, logger *log.Logger, httpClient *http.Client) (string, error) {
	var username string

	err := retry.Do(
		func() error {
			logger.Printf("Making API call to GET %s", apiUserEndpoint)
			req, err := http.NewRequest("GET", apiUserEndpoint, nil)
			if err != nil {
				return err
			}

			req.Header.Set("Authorization", "token "+token)
			req.Header.Set("Accept", acceptHeader)
			req.Header.Set("User-Agent", userAgentHeader)

			resp, err := httpClient.Do(req)
			if err != nil {
				logger.Printf("HTTP request failed: %v", err)
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusUnauthorized {
				return errors.New("invalid GitHub token")
			}
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, body)
			}

			var user struct {
				Login string `json:"login"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
				return err
			}

			username = user.Login
			return nil
		},
		retry.Attempts(retryAttempts),
		retry.Delay(retryDelay),
		retry.MaxDelay(retryMaxDelay),
		retry.DelayType(retry.BackOffDelay),
		retry.LastErrorOnly(true),
		retry.OnRetry(func(n uint, err error) {
			logger.Printf("Retry attempt %d after error: %v", n+1, err)
		}),
	)

	return username, err
}

func fetchPRsWithRetry(ctx context.Context, token, username string, logger *log.Logger, httpClient *http.Client) ([]PR, error) {
	var prs []PR

	err := retry.Do(
		func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			result, err := fetchPRs(ctx, token, username, logger, httpClient)
			if err != nil {
				return err
			}
			prs = result
			return nil
		},
		retry.Context(ctx),
		retry.Attempts(retryAttempts),
		retry.Delay(retryDelay),
		retry.MaxDelay(retryMaxDelay),
		retry.DelayType(retry.BackOffDelay),
		retry.LastErrorOnly(true),
		retry.OnRetry(func(n uint, err error) {
			logger.Printf("Retry attempt %d for fetchPRs: %v", n+1, err)
		}),
	)

	return prs, err
}

func fetchPRs(ctx context.Context, token, username string, logger *log.Logger, httpClient *http.Client) ([]PR, error) {
	// Build the search query
	query := fmt.Sprintf("involves:%s type:pr state:open", username)

	// Properly encode the URL parameters
	params := url.Values{}
	params.Add("q", query)
	params.Add("per_page", fmt.Sprintf("%d", maxPerPage))
	params.Add("sort", "updated")

	apiURL := fmt.Sprintf("%s?%s", apiSearchIssuesEndpoint, params.Encode())

	logger.Printf("Making API call to GET %s", apiURL)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "github-pr-notifier-cli")

	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Printf("HTTP request failed after %v: %v", time.Since(start), err)
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("request timed out after %v", time.Since(start))
		}
		return nil, err
	}
	defer resp.Body.Close()
	logger.Printf("Response received after %v, status: %d", time.Since(start), resp.StatusCode)

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("invalid GitHub token")
	}
	if resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API rate limit or access forbidden: %s", body)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, body)
	}

	var result SearchResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	logger.Printf("Found %d PRs", len(result.Items))

	// Fetch detailed PR info for each PR to get review status
	for i := range result.Items {
		pr := &result.Items[i]
		if err := enrichPRData(ctx, token, pr, logger, httpClient); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil, err
			}
			// Continue even if we can't enrich one PR
			logger.Printf("Failed to enrich PR #%d: %v", pr.Number, err)
			continue
		}
	}

	return result.Items, nil
}

func enrichPRData(ctx context.Context, token string, pr *PR, logger *log.Logger, httpClient *http.Client) error {
	// Extract repo and number from URL
	parts := strings.Split(pr.HTMLURL, "/")
	if len(parts) < minPRURLParts {
		return errors.New("invalid PR URL")
	}
	owner := parts[3]
	repo := parts[4]

	// Fetch PR details
	url := fmt.Sprintf(apiReposPullsEndpoint, owner, repo, pr.Number)

	return retry.Do(
		func() error {
			logger.Printf("Making API call to GET %s", url)
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return err
			}

			req.Header.Set("Authorization", "token "+token)
			req.Header.Set("Accept", acceptHeader)
			req.Header.Set("User-Agent", userAgentHeader)

			resp, err := httpClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusNotFound {
				return errors.New("PR not found")
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("failed to fetch PR details (status %d)", resp.StatusCode)
			}

			// Update PR with detailed info
			if err := json.NewDecoder(resp.Body).Decode(pr); err != nil {
				return err
			}

			return nil
		},
		retry.Context(ctx),
		retry.Attempts(enrichRetryAttempts),
		retry.Delay(enrichRetryDelay),
		retry.MaxDelay(enrichRetryMaxDelay),
		retry.DelayType(retry.BackOffDelay),
		retry.LastErrorOnly(true),
	)
}

func isBlockingOnUser(pr PR, username string) bool {
	// Check if user is in requested reviewers
	for _, reviewer := range pr.RequestedReviewers {
		if reviewer.Login == username {
			return true
		}
	}
	return false
}

func displayPRs(prs []PR, username string, blockingOnly bool) {
	// Split PRs into incoming (authored by others) and outgoing (authored by you)
	var incoming, outgoing []PR
	for _, pr := range prs {
		if pr.User.Login == username {
			outgoing = append(outgoing, pr)
		} else {
			incoming = append(incoming, pr)
		}
	}

	// Count blocking PRs
	var blockingCount int
	for _, pr := range incoming {
		if isBlockingOnUser(pr, username) {
			blockingCount++
		}
	}

	// Display incoming PRs (authored by others)
	if len(incoming) > 0 && (!blockingOnly || blockingCount > 0) {
		if blockingOnly {
			fmt.Printf("\n%d PR%s awaiting your review\n\n", blockingCount, pluralize(blockingCount))
		} else {
			fmt.Printf("\nIncoming PRs\n\n")
		}

		for _, pr := range incoming {
			if blockingOnly && !isBlockingOnUser(pr, username) {
				continue
			}
			displayPR(pr, username)
		}
	}

	// Display outgoing PRs (authored by you) - only if --all flag is used
	if len(outgoing) > 0 && !blockingOnly {
		fmt.Printf("\nYour PRs\n\n")
		for _, pr := range outgoing {
			displayPR(pr, username)
		}
	}

	if blockingOnly && blockingCount == 0 {
		fmt.Println("\n✓ No PRs awaiting your review")
	}
}

func pluralize(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func displayPR(pr PR, username string) {
	// Format age
	age := formatAge(pr.UpdatedAt)

	// Single line format with bullet: • title • age • URL
	fmt.Printf("  • %s • %s • %s\n",
		truncate(pr.Title, maxTitleLength),
		age,
		pr.HTMLURL)
}

func formatAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%dw", int(d.Hours()/(24*7)))
	default:
		return fmt.Sprintf("%dmo", int(d.Hours()/(24*30)))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func runWatchMode(ctx context.Context, token, username string, blockingOnly bool, notifyMode bool, intervalMinutes int, logger *log.Logger, httpClient *http.Client) {
	// Clear screen
	fmt.Print("\033[H\033[2J")

	var lastPRs []PR
	ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
	defer ticker.Stop()

	// Initial fetch and display (unless notify-only mode)
	prs, err := fetchPRsWithRetry(ctx, token, username, logger, httpClient)
	if err != nil {
		if err != context.Canceled {
			fmt.Fprintf(os.Stderr, "Error fetching PRs: %v\n", err)
		}
	} else {
		lastPRs = prs

		// Display PRs unless we're in notify-only mode
		if !notifyMode {
			displayHeader()
			displayPRs(prs, username, blockingOnly)
		} else {
			// In notify mode, show what we're watching for
			if blockingOnly {
				fmt.Println("Watching for newly blocking PRs...")
			} else {
				fmt.Println("Watching for all new PRs...")
			}
		}
	}

	// Set up interrupt handler
	done := make(chan bool)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if scanner.Text() == "q" {
				done <- true
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nShutting down...")
			return
		case <-ticker.C:
			prs, err := fetchPRsWithRetry(ctx, token, username, logger, httpClient)
			if err != nil {
				if err != context.Canceled {
					fmt.Fprintf(os.Stderr, "Error fetching PRs: %v\n", err)
				}
				continue
			}

			// If not in notify-only mode, clear and redraw
			if !notifyMode {
				fmt.Print("\033[H\033[2J")
				displayHeader()
				displayPRs(prs, username, blockingOnly)
			}

			// Check for new PRs based on mode
			if notifyMode {
				if blockingOnly {
					// Notify only for newly blocking PRs
					for _, pr := range prs {
						if isBlockingOnUser(pr, username) && !wasBlockingBefore(pr, lastPRs, username) {
							fmt.Printf("\n⚡ NEW BLOCKING PR:\n")
							displayPR(pr, username)
							fmt.Println()
						}
					}
				} else {
					// --notify --all: Show all new PRs
					for _, pr := range prs {
						if !wasPRBefore(pr, lastPRs) {
							fmt.Printf("\n✨ NEW PR:\n")
							displayPR(pr, username)
							fmt.Println()
						}
					}
				}
			} else {
				// In watch mode, just note newly blocking PRs
				for _, pr := range prs {
					if isBlockingOnUser(pr, username) && !wasBlockingBefore(pr, lastPRs, username) {
						fmt.Printf("\n⚡ NEW BLOCKING PR: %s\n", pr.Title)
					}
				}
			}

			lastPRs = prs

		case <-done:
			fmt.Println("\nExiting...")
			return
		}
	}
}

func displayHeader() {
	fmt.Println("Press 'q' to quit")
}

func wasBlockingBefore(pr PR, lastPRs []PR, username string) bool {
	for _, oldPR := range lastPRs {
		if oldPR.Number == pr.Number && oldPR.Repository.FullName == pr.Repository.FullName {
			return isBlockingOnUser(oldPR, username)
		}
	}
	return false
}

func wasPRBefore(pr PR, lastPRs []PR) bool {
	for _, oldPR := range lastPRs {
		if oldPR.Number == pr.Number && oldPR.Repository.FullName == pr.Repository.FullName {
			return true
		}
	}
	return false
}
