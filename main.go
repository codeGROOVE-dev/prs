package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/charmbracelet/lipgloss"
	"github.com/codeGROOVE-dev/sprinkler/pkg/client"
	"github.com/ready-to-review/turnclient/pkg/turn"
)

// PR represents a GitHub pull request with all relevant information.
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
	Repository     struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	RequestedReviewers []User `json:"requested_reviewers"`

	// Size information
	Additions    int `json:"additions"`
	Deletions    int `json:"deletions"`
	ChangedFiles int `json:"changed_files"`

	// Turn server metadata
	TurnResponse *turn.CheckResponse `json:"turn_response,omitempty"`
}

// User represents a GitHub user.
type User struct {
	Login string `json:"login"`
}

// Review represents a pull request review.
type Review struct {
	User  User   `json:"user"`
	State string `json:"state"`
}

// SearchResult represents the GitHub search API response.
type SearchResult struct {
	Items []PR `json:"items"`
}

// cacheEntry represents a cached Turn API response.
type cacheEntry struct {
	Response  *turn.CheckResponse `json:"response"`
	Timestamp time.Time           `json:"timestamp"`
}

// prRefreshTracker tracks the last refresh time for PRs to avoid duplicate API calls.
type prRefreshTracker struct {
	lastRefresh map[string]time.Time
	mu          sync.RWMutex
}

func newPRRefreshTracker() *prRefreshTracker {
	return &prRefreshTracker{
		lastRefresh: make(map[string]time.Time),
	}
}

func (t *prRefreshTracker) shouldRefresh(prURL string) bool {
	t.mu.RLock()
	lastTime, exists := t.lastRefresh[prURL]
	t.mu.RUnlock()
	
	if !exists {
		return true
	}
	
	return time.Since(lastTime) > time.Duration(prRefreshCooldownSecs)*time.Second
}

func (t *prRefreshTracker) markRefreshed(prURL string) {
	t.mu.Lock()
	t.lastRefresh[prURL] = time.Now()
	t.mu.Unlock()
}

const (
	defaultTimeout         = 30 * time.Second
	defaultWatchInterval   = 90 * time.Second
	maxPerPage             = 100
	retryAttempts          = 3
	retryDelay             = time.Second
	retryMaxDelay          = 10 * time.Second
	enrichRetries          = 2
	enrichDelay            = 500 * time.Millisecond
	enrichMaxDelay         = 2 * time.Second
	apiUserEndpoint        = "https://api.github.com/user"
	apiSearchEndpoint      = "https://api.github.com/search/issues"
	apiPullsEndpoint       = "https://api.github.com/repos/%s/%s/pulls/%d"
	defaultTurnServerURL   = "https://turn.ready-to-review.dev"
	defaultSprinklerURL    = "wss://hook.g.robot-army.dev/ws"
	maxConcurrent          = 20            // Increased for better throughput
	cacheTTL               = 2 * time.Hour // 2 hours
	prRefreshCooldownSecs  = 1             // Avoid refreshing same PR within 1 second
)

// Style definitions - modern minimalist palette
var (
	// Modern palette inspired by Vercel/Linear design
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E5484D")). // Modern red
			Bold(true)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8B8B8B")). // Neutral gray
			Bold(false)

	prTitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")). // Almost white
			Bold(false)

	ageStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666")).
			Italic(true)

	urlStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#3E63DD")). // Modern blue
			Underline(true)

	tagStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8B8B8B")).
			Bold(false)

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8B8B8B")) // Neutral gray

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#30A46C")). // Modern green
			Bold(true)
)

// isValidOrgName validates GitHub organization names.
func isValidOrgName(org string) bool {
	if org == "" || len(org) > 39 { // GitHub org name limit
		return false
	}
	for _, r := range org {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	// Cannot start or end with hyphen
	return org[0] != '-' && org[len(org)-1] != '-'
}

// turnCache handles caching of Turn API responses.
func turnCachePath(url string, updatedAt time.Time) string {
	dir, _ := os.UserCacheDir()
	if dir == "" {
		return "" // No cache if we can't find cache dir
	}

	// Simple hash for filename
	h := sha256.Sum256([]byte(url + updatedAt.Format(time.RFC3339)))
	return filepath.Join(dir, "github-pr-notifier", "turn-cache", hex.EncodeToString(h[:8])+".json")
}

func loadTurnCache(path string) (*turn.CheckResponse, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var entry cacheEntry
	if json.Unmarshal(data, &entry) != nil {
		return nil, false
	}

	// Check if expired
	if time.Since(entry.Timestamp) > cacheTTL {
		os.Remove(path)
		return nil, false
	}

	return entry.Response, true
}

func saveTurnCache(path string, response *turn.CheckResponse) {
	if path == "" {
		return
	}

	os.MkdirAll(filepath.Dir(path), 0o755)
	data, _ := json.Marshal(cacheEntry{Response: response, Timestamp: time.Now()})
	os.WriteFile(path, data, 0o644)
}

func main() {
	var (
		watch        = flag.Bool("watch", false, "Continuously watch for PR updates")
		blocked      = flag.Bool("blocked", false, "Show only PRs blocking on you")
		verbose      = flag.Bool("verbose", false, "Show verbose logging from libraries")
		excludeOrgs  = flag.String("exclude-orgs", "", "Comma-separated list of orgs to exclude")
		includeStale = flag.Bool("include-stale", false, "Include PRs that haven't been modified in 90 days")
	)
	flag.Parse()

	// Set up logger
	var logger *log.Logger
	if *verbose {
		logger = log.New(os.Stderr, "[github-pr-notifier] ", log.Ltime)
	} else {
		logger = log.New(io.Discard, "", 0)
	}

	// Set up HTTP client with optimized settings
	httpClient := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100, // Increased for better connection reuse
			MaxIdleConnsPerHost: 10,  // Allow more connections per host
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false,
			DisableCompression:  false,
			ForceAttemptHTTP2:   true, // Use HTTP/2 when available
		},
	}

	token, err := gitHubToken()
	if err != nil {
		logger.Printf("ERROR: Failed to get GitHub token: %v", err)
		fmt.Fprintf(os.Stderr, "error: failed to authenticate with github\n")
		os.Exit(1)
	}
	logger.Printf("INFO: Successfully retrieved GitHub token")

	username, err := currentUser(token, logger, httpClient)
	if err != nil {
		logger.Printf("ERROR: Failed to get current user: %v", err)
		fmt.Fprintf(os.Stderr, "error: failed to identify github user\n")
		os.Exit(1)
	}
	logger.Printf("INFO: Authenticated as user: %s", username)

	// Set up turn client
	var turnClient *turn.Client
	turnClient, err = turn.NewClient(defaultTurnServerURL)
	if err != nil {
		logger.Printf("ERROR: Failed to create turn client: %v", err)
		turnClient = nil
	} else {
		logger.Printf("INFO: Connected to turn server")
		if *verbose {
			turnClient.SetLogger(logger)
		}
		if token != "" {
			turnClient.SetAuthToken(token)
		}
	}

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupts gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Println("Received interrupt signal, shutting down...")
		cancel()
	}()

	// Parse excluded orgs
	var excludedOrgs []string
	if *excludeOrgs != "" {
		excludedOrgs = strings.Split(*excludeOrgs, ",")
		for i := range excludedOrgs {
			excludedOrgs[i] = strings.TrimSpace(excludedOrgs[i])
		}
	}
	
	if *watch {
		// Watch mode: hybrid WebSocket + polling with smart display updates
		runWatchMode(ctx, token, username, *blocked, *verbose, *includeStale, logger, httpClient, turnClient, excludedOrgs)
	} else {
		// Default: one-time display
		prs, err := fetchPRsWithRetry(ctx, token, username, logger, httpClient, turnClient, *verbose, "")
		if err != nil {
			if err == context.Canceled {
				fmt.Fprintf(os.Stderr, "\nOperation cancelled\n")
			} else {
				fmt.Fprintf(os.Stderr, "Error fetching PRs: %v\n", err)
			}
			os.Exit(1)
		}
		output := generatePRDisplay(prs, username, *blocked, *verbose, *includeStale, excludedOrgs)
		if output != "" {
			fmt.Print(output)
		}
	}
}

func gitHubToken() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gh", "auth", "token")
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("timeout getting auth token")
		}
		return "", fmt.Errorf("failed to get auth token (is 'gh' installed and authenticated?): %w", err)
	}

	token := strings.TrimSpace(string(output))
	if token == "" {
		return "", fmt.Errorf("empty auth token received")
	}

	// Basic validation - GitHub tokens should be non-empty alphanumeric strings
	if len(token) < 10 {
		return "", fmt.Errorf("invalid token format")
	}

	return token, nil
}

func currentUser(token string, logger *log.Logger, httpClient *http.Client) (string, error) {
	var username string

	err := retry.Do(
		func() error {
			logger.Printf("Making API call to GET %s", apiUserEndpoint)
			req, err := http.NewRequest("GET", apiUserEndpoint, nil)
			if err != nil {
				return err
			}

			req.Header.Set("Authorization", "token "+token)
			req.Header.Set("Accept", "application/vnd.github.v3+json")
			req.Header.Set("User-Agent", "github-pr-notifier-cli")

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

func fetchPRsWithRetry(ctx context.Context, token, username string, logger *log.Logger, httpClient *http.Client, turnClient *turn.Client, debug bool, org string) ([]PR, error) {
	var prs []PR

	err := retry.Do(
		func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			result, err := fetchPRs(ctx, token, username, logger, httpClient, turnClient, debug, org)
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

func fetchPRs(ctx context.Context, token, username string, logger *log.Logger, httpClient *http.Client, turnClient *turn.Client, debug bool, org string) ([]PR, error) {
	// Query 1: PRs that involve the user (mentioned, assigned, review requested, etc.)
	query1 := fmt.Sprintf("is:open is:pr involves:%s archived:false", username)
	if org != "" {
		// org is already validated, safe to use
		query1 += fmt.Sprintf(" org:%s", org)
	}

	// Query 2: PRs authored by the user
	query2 := fmt.Sprintf("is:open is:pr user:%s archived:false", username)
	if org != "" {
		query2 += fmt.Sprintf(" org:%s", org)
	}

	// Execute both queries
	resp1, err := makeGitHubSearchRequest(ctx, query1, token, httpClient, logger)
	if err != nil {
		return nil, err
	}
	defer resp1.Body.Close()

	prs1, err := parseSearchResponse(resp1)
	if err != nil {
		return nil, err
	}

	resp2, err := makeGitHubSearchRequest(ctx, query2, token, httpClient, logger)
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()

	prs2, err := parseSearchResponse(resp2)
	if err != nil {
		return nil, err
	}

	// Combine results
	prs := append(prs1, prs2...)

	logger.Printf("Found %d PRs (before deduplication)", len(prs))
	prs = deduplicatePRs(prs)
	logger.Printf("Found %d PRs (after deduplication)", len(prs))

	if err := enrichPRsParallel(ctx, token, prs, logger, httpClient, turnClient, username, debug); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		logger.Printf("WARNING: Failed to enrich some PR data: %v", err)
		// Continue with partial results rather than failing completely
	} else {
		logger.Printf("INFO: Successfully enriched all %d PRs", len(prs))
	}

	return prs, nil
}

func makeGitHubSearchRequest(ctx context.Context, query, token string, httpClient *http.Client, logger *log.Logger) (*http.Response, error) {
	params := url.Values{}
	params.Add("q", query)
	params.Add("per_page", fmt.Sprintf("%d", maxPerPage))
	params.Add("sort", "updated")

	apiURL := fmt.Sprintf("%s?%s", apiSearchEndpoint, params.Encode())
	logger.Printf("Making API call to GET %s", apiURL)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "github-pr-notifier-cli")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	start := time.Now()
	resp, err := httpClient.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		logger.Printf("ERROR: HTTP request failed after %v: %v", elapsed, err)
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("request timed out after %v", elapsed)
		}
		return nil, fmt.Errorf("github api request failed: %w", err)
	}
	logger.Printf("INFO: GitHub API request completed in %v with status %d", elapsed, resp.StatusCode)

	return resp, nil
}

func parseSearchResponse(resp *http.Response) ([]PR, error) {
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("invalid github token")
	}
	if resp.StatusCode == http.StatusForbidden {
		// Check for rate limit headers
		if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining == "0" {
			resetTime := resp.Header.Get("X-RateLimit-Reset")
			return nil, fmt.Errorf("github api rate limit exceeded, resets at %s", resetTime)
		}
		return nil, handleHTTPError(resp, "github api access forbidden")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, handleHTTPError(resp, "github api error")
	}

	var result SearchResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Items, nil
}

func handleHTTPError(resp *http.Response, message string) error {
	return fmt.Errorf("%s: status %d", message, resp.StatusCode)
}

func deduplicatePRs(prs []PR) []PR {
	if len(prs) <= 1 {
		return prs
	}

	seen := make(map[string]PR, len(prs))

	for _, pr := range prs {
		if existing, exists := seen[pr.HTMLURL]; !exists || pr.UpdatedAt.After(existing.UpdatedAt) {
			seen[pr.HTMLURL] = pr
		}
	}

	result := make([]PR, 0, len(seen))
	for _, pr := range seen {
		result = append(result, pr)
	}

	return result
}

func enrichPRsParallel(ctx context.Context, token string, prs []PR, logger *log.Logger, httpClient *http.Client, turnClient *turn.Client, username string, debug bool) error {
	// Simple semaphore pattern - Rob Pike style
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for i := range prs {
		wg.Add(1)
		sem <- struct{}{} // acquire semaphore

		go func(pr *PR) {
			defer func() {
				<-sem // release semaphore
				wg.Done()
			}()

			// Ignore non-critical errors - let the app continue
			if err := enrichPRData(ctx, pr, logger, turnClient, username, debug); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				logger.Printf("WARNING: Failed to enrich PR #%d: %v", pr.Number, err)
			}
		}(&prs[i])
	}

	wg.Wait()
	return nil
}

func fetchPRDetails(ctx context.Context, pr *PR, logger *log.Logger, debug bool) error {
	// Get token from environment
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN not set")
	}

	// Extract repository info from PR URL
	// URL format: https://github.com/owner/repo/pull/123
	parts := strings.Split(pr.HTMLURL, "/")
	if len(parts) < 6 {
		return fmt.Errorf("invalid PR URL format: %s", pr.HTMLURL)
	}
	owner := parts[3]
	repo := parts[4]

	// Build API URL
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d", owner, repo, pr.Number)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	// Make request
	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	// Parse response
	var prDetails PR
	if err := json.NewDecoder(resp.Body).Decode(&prDetails); err != nil {
		return err
	}

	// Update PR with size information
	pr.Additions = prDetails.Additions
	pr.Deletions = prDetails.Deletions
	pr.ChangedFiles = prDetails.ChangedFiles

	if debug {
		logger.Printf("Fetched PR #%d size: +%d/-%d files:%d", pr.Number, pr.Additions, pr.Deletions, pr.ChangedFiles)
	}

	return nil
}

func enrichPRData(ctx context.Context, pr *PR, logger *log.Logger, turnClient *turn.Client, username string, debug bool) error {
	start := time.Now()
	defer func() {
		if debug {
			logger.Printf("Enriched PR #%d in %v", pr.Number, time.Since(start))
		}
	}()

	// Fetch individual PR data to get size information
	if err := fetchPRDetails(ctx, pr, logger, debug); err != nil {
		logger.Printf("WARNING: Failed to fetch PR details for #%d: %v", pr.Number, err)
		// Continue without size info
	}

	// Enrich with turn server data if available
	if turnClient != nil {
		// Validate PR URL before sending to turn server
		if pr.HTMLURL == "" || !strings.HasPrefix(pr.HTMLURL, "https://github.com/") {
			logger.Printf("WARNING: Invalid PR URL for turn enrichment: %s", pr.HTMLURL)
			return nil
		}

		// Check cache first
		cachePath := turnCachePath(pr.HTMLURL, pr.UpdatedAt)
		if cached, found := loadTurnCache(cachePath); found {
			pr.TurnResponse = cached
			return nil
		}

		// Cache miss
		if debug && cachePath != "" {
			logger.Printf("INFO: Cache miss for PR #%d", pr.Number)
		}

		turnStart := time.Now()
		if debug {
			logger.Printf("Sending turnclient request for PR #%d: URL=%s, UpdatedAt=%s",
				pr.Number, pr.HTMLURL, pr.UpdatedAt.Format(time.RFC3339))
		}

		turnResponse, err := turnClient.Check(ctx, pr.HTMLURL, username, pr.UpdatedAt)
		if err != nil {
			logger.Printf("WARNING: Failed to get turn data for PR #%d: %v", pr.Number, err)
			// Don't fail the entire enrichment if turn server is unavailable
		} else if turnResponse != nil {
			pr.TurnResponse = turnResponse
			// Save to cache
			saveTurnCache(cachePath, turnResponse)
			if debug {
				logger.Printf("Turn server call for PR #%d took %v", pr.Number, time.Since(turnStart))
				responseJSON, _ := json.MarshalIndent(turnResponse, "", "  ")
				logger.Printf("Received turnclient response for PR #%d: %s", pr.Number, string(responseJSON))
			}
		}
	}

	return nil
}

func isBlockingOnUser(pr PR, username string) bool {
	// If we have turn client data, use that for blocking determination
	if pr.TurnResponse != nil && pr.TurnResponse.PRState.UnblockAction != nil {
		_, hasAction := pr.TurnResponse.PRState.UnblockAction[username]
		return hasAction
	}

	// Fallback to GitHub API requested reviewers if no turn data
	for _, reviewer := range pr.RequestedReviewers {
		if reviewer.Login == username {
			return true
		}
	}
	return false
}


func categorizePRs(prs []PR, username string) (incoming, outgoing []PR) {
	for _, pr := range prs {
		if pr.User.Login == username {
			outgoing = append(outgoing, pr)
		} else {
			incoming = append(incoming, pr)
		}
	}
	return
}

func countBlockingPRs(prs []PR, username string, debug bool) int {
	count := 0
	for _, pr := range prs {
		if isBlockingOnUser(pr, username) {
			count++
		}
		if debug {
			debugPR(pr, username)
		}
	}
	return count
}

func debugPR(pr PR, username string) {
	blocking := isBlockingOnUser(pr, username)
	fmt.Fprintf(os.Stderr, "[DEBUG] PR #%d (%s) - blocking: %v\n", pr.Number, pr.Title, blocking)
	if pr.TurnResponse != nil {
		if pr.TurnResponse.PRState.UnblockAction != nil {
			fmt.Fprintf(os.Stderr, "  UnblockAction: %+v\n", pr.TurnResponse.PRState.UnblockAction)
		}
		if len(pr.TurnResponse.PRState.Tags) > 0 {
			fmt.Fprintf(os.Stderr, "  Tags: %v\n", pr.TurnResponse.PRState.Tags)
		}
	}
}





func coloredTag(tag string) string {
	var color string
	var icon string

	switch tag {
	case "draft":
		color = "#FFA500"
		icon = "🚧"
	case "has_approval":
		color = "#00FF00"
		icon = "✅"
	case "merge_conflict":
		color = "#FF0000"
		icon = "💥"
	case "stale":
		color = "#808080"
		icon = "⏰"
	case "failing_tests":
		color = "#FF4444"
		icon = "❌"
	case "ready_to_merge":
		color = "#00DD00"
		icon = "🚀"
	case "updated":
		color = "#44AAFF"
		icon = "🔄"
	default:
		color = "#FF9FF3"
		icon = "🏷️"
	}

	// Create a more subtle tag style
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color(color)).
		Bold(false).
		Padding(0, 1).
		Background(lipgloss.Color("#1a1a1a"))

	return style.Render(fmt.Sprintf("%s %s", icon, tag))
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

func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}

	// Keep the important parts of GitHub URLs
	parts := strings.Split(url, "/")
	if len(parts) >= 6 && strings.Contains(url, "github.com") {
		// Extract owner/repo/pull/number
		owner := parts[3]
		repo := parts[4]
		prType := parts[5]
		number := parts[6]
		shortened := fmt.Sprintf("github.com/%s/%s/%s/%s", owner, repo, prType, number)
		if len(shortened) <= maxLen {
			return shortened
		}
	}

	// Fallback to regular truncation
	return truncate(url, maxLen)
}

// Helper functions for enhanced display

func getAgeColor(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < 24*time.Hour:
		return "#00FF88" // Fresh - bright green
	case d < 3*24*time.Hour:
		return "#00BCD4" // Recent - cyan
	case d < 7*24*time.Hour:
		return "#FFC107" // Week old - amber
	case d < 30*24*time.Hour:
		return "#FF9800" // Month old - orange
	default:
		return "#FF5722" // Old - deep orange
	}
}

func getSizeIndicator(additions, deletions, files int) string {
	total := additions + deletions
	
	// Visual size indicator
	var size string
	var color string
	
	switch {
	case total < 10:
		size = "●"
		color = "#00E676"
	case total < 50:
		size = "●●"
		color = "#FFC107"
	case total < 200:
		size = "●●●"
		color = "#FF9800"
	case total < 500:
		size = "●●●●"
		color = "#FF5722"
	default:
		size = "●●●●●"
		color = "#FF1744"
	}
	
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(color)).
		Render(size)
}

func getMinimalTag(tag string) string {
	var symbol string
	var color string
	
	switch tag {
	case "has_approval":
		symbol = "✓"
		color = "#00E676"
	case "merge_conflict":
		symbol = "✗"
		color = "#FF1744"
	case "stale":
		symbol = "◔"
		color = "#666666"
	case "failing_tests":
		symbol = "⚠"
		color = "#FFC107"
	case "ready_to_merge":
		symbol = "→"
		color = "#00FF88"
	default:
		return ""
	}
	
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(color)).
		Render(symbol)
}

func shortenRepo(url string) string {
	// Extract just owner/repo from GitHub URL
	parts := strings.Split(url, "/")
	if len(parts) >= 6 && strings.Contains(url, "github.com") {
		owner := parts[3]
		repo := parts[4]
		number := parts[6]
		
		// Shorten long repo names
		if len(owner) > 15 {
			owner = owner[:12] + "..."
		}
		if len(repo) > 20 {
			repo = repo[:17] + "..."
		}
		
		return fmt.Sprintf("%s/%s#%s", owner, repo, number)
	}
	return url
}

func getOrgFromURL(url string) string {
	// Extract org/owner from GitHub URL
	parts := strings.Split(url, "/")
	if len(parts) >= 4 && strings.Contains(url, "github.com") {
		return parts[3] // This is the org/owner
	}
	return ""
}

// sortPRsByUpdateTime sorts PRs by most recently updated first
func sortPRsByUpdateTime(prs []PR) {
	for i := 0; i < len(prs); i++ {
		for j := i + 1; j < len(prs); j++ {
			if prs[j].UpdatedAt.After(prs[i].UpdatedAt) {
				prs[i], prs[j] = prs[j], prs[i]
			}
		}
	}
}



// runHybridMode runs the application with both WebSocket and polling for maximum coverage
// runWatchMode runs the simplified watch mode with WebSocket + polling and smart display updates
func runWatchMode(ctx context.Context, token, username string, blockingOnly bool, verbose bool, includeStale bool, logger *log.Logger, httpClient *http.Client, turnClient *turn.Client, excludedOrgs []string) {
	logger.Printf("Starting watch mode with WebSocket + polling")
	
	// Track last displayed output to detect changes
	var lastDisplayHash string
	
	// Create refresh tracker to prevent duplicate API calls
	refreshTracker := newPRRefreshTracker()
	
	// Channel to trigger display updates
	updateChan := make(chan bool, 10)
	
	// Initial display
	if err := updateDisplay(ctx, token, username, blockingOnly, verbose, includeStale, logger, httpClient, turnClient, &lastDisplayHash, true, excludedOrgs); err != nil {
		logger.Printf("ERROR: Initial display failed: %v", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// Start WebSocket monitoring
	go func() {
		// Redirect standard log output to discard when not verbose
		// This suppresses sprinkler library logs
		if !verbose {
			log.SetOutput(io.Discard)
			defer log.SetOutput(os.Stderr) // Restore on exit
		}
		
		config := client.Config{
			ServerURL:      defaultSprinklerURL,
			Token:          token,
			Organization:   "*",
			EventTypes:     []string{"*"}, 
			UserEventsOnly: false,
			Verbose:        verbose,
			NoReconnect:    false,
			OnConnect: func() {
				logger.Println("✓ WebSocket connected")
			},
			OnDisconnect: func(err error) {
				logger.Printf("WebSocket disconnected: %v", err)
			},
			OnEvent: func(event client.Event) {
				if event.Type == "pull_request" && event.URL != "" {
					if refreshTracker.shouldRefresh(event.URL) {
						refreshTracker.markRefreshed(event.URL)
						logger.Printf("WebSocket event: %s", event.URL)
						select {
						case updateChan <- true:
						default: // Don't block if channel is full
						}
					}
				}
			},
		}
		
		wsClient, err := client.New(config)
		if err != nil {
			logger.Printf("WARNING: Failed to create WebSocket client: %v", err)
			return
		}
		
		if err := wsClient.Start(ctx); err != nil && err != context.Canceled {
			logger.Printf("WARNING: WebSocket client error: %v", err)
		}
	}()
	
	// Start polling
	go func() {
		ticker := time.NewTicker(defaultWatchInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				logger.Printf("Polling update")
				select {
				case updateChan <- true:
				default: // Don't block if channel is full
				}
			}
		}
	}()
	
	// Main update loop
	for {
		select {
		case <-ctx.Done():
			return
		case <-updateChan:
			if err := updateDisplay(ctx, token, username, blockingOnly, verbose, includeStale, logger, httpClient, turnClient, &lastDisplayHash, false, excludedOrgs); err != nil {
				logger.Printf("ERROR: Display update failed: %v", err)
			}
		}
	}
}

// updateDisplay fetches current PRs and updates the display only if content changed
func updateDisplay(ctx context.Context, token, username string, blockingOnly bool, verbose bool, includeStale bool, logger *log.Logger, httpClient *http.Client, turnClient *turn.Client, lastHash *string, forceDisplay bool, excludedOrgs []string) error {
	// Fetch current PRs
	prs, err := fetchPRsWithRetry(ctx, token, username, logger, httpClient, turnClient, verbose, "")
	if err != nil {
		return err
	}
	
	// Generate display output
	output := generatePRDisplay(prs, username, blockingOnly, verbose, includeStale, excludedOrgs)
	
	// Calculate hash of the output
	h := sha256.Sum256([]byte(output))
	currentHash := hex.EncodeToString(h[:])
	
	// Only update display if content changed or forced
	if forceDisplay || *lastHash != currentHash {
		// Always clear screen before drawing
		fmt.Print("\033[H\033[2J")
		
		if output != "" { // Only display if there's content
			fmt.Print(output)
			*lastHash = currentHash
			
			logger.Printf("Display updated (hash: %s)", currentHash[:8])
		} else {
			// No content to display (screen already cleared)
			*lastHash = currentHash
			logger.Printf("No PRs to display")
		}
	} else {
		logger.Printf("No display changes detected")
	}
	
	return nil
}

// generatePRDisplay creates the display output string without printing it
func generatePRDisplay(prs []PR, username string, blockingOnly bool, verbose bool, includeStale bool, excludedOrgs []string) string {
	var output strings.Builder
	
	// Filter out excluded orgs
	if len(excludedOrgs) > 0 {
		var filteredPRs []PR
		for _, pr := range prs {
			excluded := false
			prOrg := getOrgFromURL(pr.HTMLURL)
			for _, excludeOrg := range excludedOrgs {
				if prOrg == excludeOrg {
					excluded = true
					break
				}
			}
			if !excluded {
				filteredPRs = append(filteredPRs, pr)
			}
		}
		prs = filteredPRs
	}
	
	// Filter out stale PRs unless includeStale is true
	// A PR is considered stale if it hasn't been updated in 90 days
	if !includeStale {
		var filteredPRs []PR
		staleCutoff := time.Now().AddDate(0, 0, -90) // 90 days ago
		for _, pr := range prs {
			// Keep PRs that were updated within the last 90 days
			if pr.UpdatedAt.After(staleCutoff) {
				filteredPRs = append(filteredPRs, pr)
			}
		}
		prs = filteredPRs
	}

	incoming, outgoing := categorizePRs(prs, username)
	
	// Sort by most recently updated first
	sortPRsByUpdateTime(incoming)
	sortPRsByUpdateTime(outgoing)
	
	// If no PRs at all, return empty string
	if len(incoming) == 0 && len(outgoing) == 0 {
		return ""
	}

	// Count blocking PRs in both incoming and outgoing
	incomingBlockingCount := 0
	for _, pr := range incoming {
		if isBlockingOnUser(pr, username) {
			incomingBlockingCount++
		}
	}
	
	outgoingBlockingCount := 0
	for _, pr := range outgoing {
		if isBlockingOnUser(pr, username) {
			outgoingBlockingCount++
		}
	}

	output.WriteString("\n")
	
	// Incoming PRs with integrated header
	if len(incoming) > 0 && (!blockingOnly || incomingBlockingCount > 0) {
		// Header with counts
		output.WriteString(headerStyle.Render(fmt.Sprintf("incoming - %d PRs", len(incoming))))
		if incomingBlockingCount > 0 {
			output.WriteString(headerStyle.Render(", "))
			output.WriteString(lipgloss.NewStyle().
				Foreground(lipgloss.Color("#E5484D")). // Same red as bullet
				Bold(true).
				Render(fmt.Sprintf("%d blocked on you", incomingBlockingCount)))
		}
		output.WriteString(headerStyle.Render(":"))
		output.WriteString("\n")

		for _, pr := range incoming {
			if blockingOnly && !isBlockingOnUser(pr, username) {
				continue
			}
			output.WriteString(formatPR(pr, username))
		}
	}

	// Outgoing PRs with integrated header
	if len(outgoing) > 0 && (!blockingOnly || outgoingBlockingCount > 0) {
		if len(incoming) > 0 {
			output.WriteString("\n")
		}
		
		// Header with counts
		output.WriteString(headerStyle.Render(fmt.Sprintf("outgoing - %d PRs", len(outgoing))))
		if outgoingBlockingCount > 0 {
			output.WriteString(headerStyle.Render(", "))
			output.WriteString(lipgloss.NewStyle().
				Foreground(lipgloss.Color("#E5484D")). // Same red as bullet
				Bold(true).
				Render(fmt.Sprintf("%d blocked on you", outgoingBlockingCount)))
		}
		output.WriteString(headerStyle.Render(":"))
		output.WriteString("\n")
		
		for _, pr := range outgoing {
			if blockingOnly && !isBlockingOnUser(pr, username) {
				continue
			}
			output.WriteString(formatPR(pr, username))
		}
	}

	if blockingOnly && incomingBlockingCount == 0 && outgoingBlockingCount == 0 {
		// No blocking PRs - return empty string for no output
		return ""
	}
	output.WriteString("\n")

	return output.String()
}

// formatPR formats a single PR for display - Craigslist minimal with clickable URLs
func formatPR(pr PR, username string) string {
	var output strings.Builder
	
	// Blocking indicator - the only visual accent
	isBlocking := isBlockingOnUser(pr, username)
	if isBlocking {
		output.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E5484D")). // Modern red
			Bold(true).
			Render("• "))
	} else {
		output.WriteString("  ")
	}
	
	// Title - truncated
	title := pr.Title
	if len(title) > 60 {
		title = title[:57] + "..."
	}
	
	output.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FAFAFA")). // Almost white
		Render(title))
	output.WriteString(" ")
	
	// Clickable URL - full repo name, no truncation
	output.WriteString(makeClickableURL(pr.HTMLURL))
	
	// Size indicator - subtle
	if pr.Additions > 0 || pr.Deletions > 0 {
		size := pr.Additions + pr.Deletions
		sizeStr := ""
		sizeColor := "#8B8B8B"
		if size < 50 {
			sizeStr = "s"
			sizeColor = "#30A46C" // Green for small
		} else if size < 200 {
			sizeStr = "m"  
			sizeColor = "#F5A623" // Orange for medium
		} else if size < 500 {
			sizeStr = "l"
			sizeColor = "#FF8C69" // Coral for large
		} else {
			sizeStr = "xl"
			sizeColor = "#E5484D" // Red for extra large
		}
		output.WriteString(" ")
		output.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color(sizeColor)).
			Render(sizeStr))
	}
	
	// Status tags - minimal and modern
	if pr.TurnResponse != nil {
		for _, tag := range pr.TurnResponse.PRState.Tags {
			switch tag {
			case "merge_conflict":
				output.WriteString(" ")
				output.WriteString(lipgloss.NewStyle().
					Foreground(lipgloss.Color("#E5484D")). // Red
					Render("conflict"))
			case "ready_to_merge":
				output.WriteString(" ")
				output.WriteString(lipgloss.NewStyle().
					Foreground(lipgloss.Color("#30A46C")). // Green
					Render("ready"))
			case "draft":
				output.WriteString(" ")
				output.WriteString(lipgloss.NewStyle().
					Foreground(lipgloss.Color("#8B8B8B")). // Gray
					Render("draft"))
			}
		}
	}
	
	output.WriteString("\n")
	return output.String()
}

// makeClickableURL creates a terminal hyperlink
func makeClickableURL(url string) string {
	// Terminal hyperlink format: \033]8;;URL\033\\LABEL\033]8;;\033\\
	// Extract full repo path without truncation
	label := getRepoPath(url)
	
	// Use OSC 8 hyperlink escape sequence
	return fmt.Sprintf("\033]8;;%s\033\\%s\033]8;;\033\\", 
		url,
		lipgloss.NewStyle().
			Foreground(lipgloss.Color("#3E63DD")). // Modern blue
			Underline(true).
			Render(label))
}

// getRepoPath extracts the full repo path from a GitHub URL
func getRepoPath(url string) string {
	// Extract owner/repo#number from GitHub URL
	parts := strings.Split(url, "/")
	if len(parts) >= 7 && strings.Contains(url, "github.com") {
		owner := parts[3]
		repo := parts[4]
		number := parts[6]
		return fmt.Sprintf("%s/%s#%s", owner, repo, number)
	}
	return url
}
