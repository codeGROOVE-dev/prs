// Package main implements a GitHub PR notifier CLI tool.
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
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/codeGROOVE-dev/retry"
	"github.com/codeGROOVE-dev/sprinkler/pkg/client"
	"github.com/codeGROOVE-dev/turnclient/pkg/turn"
	"golang.org/x/term"
)

// PR represents a GitHub pull request with all relevant information.
type PR struct {
	CreatedAt    time.Time           `json:"created_at"`
	UpdatedAt    time.Time           `json:"updated_at"`
	TurnResponse *turn.CheckResponse `json:"turn_response,omitempty"`
	Repository   struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Title              string `json:"title"`
	User               User   `json:"user"`
	State              string `json:"state"`
	HTMLURL            string `json:"html_url"`
	RequestedReviewers []User `json:"requested_reviewers"`
	ReviewComments     int    `json:"review_comments"`
	Comments           int    `json:"comments"`
	Number             int    `json:"number"`
	Additions          int    `json:"additions"`
	Deletions          int    `json:"deletions"`
	ChangedFiles       int    `json:"changed_files"`
	Draft              bool   `json:"draft"`
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
	defaultTimeout        = 30 * time.Second
	defaultWatchInterval  = 60 * time.Second
	maxPerPage            = 100
	retryAttempts         = 3
	retryDelay            = time.Second
	retryMaxDelay         = 10 * time.Second
	enrichRetries         = 2
	enrichDelay           = 500 * time.Millisecond
	enrichMaxDelay        = 2 * time.Second
	apiUserEndpoint       = "https://api.github.com/user"
	apiSearchEndpoint     = "https://api.github.com/search/issues"
	apiPullsEndpoint      = "https://api.github.com/repos/%s/%s/pulls/%d"
	maxConcurrent         = 20                  // Increased for better throughput
	cacheTTL              = 10 * 24 * time.Hour // 10 days
	prRefreshCooldownSecs = 1                   // Avoid refreshing same PR within 1 second
	maxOrgNameLength      = 39                  // GitHub org name limit
	minTokenLength        = 10                  // Minimum GitHub token length
	maxIdleConnsPerHost   = 10                  // HTTP client setting
	idleConnTimeout       = 90 * time.Second
	minPRURLParts         = 6     // Minimum parts in PR URL
	minOrgURLParts        = 4     // Minimum parts in org URL
	repoPartIndex         = 4     // Index of repo in URL parts
	prTypePartIndex       = 5     // Index of PR type in URL parts
	numberPartIndex       = 6     // Index of PR number in URL parts
	prURLParts            = 7     // Number of parts in a full PR URL
	truncatedURLLength    = 80    // Max URL display length
	defaultTerminalWidth  = 80    // Default terminal width if detection fails
	titlePadding          = 5     // Space between title and URL
	minTitleLength        = 20    // Minimum title display length
	cacheFileMode         = 0o644 // File permissions for cache files
	stalePRDays           = 90    // Days before a PR is considered stale
)

// turnCache handles caching of Turn API responses.
func turnCachePath(urlPath string, updatedAt time.Time) string {
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		return "" // No cache if we can't find cache dir
	}

	// Simple hash for filename
	h := sha256.Sum256([]byte(urlPath + updatedAt.Format(time.RFC3339)))
	return filepath.Join(dir, "prs", "turn-cache", hex.EncodeToString(h[:8])+".json")
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
		// Best effort removal of expired cache
		os.Remove(path) //nolint:errcheck,gosec // Removal failures are acceptable
		return nil, false
	}

	return entry.Response, true
}

func saveTurnCache(path string, response *turn.CheckResponse) {
	if path == "" {
		return
	}

	// Best effort cache write - failures are non-critical
	os.MkdirAll(filepath.Dir(path), 0o755) //nolint:errcheck,gosec // Directory creation failures are acceptable
	data, err := json.Marshal(cacheEntry{Response: response, Timestamp: time.Now()})
	if err == nil {
		os.WriteFile(path, data, cacheFileMode) //nolint:errcheck,gosec // Write failures are acceptable
	}
}

func main() {
	var (
		watch        = flag.Bool("watch", false, "Continuously watch for PR updates")
		blocked      = flag.Bool("blocked", false, "Show only PRs blocking on you")
		verbose      = flag.Bool("verbose", false, "Show verbose logging from libraries")
		excludeOrgs  = flag.String("exclude-orgs", "", "Comma-separated list of orgs to exclude")
		includeStale = flag.Bool("include-stale", false, "Include PRs that haven't been modified in 90 days")
		user         = flag.String("user", "", "View PRs for specified user instead of authenticated user")
		noCache      = flag.Bool("no-cache", false, "Disable caching of Turn API responses")
	)
	flag.Parse()

	// Set up logger
	var logger *log.Logger
	if *verbose {
		logger = log.New(os.Stderr, "[prs] ", log.Ltime)
	} else {
		logger = log.New(io.Discard, "", 0)
	}

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up HTTP client with optimized settings
	httpClient := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100, // Increased for better connection reuse
			MaxIdleConnsPerHost: maxIdleConnsPerHost,
			IdleConnTimeout:     idleConnTimeout,
			DisableKeepAlives:   false,
			DisableCompression:  false,
			ForceAttemptHTTP2:   true, // Use HTTP/2 when available
		},
	}

	token, err := gitHubToken(ctx)
	if err != nil {
		logger.Printf("ERROR: Failed to get GitHub token: %v", err)
		fmt.Fprint(os.Stderr, "error: failed to authenticate with github\n")
		cancel()
		return
	}
	logger.Print("INFO: Successfully retrieved GitHub token")

	// Determine the username to use - priority: --user flag, GITHUB_USER env, authenticated user
	var username string
	if *user != "" {
		username = *user
		logger.Printf("INFO: Using specified user from --user flag: %s", username)
	} else if envUser := os.Getenv("GITHUB_USER"); envUser != "" {
		username = envUser
		logger.Printf("INFO: Using user from GITHUB_USER environment variable: %s", username)
	} else {
		username, err = currentUser(ctx, token, logger, httpClient)
		if err != nil {
			logger.Printf("ERROR: Failed to get current user: %v", err)
			fmt.Fprint(os.Stderr, "error: failed to identify github user\n")
			cancel()
			return
		}
		logger.Printf("INFO: Authenticated as user: %s", username)
	}

	// Set up turn client
	var turnClient *turn.Client
	turnClient, err = turn.NewDefaultClient()
	if err != nil {
		logger.Printf("ERROR: Failed to create turn client: %v", err)
		turnClient = nil
	} else {
		logger.Print("INFO: Connected to turn server")
		if *verbose {
			turnClient.SetLogger(logger)
		}
		if token != "" {
			turnClient.SetAuthToken(token)
		}
	}

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
		cfg := &watchConfig{
			token:        token,
			username:     username,
			blockingOnly: *blocked,
			notifyMode:   false,
			bell:         false,
			interval:     defaultWatchInterval,
			logger:       logger,
			httpClient:   httpClient,
			turnClient:   turnClient,
			debug:        *verbose,
			org:          "",
			includeStale: *includeStale,
			excludedOrgs: excludedOrgs,
			noCache:      *noCache,
		}
		runWatchMode(ctx, cfg)
	} else {
		// Default: one-time display
		query := &prQuery{
			token:    token,
			username: username,
			org:      "",
			debug:    *verbose,
			noCache:  *noCache,
		}
		cls := &clients{
			http: httpClient,
			turn: turnClient,
		}
		prs, err := fetchPRsWithRetry(ctx, query, logger, cls)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				fmt.Fprint(os.Stderr, "\nOperation cancelled\n")
			} else {
				fmt.Fprintf(os.Stderr, "Error fetching PRs: %v\n", err)
			}
			cancel()
			return
		}
		output := generatePRDisplay(prs, username, *blocked, *includeStale, excludedOrgs)
		if output != "" {
			fmt.Print(output)
		}
	}
}

func gitHubToken(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gh", "auth", "token")
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", errors.New("timeout getting auth token")
		}
		return "", fmt.Errorf("failed to get auth token (is 'gh' installed and authenticated?): %w", err)
	}

	token := strings.TrimSpace(string(output))
	if token == "" {
		return "", errors.New("empty auth token received")
	}

	// Basic validation - GitHub tokens should be non-empty alphanumeric strings
	if len(token) < minTokenLength {
		return "", errors.New("invalid token format")
	}

	return token, nil
}

func currentUser(ctx context.Context, token string, logger *log.Logger, httpClient *http.Client) (string, error) {
	return retry.DoWithData(
		func() (string, error) {
			logger.Printf("Making API call to GET %s", apiUserEndpoint)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiUserEndpoint, http.NoBody)
			if err != nil {
				return "", err
			}

			req.Header.Set("Authorization", "token "+token)
			req.Header.Set("Accept", "application/vnd.github.v3+json")
			req.Header.Set("User-Agent", "prs-cli")

			resp, err := httpClient.Do(req)
			if err != nil {
				logger.Printf("HTTP request failed: %v", err)
				return "", err
			}
			defer resp.Body.Close() //nolint:errcheck // Best effort close

			if resp.StatusCode == http.StatusUnauthorized {
				return "", errors.New("invalid GitHub token")
			}
			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return "", fmt.Errorf("failed to read response body: %w", err)
				}
				return "", fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, body)
			}

			var user struct {
				Login string `json:"login"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
				return "", err
			}

			return user.Login, nil
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
}

func fetchPRsWithRetry(ctx context.Context, query *prQuery, logger *log.Logger, cls *clients) ([]PR, error) {
	return retry.DoWithData(
		func() ([]PR, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			return fetchPRs(ctx, query, logger, cls)
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
}

func fetchPRs(ctx context.Context, query *prQuery, logger *log.Logger, cls *clients) ([]PR, error) {
	// Query 1: PRs that involve the user (mentioned, assigned, review requested, etc.)
	query1 := fmt.Sprintf("is:open is:pr involves:%s archived:false", query.username)
	if query.org != "" {
		// org is already validated, safe to use
		query1 += fmt.Sprintf(" org:%s", query.org)
	}

	// Query 2: PRs authored by the user
	query2 := fmt.Sprintf("is:open is:pr user:%s archived:false", query.username)
	if query.org != "" {
		query2 += fmt.Sprintf(" org:%s", query.org)
	}

	// Execute both queries
	resp1, err := makeGitHubSearchRequest(ctx, query1, query.token, cls.http, logger)
	if err != nil {
		return nil, err
	}
	defer resp1.Body.Close() //nolint:errcheck // Best effort close

	prs1, err := parseSearchResponse(resp1)
	if err != nil {
		return nil, err
	}

	resp2, err := makeGitHubSearchRequest(ctx, query2, query.token, cls.http, logger)
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close() //nolint:errcheck // Best effort close

	prs2, err := parseSearchResponse(resp2)
	if err != nil {
		return nil, err
	}

	// Combine results
	prs := make([]PR, 0, len(prs1)+len(prs2))
	prs = append(prs, prs1...)
	prs = append(prs, prs2...)

	logger.Printf("Found %d PRs (before deduplication)", len(prs))
	prs = deduplicatePRs(prs)
	logger.Printf("Found %d PRs (after deduplication)", len(prs))

	enrichCfg := &enrichConfig{
		httpClient: cls.http,
		turnClient: cls.turn,
		logger:     logger,
		token:      query.token,
		username:   query.username,
		debug:      query.debug,
		noCache:    query.noCache,
	}
	enrichPRsParallel(ctx, prs, enrichCfg)
	logger.Printf("INFO: Successfully enriched all %d PRs", len(prs))

	// Filter out closed/merged PRs (can happen due to GitHub search lag or stale cache)
	openPRs := make([]PR, 0, len(prs))
	for i := range prs {
		if prs[i].State == "open" {
			openPRs = append(openPRs, prs[i])
		}
	}
	if len(openPRs) != len(prs) {
		logger.Printf("Filtered out %d closed/merged PRs", len(prs)-len(openPRs))
	}

	return openPRs, nil
}

func makeGitHubSearchRequest(ctx context.Context, query, token string, httpClient *http.Client, logger *log.Logger) (*http.Response, error) {
	params := url.Values{}
	params.Add("q", query)
	params.Add("per_page", strconv.Itoa(maxPerPage))
	params.Add("sort", "updated")

	apiURL := fmt.Sprintf("%s?%s", apiSearchEndpoint, params.Encode())
	logger.Printf("Making API call to GET %s", apiURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "prs-cli")
	req.Header.Set("X-Github-Api-Version", "2022-11-28")

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
		if remaining := resp.Header.Get("X-Ratelimit-Remaining"); remaining == "0" {
			resetTime := resp.Header.Get("X-Ratelimit-Reset")
			return nil, fmt.Errorf("github api rate limit exceeded, resets at %s", resetTime)
		}
		return nil, fmt.Errorf("github api access forbidden: status %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api error: status %d", resp.StatusCode)
	}

	var result SearchResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Items, nil
}

func deduplicatePRs(prs []PR) []PR {
	seen := make(map[string]PR, len(prs))

	for i := range prs {
		if existing, exists := seen[prs[i].HTMLURL]; !exists || prs[i].UpdatedAt.After(existing.UpdatedAt) {
			seen[prs[i].HTMLURL] = prs[i]
		}
	}

	result := make([]PR, 0, len(seen))
	for u := range seen {
		result = append(result, seen[u])
	}

	return result
}

func enrichPRsParallel(ctx context.Context, prs []PR, cfg *enrichConfig) {
	// Simple semaphore pattern - Rob Pike style
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for i := range prs {
		sem <- struct{}{} // acquire semaphore
		pr := &prs[i]

		wg.Go(func() {
			defer func() {
				<-sem // release semaphore
			}()

			// Ignore non-critical errors - let the app continue
			if err := enrichPRData(ctx, pr, cfg); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				cfg.logger.Printf("WARNING: Failed to enrich PR #%d: %v", pr.Number, err)
			}
		})
	}

	wg.Wait()
}

func fetchPRDetails(ctx context.Context, pr *PR, token string, httpClient *http.Client, logger *log.Logger, debug bool) error {
	// Extract repository info from PR URL
	// URL format: https://github.com/owner/repo/pull/123
	parts := strings.Split(pr.HTMLURL, "/")
	if len(parts) < minPRURLParts {
		return fmt.Errorf("invalid PR URL format: %s", pr.HTMLURL)
	}
	owner := parts[3]
	repo := parts[repoPartIndex]

	// Build API URL
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d", owner, repo, pr.Number)

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	// Make request
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // Best effort close

	if resp.StatusCode != http.StatusOK {
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

func enrichPRData(ctx context.Context, pr *PR, cfg *enrichConfig) error {
	start := time.Now()
	defer func() {
		if cfg.debug {
			cfg.logger.Printf("Enriched PR #%d in %v", pr.Number, time.Since(start))
		}
	}()

	// Fetch individual PR data to get size information
	if err := fetchPRDetails(ctx, pr, cfg.token, cfg.httpClient, cfg.logger, cfg.debug); err != nil {
		cfg.logger.Printf("WARNING: Failed to fetch PR details for #%d: %v", pr.Number, err)
		// Continue without size info
	}

	// Enrich with turn server data if available
	if cfg.turnClient == nil {
		if cfg.debug {
			cfg.logger.Printf("Turn client is nil, skipping turn enrichment for PR #%d", pr.Number)
		}
		return nil
	}
	if cfg.debug {
		cfg.logger.Printf("Calling enrichWithTurnData for PR #%d", pr.Number)
	}
	return enrichWithTurnData(ctx, pr, cfg)
}

func enrichWithTurnData(ctx context.Context, pr *PR, cfg *enrichConfig) error {
	if cfg.debug {
		cfg.logger.Printf("enrichWithTurnData called for PR #%d, URL: %s", pr.Number, pr.HTMLURL)
	}

	// Validate PR URL before sending to turn server
	if pr.HTMLURL == "" || !strings.HasPrefix(pr.HTMLURL, "https://github.com/") {
		cfg.logger.Printf("WARNING: Invalid PR URL for turn enrichment: %s", pr.HTMLURL)
		return nil
	}

	// Check cache first (unless noCache is enabled)
	var cachePath string
	if !cfg.noCache {
		cachePath = turnCachePath(pr.HTMLURL, pr.UpdatedAt)
		if cfg.debug {
			cfg.logger.Printf("Cache path for PR #%d: %s", pr.Number, cachePath)
		}
		if cached, found := loadTurnCache(cachePath); found {
			if cfg.debug {
				cfg.logger.Printf("INFO: Cache hit for PR #%d", pr.Number)
			}
			pr.TurnResponse = cached
			return nil
		}

		// Cache miss
		if cfg.debug {
			cfg.logger.Printf("INFO: Cache miss for PR #%d", pr.Number)
		}
	} else if cfg.debug {
		cfg.logger.Printf("INFO: Cache disabled (--no-cache) for PR #%d", pr.Number)
	}

	return fetchAndCacheTurnData(ctx, pr, cachePath, cfg)
}

func fetchAndCacheTurnData(ctx context.Context, pr *PR, cachePath string, cfg *enrichConfig) error {
	turnStart := time.Now()
	if cfg.debug {
		cfg.logger.Printf("Sending turnclient request for PR #%d: URL=%s, UpdatedAt=%s",
			pr.Number, pr.HTMLURL, pr.UpdatedAt.Format(time.RFC3339))
	}

	turnResponse, err := cfg.turnClient.Check(ctx, pr.HTMLURL, cfg.username, pr.UpdatedAt)
	if err != nil {
		cfg.logger.Printf("WARNING: Failed to get turn data for PR #%d: %v", pr.Number, err)
		return nil // Don't fail the entire enrichment if turn server is unavailable
	}

	if turnResponse == nil {
		return nil
	}

	pr.TurnResponse = turnResponse
	if !cfg.noCache {
		saveTurnCache(cachePath, turnResponse)
	}

	if cfg.debug {
		logDebugTurnResponse(cfg.logger, pr.Number, turnResponse, time.Since(turnStart))
	}
	return nil
}

func logDebugTurnResponse(logger *log.Logger, prNumber int, turnResponse *turn.CheckResponse, duration time.Duration) {
	logger.Printf("Turn server call for PR #%d took %v", prNumber, duration)
	responseJSON, err := json.MarshalIndent(turnResponse, "", "  ")
	if err != nil {
		logger.Printf("WARNING: Failed to marshal turn response for PR #%d: %v", prNumber, err)
		// Try to at least log some basic info
		logger.Printf("Turn response for PR #%d: Analysis.Tags=%v, NextActions=%d",
			prNumber, turnResponse.Analysis.Tags, len(turnResponse.Analysis.NextAction))
		return
	}
	logger.Printf("Received turnclient response for PR #%d:\n%s", prNumber, string(responseJSON))
}

func isBlockingOnUser(pr *PR, username string) bool {
	// If we have turn client data, use that for blocking determination
	if pr.TurnResponse != nil && pr.TurnResponse.Analysis.NextAction != nil {
		_, hasAction := pr.TurnResponse.Analysis.NextAction[username]
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

func isCriticalBlocker(pr *PR, username string) bool {
	// Check if user has a critical action
	if pr.TurnResponse != nil && pr.TurnResponse.Analysis.NextAction != nil {
		if action, exists := pr.TurnResponse.Analysis.NextAction[username]; exists {
			return action.Critical
		}
	}
	return false
}

func categorizePRs(prs []PR, username string) (incoming, outgoing []PR) {
	for i := range prs {
		if prs[i].User.Login == username {
			outgoing = append(outgoing, prs[i])
		} else {
			incoming = append(incoming, prs[i])
		}
	}
	return incoming, outgoing
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func wasBlockingBefore(pr *PR, previous []PR, username string) bool {
	if found, exists := findPRInList(pr, previous); exists {
		return isBlockingOnUser(&found, username)
	}
	return false
}

func findPRInList(target *PR, prs []PR) (PR, bool) {
	for i := range prs {
		if prs[i].Number == target.Number && prs[i].Repository.FullName == target.Repository.FullName {
			return prs[i], true
		}
	}
	return PR{}, false
}

// clients holds HTTP and Turn clients.
type clients struct {
	http *http.Client
	turn *turn.Client
}

// enrichConfig holds configuration for PR enrichment.
type enrichConfig struct {
	httpClient *http.Client
	turnClient *turn.Client
	logger     *log.Logger
	token      string
	username   string
	debug      bool
	noCache    bool
}

// prQuery holds parameters for PR queries.
type prQuery struct {
	token    string
	username string
	org      string
	debug    bool
	noCache  bool
}

// displayConfig holds configuration for updateDisplay.
type displayConfig struct {
	logger          *log.Logger
	httpClient      *http.Client
	turnClient      *turn.Client
	lastDisplayHash *string
	token           string
	username        string
	excludedOrgs    []string
	blockingOnly    bool
	verbose         bool
	includeStale    bool
	force           bool
	noCache         bool
}

// watchConfig holds configuration for watch mode.
type watchConfig struct {
	httpClient   *http.Client
	turnClient   *turn.Client
	logger       *log.Logger
	org          string
	token        string
	username     string
	excludedOrgs []string
	interval     time.Duration
	blockingOnly bool
	notifyMode   bool
	bell         bool
	debug        bool
	includeStale bool
	noCache      bool
}

func runWatchMode(ctx context.Context, cfg *watchConfig) {
	cfg.logger.Printf("Starting watch mode with WebSocket + polling")

	// Track last displayed output to detect changes
	var lastDisplayHash string

	// Create refresh tracker to prevent duplicate API calls
	refreshTracker := newPRRefreshTracker()

	// Channel to trigger display updates
	updateChan := make(chan bool, 10)

	// Initial display
	displayCfg := &displayConfig{
		logger:          cfg.logger,
		httpClient:      cfg.httpClient,
		turnClient:      cfg.turnClient,
		lastDisplayHash: &lastDisplayHash,
		excludedOrgs:    cfg.excludedOrgs,
		token:           cfg.token,
		username:        cfg.username,
		blockingOnly:    cfg.blockingOnly,
		verbose:         cfg.debug,
		includeStale:    cfg.includeStale,
		force:           true,
		noCache:         cfg.noCache,
	}
	err := updateDisplay(ctx, displayCfg)
	if err != nil {
		cfg.logger.Printf("ERROR: Initial display failed: %v", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	// Start WebSocket monitoring
	go func() {
		// Create a custom logger for sprinkler client
		var sprinklerLogger *slog.Logger
		if cfg.debug {
			// Use stderr with text handler for verbose mode
			sprinklerLogger = slog.New(slog.NewTextHandler(os.Stderr, nil))
		} else {
			// Discard all logs in non-verbose mode
			sprinklerLogger = slog.New(slog.DiscardHandler)
		}

		config := client.Config{
			ServerURL:      "wss://" + client.DefaultServerAddress + "/ws",
			Token:          cfg.token,
			Organization:   "*",
			EventTypes:     []string{"*"},
			UserEventsOnly: false,
			Verbose:        cfg.debug,
			NoReconnect:    false,
			Logger:         sprinklerLogger,
			OnConnect: func() {
				cfg.logger.Println("✓ WebSocket connected")
			},
			OnDisconnect: func(err error) {
				cfg.logger.Printf("WebSocket disconnected: %v", err)
			},
			OnEvent: func(event client.Event) {
				if event.Type == "pull_request" && event.URL != "" {
					if refreshTracker.shouldRefresh(event.URL) {
						refreshTracker.markRefreshed(event.URL)
						cfg.logger.Printf("WebSocket event: %s", event.URL)
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
			cfg.logger.Printf("WARNING: Failed to create WebSocket client: %v", err)
			return
		}

		if err := wsClient.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
			cfg.logger.Printf("WARNING: WebSocket client error: %v", err)
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
				select {
				case updateChan <- true:
					cfg.logger.Println("Polling trigger")
				default:
				}
			}
		}
	}()

	// Process updates
	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nShutting down...")
			return
		case <-updateChan:
			displayCfg.force = false
			err := updateDisplay(ctx, displayCfg)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					cfg.logger.Printf("ERROR: Update failed: %v", err)
				}
			}
		}
	}
}

func updateDisplay(ctx context.Context, cfg *displayConfig) error {
	// Fetch current PRs
	query := &prQuery{
		token:    cfg.token,
		username: cfg.username,
		org:      "",
		debug:    cfg.verbose,
		noCache:  cfg.noCache,
	}
	cls := &clients{
		http: cfg.httpClient,
		turn: cfg.turnClient,
	}
	prs, err := fetchPRsWithRetry(ctx, query, cfg.logger, cls)
	if err != nil {
		return err
	}

	// Generate display output
	output := generatePRDisplay(prs, cfg.username, cfg.blockingOnly, cfg.includeStale, cfg.excludedOrgs)

	// Check if display has changed
	currentHash := fmt.Sprintf("%x", sha256.Sum256([]byte(output)))
	if !cfg.force && currentHash == *cfg.lastDisplayHash {
		cfg.logger.Println("No changes to display")
		return nil
	}

	// Clear screen and display
	fmt.Print("\033[H\033[2J")
	fmt.Print(output)
	*cfg.lastDisplayHash = currentHash

	return nil
}

// filterExcludedOrgs removes PRs from excluded organizations.
func filterExcludedOrgs(prs []PR, excludedOrgs []string) []PR {
	if len(excludedOrgs) == 0 {
		return prs
	}

	filtered := make([]PR, 0, len(prs))
	for i := range prs {
		excluded := false
		org := orgFromURL(prs[i].HTMLURL)
		for _, exc := range excludedOrgs {
			if org == exc {
				excluded = true
				break
			}
		}
		if !excluded {
			filtered = append(filtered, prs[i])
		}
	}
	return filtered
}

// filterStalePRs removes PRs that are considered stale.
func filterStalePRs(prs []PR) []PR {
	filtered := make([]PR, 0, len(prs))
	staleAge := stalePRDays * 24 * time.Hour
	for i := range prs {
		stale := false

		// Check if PR is older than 90 days based on UpdatedAt
		if time.Since(prs[i].UpdatedAt) > staleAge {
			stale = true
		}

		// Also check TurnResponse tags if available
		if !stale && prs[i].TurnResponse != nil {
			for _, tag := range prs[i].TurnResponse.Analysis.Tags {
				if tag == "stale" {
					stale = true
					break
				}
			}
		}

		if !stale {
			filtered = append(filtered, prs[i])
		}
	}
	return filtered
}

// countBlockingPRs counts how many PRs are blocking on the user.
// Returns blocked (critical) and awaiting (non-critical) counts.
func countBlockingPRs(prs []PR, username string) (blocked, awaiting int) {
	for i := range prs {
		if isCriticalBlocker(&prs[i], username) {
			blocked++
		} else if isBlockingOnUser(&prs[i], username) {
			awaiting++
		}
	}
	return blocked, awaiting
}

// formatPRListHeader generates a header for a PR list with counts.
func formatPRListHeader(prCount, blocked, awaiting int, isOutgoing bool) string {
	var output strings.Builder

	// Proper singular/plural for PRs
	prText := "PR"
	if prCount != 1 {
		prText = "PRs"
	}

	// Base text - gray for outgoing
	baseText := fmt.Sprintf("incoming - %d %s", prCount, prText)
	if isOutgoing {
		baseText = fmt.Sprintf("outgoing - %d %s", prCount, prText)
		output.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8B8B8B")).
			Render(baseText))
	} else {
		output.WriteString(baseText)
	}

	// Add blocked count
	if blocked > 0 {
		output.WriteString(", ")
		blockText := "blocked on YOU"
		output.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E5484D")).
			Bold(true).
			Render(fmt.Sprintf("%d %s", blocked, blockText)))
	}

	// Add awaiting count
	if awaiting > 0 {
		output.WriteString(", ")
		awaitText := "awaiting your input"
		output.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFB224")).
			Bold(true).
			Render(fmt.Sprintf("%d %s", awaiting, awaitText)))
	}

	output.WriteString(":\n")
	return output.String()
}

func generatePRDisplay(prs []PR, username string, blockingOnly, includeStale bool, excludedOrgs []string) string {
	var output strings.Builder

	// Filter PRs
	prs = filterExcludedOrgs(prs, excludedOrgs)
	if !includeStale {
		prs = filterStalePRs(prs)
	}

	// Sort PRs by most recently updated
	sortPRsByUpdateTime(prs)

	// Split into incoming and outgoing
	incoming, outgoing := categorizePRs(prs, username)

	// Count blocking PRs
	inBlocked, inAwaiting := countBlockingPRs(incoming, username)
	outBlocked, outAwaiting := countBlockingPRs(outgoing, username)

	output.WriteString("\n")

	// Incoming PRs with integrated header
	if len(incoming) > 0 && (!blockingOnly || inBlocked > 0 || inAwaiting > 0) {
		output.WriteString(formatPRListHeader(len(incoming), inBlocked, inAwaiting, false))
		for i := range incoming {
			if blockingOnly && !isBlockingOnUser(&incoming[i], username) {
				continue
			}
			output.WriteString(formatPR(&incoming[i], username))
		}
	}

	// Outgoing PRs with integrated header
	if len(outgoing) > 0 && (!blockingOnly || outBlocked > 0 || outAwaiting > 0) {
		if len(incoming) > 0 {
			output.WriteString("\n")
		}
		output.WriteString(formatPRListHeader(len(outgoing), outBlocked, outAwaiting, true))
		for i := range outgoing {
			if blockingOnly && !isBlockingOnUser(&outgoing[i], username) {
				continue
			}
			output.WriteString(formatPR(&outgoing[i], username))
		}
	}

	if blockingOnly && inBlocked == 0 && inAwaiting == 0 && outBlocked == 0 && outAwaiting == 0 {
		// Show nothing when no PRs are blocking
		return ""
	}

	output.WriteString("\n")
	return output.String()
}

// terminalWidth returns the current terminal width, defaulting to 80 if unable to detect.
func terminalWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 {
		return defaultTerminalWidth
	}
	return width
}

// appendNextActionKinds appends formatted next action kinds to the output.
func appendNextActionKinds(output *strings.Builder, pr *PR, username string) {
	if pr.TurnResponse == nil || pr.TurnResponse.Analysis.NextAction == nil {
		return
	}

	var userActionKinds []string
	var otherCriticalKinds []string
	var userActionCritical bool
	seen := make(map[string]bool)

	// First, collect current user's actions
	if userAction, hasUserAction := pr.TurnResponse.Analysis.NextAction[username]; hasUserAction {
		kind := string(userAction.Kind)
		if !seen[kind] {
			userActionKinds = append(userActionKinds, kind)
			seen[kind] = true
			userActionCritical = userAction.Critical
		}
	}

	// Then collect critical actions from other users (avoiding duplicates)
	for user, action := range pr.TurnResponse.Analysis.NextAction {
		if user != username && action.Critical {
			kind := string(action.Kind)
			if !seen[kind] {
				otherCriticalKinds = append(otherCriticalKinds, kind)
				seen[kind] = true
			}
		}
	}

	// Display actions if any exist
	if len(userActionKinds) == 0 && len(otherCriticalKinds) == 0 {
		return
	}

	// Dark grey emdash
	output.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6B6B6B")). // Dark grey
		Render(" — "))

	// Display user's actions first with appropriate color
	if len(userActionKinds) > 0 {
		actionText := strings.Join(userActionKinds, " ")
		if userActionCritical {
			// Red for critical user action
			output.WriteString(lipgloss.NewStyle().
				Foreground(lipgloss.Color("#E5484D")).
				Render(actionText))
		} else {
			// Yellow for non-critical user action
			output.WriteString(lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FFB224")).
				Render(actionText))
		}
	}

	// Display other critical actions in dark grey
	if len(otherCriticalKinds) > 0 {
		if len(userActionKinds) > 0 {
			output.WriteString(" ") // Space between user and other actions
		}
		actionText := strings.Join(otherCriticalKinds, " ")
		output.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B6B6B")).
			Render(actionText))
	}
}

func formatPR(pr *PR, username string) string {
	var output strings.Builder

	// Get terminal width for dynamic truncation
	termWidth := terminalWidth()

	// Blocking indicator - differentiate between critical and regular actions
	isBlocking := isBlockingOnUser(pr, username)
	isCritical := isCriticalBlocker(pr, username)

	switch {
	case isCritical:
		// Red triangle for critical blocker
		output.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E5484D")). // Modern red
			Bold(true).
			Render("► "))
	case isBlocking:
		// Yellow bullet for regular next action
		output.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFB224")). // Yellow/amber
			Bold(true).
			Render("• "))
	default:
		output.WriteString("  ") // Just indent, no bullet for non-blocking
	}

	// Calculate space available for title
	// Account for: bullet (2), space after title (1), and URL estimate
	parts := strings.Split(pr.HTMLURL, "/")
	urlLength := 30 // Default estimate
	if len(parts) >= prURLParts {
		// Actual URL will be org/repo#number
		urlLength = len(fmt.Sprintf("%s/%s#%s", parts[3], parts[4], parts[6]))
	}

	// Reserve space: bullet(2) + space(1) + url + some padding(5)
	availableForTitle := termWidth - 2 - 1 - urlLength - titlePadding
	if availableForTitle < minTitleLength {
		availableForTitle = minTitleLength // Minimum title length
	}

	// Title - truncated based on available space
	title := pr.Title
	if len(title) > availableForTitle {
		title = title[:availableForTitle-3] + "..."
	}
	// Style title in white
	whiteTitle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Render(title)
	output.WriteString(whiteTitle)
	output.WriteString(" ")

	// Shortened URL - just org/repo#number in blue
	if len(parts) >= prURLParts {
		shortURL := fmt.Sprintf("%s/%s#%s", parts[3], parts[4], parts[6])
		// Style the URL in blue and make it clickable with OSC 8 hyperlink
		blueURL := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#3E63DD")). // Modern blue
			Render(shortURL)
		// Wrap with OSC 8 hyperlink
		output.WriteString(fmt.Sprintf("\x1b]8;;%s\x1b\\%s\x1b]8;;\x1b\\", pr.HTMLURL, blueURL))
	} else {
		// Fallback - still make it blue
		blueURL := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#3E63DD")).
			Render(pr.HTMLURL)
		output.WriteString(blueURL)
	}

	// Add NextAction kinds if available
	appendNextActionKinds(&output, pr, username)

	output.WriteString("\n")
	return output.String()
}

func orgFromURL(urlStr string) string {
	// Extract org/owner from GitHub URL
	parts := strings.Split(urlStr, "/")
	if len(parts) >= minOrgURLParts && strings.Contains(urlStr, "github.com") {
		return parts[3] // This is the org/owner
	}
	return ""
}

func sortPRsByUpdateTime(prs []PR) {
	sort.Slice(prs, func(i, j int) bool {
		return prs[i].UpdatedAt.After(prs[j].UpdatedAt)
	})
}
