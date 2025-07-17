package main

import (
	"bufio"
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
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	RequestedReviewers []User `json:"requested_reviewers"`
	
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

const (
	defaultTimeout          = 30 * time.Second
	defaultWatchInterval    = 90 * time.Second
	maxPerPage              = 100
	retryAttempts           = 3
	retryDelay              = time.Second
	retryMaxDelay           = 10 * time.Second
	enrichRetries        = 2
	enrichDelay          = 500 * time.Millisecond
	enrichMaxDelay       = 2 * time.Second
	apiUserEndpoint         = "https://api.github.com/user"
	apiSearchEndpoint    = "https://api.github.com/search/issues"
	apiPullsEndpoint     = "https://api.github.com/repos/%s/%s/pulls/%d"
	defaultTurnServerURL    = "https://turn.ready-to-review.dev"
	maxConcurrent        = 20 // Increased for better throughput
	cacheTTL             = 5 * 24 * time.Hour // 5 days
)

// Style definitions.
var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF6B6B")).
			Bold(true).
			Underline(true)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#4ECDC4")).
			Bold(true).
			Padding(0, 1)

	prTitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#45B7D1")).
			Bold(true)

	ageStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#96CEB4"))

	urlStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FECA57")).
			Underline(true)

	tagStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF9FF3")).
			Bold(true)

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#54A0FF"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#5F27CD")).
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
	
	os.MkdirAll(filepath.Dir(path), 0755)
	data, _ := json.Marshal(cacheEntry{Response: response, Timestamp: time.Now()})
	os.WriteFile(path, data, 0644)
}

func main() {
	var (
		watch         = flag.Bool("watch", false, "Continuously watch for PR updates")
		watchInterval = flag.Duration("watch-interval", defaultWatchInterval, "Watch interval (default: 90s)")
		all           = flag.Bool("all", false, "Show all PRs (not just those blocking on you)")
		notify        = flag.Bool("notify", false, "Watch for PRs and notify when they become newly blocking")
		turnServer    = flag.String("turn-server", defaultTurnServerURL, "Turn server URL for enhanced metadata")
		org           = flag.String("org", "", "Filter PRs to specific organization")
		debug         bool
	)
	flag.BoolVar(&debug, "debug", false, "Show debug information including API calls and turnclient data")
	flag.Parse()
	
	// Validate org parameter to prevent injection
	if *org != "" {
		// Allow only alphanumeric, dash, and underscore (GitHub org naming rules)
		if !isValidOrgName(*org) {
			fmt.Fprintf(os.Stderr, "error: invalid organization name\n")
			os.Exit(1)
		}
	}

	// Set up logger
	var logger *log.Logger
	if debug {
		logger = log.New(os.Stderr, "[github-pr-notifier] ", log.Ltime)
	} else {
		logger = log.New(io.Discard, "", 0)
	}

	// Set up HTTP client with optimized settings
	httpClient := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,  // Increased for better connection reuse
			MaxIdleConnsPerHost: 10,   // Allow more connections per host
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false,
			DisableCompression:  false,
			ForceAttemptHTTP2:   true,  // Use HTTP/2 when available
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

	// Set up turn client if turn server is specified
	var turnClient *turn.Client
	if *turnServer != "" {
		turnClient, err = turn.NewClient(*turnServer)
		if err != nil {
			logger.Printf("ERROR: Failed to create turn client for %s: %v", *turnServer, err)
			fmt.Fprintf(os.Stderr, "warning: failed to connect to turn server\n")
			turnClient = nil
		} else {
			logger.Printf("INFO: Connected to turn server at %s", *turnServer)
			if debug {
				turnClient.SetLogger(logger)
			}
			if token != "" {
				turnClient.SetAuthToken(token)
			}
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

	// If either watch or notify is set, run in watch mode
	if *watch || *notify {
		runWatchMode(ctx, token, username, !*all, *notify, *watchInterval, logger, httpClient, turnClient, debug, *org)
	} else {
		// One-time display
		prs, err := fetchPRsWithRetry(ctx, token, username, logger, httpClient, turnClient, debug, *org)
		if err != nil {
			if err == context.Canceled {
				fmt.Fprintf(os.Stderr, "\nOperation cancelled\n")
			} else {
				fmt.Fprintf(os.Stderr, "Error fetching PRs: %v\n", err)
			}
			os.Exit(1)
		}
		displayPRs(prs, username, !*all, debug)
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
	query := fmt.Sprintf("involves:%s type:pr state:open", username)
	if org != "" {
		// org is already validated, safe to use
		query += fmt.Sprintf(" org:%s", org)
	}
	
	resp, err := makeGitHubSearchRequest(ctx, query, token, httpClient, logger)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	prs, err := parseSearchResponse(resp)
	if err != nil {
		return nil, err
	}

	logger.Printf("Found %d PRs (before deduplication)", len(prs))
	prs = deduplicatePRs(prs)
	logger.Printf("Found %d PRs (after deduplication)", len(prs))

	if err := enrichPRsParallel(ctx, token, prs, logger, httpClient, turnClient, debug); err != nil {
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

func enrichPRsParallel(ctx context.Context, token string, prs []PR, logger *log.Logger, httpClient *http.Client, turnClient *turn.Client, debug bool) error {
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
			if err := enrichPRData(ctx, pr, logger, turnClient, debug); err != nil {
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


func enrichPRData(ctx context.Context, pr *PR, logger *log.Logger, turnClient *turn.Client, debug bool) error {
	start := time.Now()
	defer func() {
		if debug {
			logger.Printf("Enriched PR #%d in %v", pr.Number, time.Since(start))
		}
	}()

	// The search API already provides all the PR data we need,
	// so we can skip individual PR API calls entirely

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
		
		turnResponse, err := turnClient.Check(ctx, pr.HTMLURL, pr.UpdatedAt)
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
	if pr.TurnResponse != nil && pr.TurnResponse.NextAction != nil {
		_, hasAction := pr.TurnResponse.NextAction[username]
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

func displayPRs(prs []PR, username string, blockingOnly bool, debug bool) {
	incoming, outgoing := categorizePRs(prs, username)
	blockingCount := countBlockingPRs(incoming, username, debug)

	displayHeader(blockingOnly, blockingCount, len(incoming), len(outgoing))
	
	if len(incoming) > 0 && (!blockingOnly || blockingCount > 0) {
		displayIncomingPRs(incoming, username, blockingOnly)
	}
	
	if len(outgoing) > 0 && !blockingOnly {
		displayOutgoingPRs(outgoing, username)
	}
	
	if blockingOnly && blockingCount == 0 {
		fmt.Print("\n")
		fmt.Println(successStyle.Render("✨ No PRs awaiting your review - you're all caught up!"))
	}
	fmt.Print("\n")
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
		if pr.TurnResponse.NextAction != nil {
			fmt.Fprintf(os.Stderr, "  NextAction: %+v\n", pr.TurnResponse.NextAction)
		}
		if len(pr.TurnResponse.Tags) > 0 {
			fmt.Fprintf(os.Stderr, "  Tags: %v\n", pr.TurnResponse.Tags)
		}
	}
}

func displayHeader(blockingOnly bool, blockingCount, incomingCount, outgoingCount int) {
	fmt.Print("\n")
	if blockingOnly && blockingCount > 0 {
		plural := ""
		if blockingCount != 1 {
			plural = "s"
		}
		header := fmt.Sprintf("🔥 %d PR%s awaiting your review", blockingCount, plural)
		fmt.Println(titleStyle.Render(header))
	} else if !blockingOnly {
		fmt.Println(titleStyle.Render("📋 Pull Request Dashboard"))
		
		totalPRs := incomingCount + outgoingCount
		summaryText := fmt.Sprintf("📊 %d total PR%s • %d incoming • %d outgoing • %d blocking you", 
			totalPRs, func() string { if totalPRs == 1 { return "" }; return "s" }(), incomingCount, outgoingCount, blockingCount)
		fmt.Println(infoStyle.Render(summaryText))
	}
}


func displayIncomingPRs(incoming []PR, username string, blockingOnly bool) {
	if !blockingOnly {
		fmt.Print("\n")
		fmt.Println(headerStyle.Render("⬇️  Incoming PRs"))
	}
	fmt.Print("\n")

	for _, pr := range incoming {
		if blockingOnly && !isBlockingOnUser(pr, username) {
			continue
		}
		displayPR(pr, username)
	}
}

func displayOutgoingPRs(outgoing []PR, username string) {
	fmt.Print("\n")
	fmt.Println(headerStyle.Render("⬆️  Your PRs"))
	fmt.Print("\n")
	for _, pr := range outgoing {
		displayPR(pr, username)
	}
}


func displayPR(pr PR, username string) {
	// Format age
	age := formatAge(pr.UpdatedAt)

	// Get PR icon based on status
	icon := prIcon(pr)

	// Prepare tags display with colors
	var tagsDisplay string
	if pr.TurnResponse != nil && len(pr.TurnResponse.Tags) > 0 {
		var coloredTags []string
		for _, tag := range pr.TurnResponse.Tags {
			coloredTags = append(coloredTags, coloredTag(tag))
		}
		tagsDisplay = fmt.Sprintf(" %s", strings.Join(coloredTags, " "))
	}

	// Create styled components
	bullet := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6")).Render("●")
	prIcon := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6")).Render(icon)
	title := prTitleStyle.Render(truncate(pr.Title, 60))
	ageFormatted := ageStyle.Render(age)
	url := urlStyle.Render(truncateURL(pr.HTMLURL, 80))

	// Create the main PR line with bullet
	prLine := fmt.Sprintf("  %s %s %s", bullet, prIcon, title)
	
	// Add blocking indicator if user is blocked
	if isBlockingOnUser(pr, username) {
		blockingIndicator := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF5555")).
			Bold(true).
			Render(" ⚡")
		prLine += blockingIndicator
	}

	// Create info line with indentation
	infoLine := fmt.Sprintf("     %s • %s%s", ageFormatted, url, tagsDisplay)

	// Print with nice spacing
	fmt.Println(prLine)
	fmt.Println(infoLine)
	fmt.Println()
}

func prIcon(pr PR) string {
	if pr.Draft {
		return "🚧"
	}
	if pr.TurnResponse != nil && pr.TurnResponse.ReadyToMerge {
		return "✅"
	}
	if pr.TurnResponse != nil {
		for _, tag := range pr.TurnResponse.Tags {
			switch tag {
			case "has_approval":
				return "👍"
			case "merge_conflict":
				return "💥"
			case "stale":
				return "⏰"
			case "failing_tests":
				return "❌"
			}
		}
	}
	return "📝"
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

func runWatchMode(ctx context.Context, token, username string, blockingOnly bool, notifyMode bool, interval time.Duration, logger *log.Logger, httpClient *http.Client, turnClient *turn.Client, debug bool, org string) {
	// Clear screen
	fmt.Print("\033[H\033[2J")

	var lastPRs []PR
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial fetch and display (unless notify-only mode)
	prs, err := fetchPRsWithRetry(ctx, token, username, logger, httpClient, turnClient, debug, org)
	if err != nil {
		if err != context.Canceled {
			fmt.Fprintf(os.Stderr, "Error fetching PRs: %v\n", err)
		}
	} else {
		lastPRs = prs

		// Display PRs unless we're in notify-only mode
		if !notifyMode {
			header := "🔄 Live PR Dashboard - Press 'q' to quit"
			fmt.Println(titleStyle.Render(header))
			fmt.Println()
			displayPRs(prs, username, blockingOnly, debug)
		} else {
			// In notify mode, show what we're watching for
			if blockingOnly {
				watchMsg := "🔍 Watching for newly blocking PRs..."
				fmt.Println(infoStyle.Render(watchMsg))
			} else {
				watchMsg := "🔍 Watching for all new PRs..."
				fmt.Println(infoStyle.Render(watchMsg))
			}
		}
	}

	// Set up interrupt handler
	quitCh := make(chan bool)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if scanner.Text() == "q" {
				quitCh <- true
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
			prs, err := fetchPRsWithRetry(ctx, token, username, logger, httpClient, turnClient, debug, org)
			if err != nil {
				if err != context.Canceled {
					fmt.Fprintf(os.Stderr, "Error fetching PRs: %v\n", err)
				}
				continue
			}

			// If not in notify-only mode, clear and redraw
			if !notifyMode {
				fmt.Print("\033[H\033[2J")
				header := "🔄 Live PR Dashboard - Press 'q' to quit"
			fmt.Println(titleStyle.Render(header))
			fmt.Println()
				displayPRs(prs, username, blockingOnly, debug)
			}

			// Check for new PRs based on mode
			if notifyMode {
				if blockingOnly {
					// Notify only for newly blocking PRs
					for _, pr := range prs {
						if isBlockingOnUser(pr, username) && !wasBlockingBefore(pr, lastPRs, username) {
							fmt.Print("\n")
							alertMsg := "⚡ NEW BLOCKING PR:"
							fmt.Println(lipgloss.NewStyle().
								Foreground(lipgloss.Color("#FF5555")).
								Bold(true).
								Render(alertMsg))
							displayPR(pr, username)
							fmt.Println()
						}
					}
				} else {
					// --notify --all: Show all new PRs
					for _, pr := range prs {
						_, exists := findPRInList(pr, lastPRs)
						if !exists {
							fmt.Print("\n")
							alertMsg := "✨ NEW PR:"
							fmt.Println(lipgloss.NewStyle().
								Foreground(lipgloss.Color("#00FF00")).
								Bold(true).
								Render(alertMsg))
							displayPR(pr, username)
							fmt.Println()
						}
					}
				}
			} else {
				// In watch mode, just note newly blocking PRs
				for _, pr := range prs {
					if isBlockingOnUser(pr, username) && !wasBlockingBefore(pr, lastPRs, username) {
						newPRMsg := fmt.Sprintf("⚡ NEW BLOCKING PR: %s", pr.Title)
						fmt.Print("\n")
						fmt.Println(lipgloss.NewStyle().
							Foreground(lipgloss.Color("#FF5555")).
							Bold(true).
							Render(newPRMsg))
					}
				}
			}

			lastPRs = prs

		case <-quitCh:
			fmt.Println("\nExiting...")
			return
		}
	}
}

func wasBlockingBefore(pr PR, previous []PR, username string) bool {
	if found, exists := findPRInList(pr, previous); exists {
		return isBlockingOnUser(found, username)
	}
	return false
}

func findPRInList(target PR, prs []PR) (PR, bool) {
	for _, pr := range prs {
		if pr.Number == target.Number && pr.Repository.FullName == target.Repository.FullName {
			return pr, true
		}
	}
	return PR{}, false
}
