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
	"sync"
	"syscall"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/charmbracelet/lipgloss"
	"github.com/ready-to-review/turnclient/pkg/turn"
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
	
	// Turn server metadata
	TurnResponse *turn.CheckResponse `json:"turn_response,omitempty"`
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
	defaultTurnServerURL    = "https://turn.ready-to-review.dev"
	maxConcurrentRequests   = 10 // Limit concurrent requests to avoid overwhelming servers
)

// Style definitions
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

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#874BFD")).
			Padding(1, 2)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#874BFD")).
			Padding(0, 1).
			Margin(0, 1)
)

func main() {
	var (
		watch         = flag.Bool("watch", false, "Continuously watch for PR updates")
		watchInterval = flag.Int("watch-interval", defaultWatchInterval, "Watch interval in minutes (default: 10)")
		all           = flag.Bool("all", false, "Show all PRs (not just those blocking on you)")
		notify        = flag.Bool("notify", false, "Watch for PRs and notify when they become newly blocking")
		turnServer    = flag.String("turn-server", defaultTurnServerURL, "Turn server URL for enhanced metadata")
		org           = flag.String("org", "", "Filter PRs to specific organization")
		debug         bool
	)
	flag.BoolVar(&debug, "debug", false, "Show debug information including API calls and turnclient data")
	flag.Parse()

	// Set up logger
	var logger *log.Logger
	if debug {
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

	// Set up turn client if turn server is specified
	var turnClient *turn.Client
	if *turnServer != "" {
		turnClient, err = turn.NewClient(*turnServer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating turn client: %v\n", err)
			os.Exit(1)
		}
		if debug {
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
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
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
	// Build the search query
	query := fmt.Sprintf("involves:%s type:pr state:open", username)
	
	// Add org filter if specified
	if org != "" {
		query += fmt.Sprintf(" org:%s", org)
	}

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

	logger.Printf("Found %d PRs (before deduplication)", len(result.Items))
	
	// Deduplicate PRs by URL (in case GitHub returns duplicates)
	result.Items = deduplicatePRs(result.Items)
	logger.Printf("Found %d PRs (after deduplication)", len(result.Items))

	// Fetch detailed PR info for each PR to get review status (parallel)
	enrichStart := time.Now()
	if err := enrichPRsParallel(ctx, token, result.Items, logger, httpClient, turnClient, debug); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		// Continue even if enrichment fails - we'll have basic PR data
		logger.Printf("Failed to enrich PR data: %v", err)
	}
	if debug {
		logger.Printf("Enriched %d PRs in %v", len(result.Items), time.Since(enrichStart))
	}

	return result.Items, nil
}

func deduplicatePRs(prs []PR) []PR {
	seen := make(map[string]int) // URL -> index in result slice
	var result []PR
	
	for _, pr := range prs {
		if existingIndex, exists := seen[pr.HTMLURL]; exists {
			// If we've seen this PR before, keep the one with the later updated time
			if pr.UpdatedAt.After(result[existingIndex].UpdatedAt) {
				result[existingIndex] = pr
			}
		} else {
			// First time seeing this PR
			seen[pr.HTMLURL] = len(result)
			result = append(result, pr)
		}
	}
	
	return result
}

func enrichPRsParallel(ctx context.Context, token string, prs []PR, logger *log.Logger, httpClient *http.Client, turnClient *turn.Client, debug bool) error {
	// Create a semaphore to limit concurrent requests
	semaphore := make(chan struct{}, maxConcurrentRequests)
	
	// Create a wait group to wait for all goroutines to complete
	var wg sync.WaitGroup
	
	// Channel to collect any errors
	errChan := make(chan error, len(prs))
	
	// Launch goroutines for each PR
	for i := range prs {
		wg.Add(1)
		go func(pr *PR) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			// Check for cancellation
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
			}
			
			// Enrich the PR data
			if err := enrichPRData(ctx, token, pr, logger, httpClient, turnClient, debug); err != nil {
				if errors.Is(err, context.Canceled) {
					errChan <- err
					return
				}
				// Log error but don't fail the whole operation
				logger.Printf("Failed to enrich PR #%d: %v", pr.Number, err)
			}
		}(&prs[i])
	}
	
	// Wait for all goroutines to complete
	wg.Wait()
	close(errChan)
	
	// Check for cancellation errors
	for err := range errChan {
		if errors.Is(err, context.Canceled) {
			return err
		}
	}
	
	return nil
}

func enrichPRData(ctx context.Context, token string, pr *PR, logger *log.Logger, httpClient *http.Client, turnClient *turn.Client, debug bool) error {
	start := time.Now()
	defer func() {
		if debug {
			logger.Printf("Enriched PR #%d in %v", pr.Number, time.Since(start))
		}
	}()

	// Extract repo and number from URL
	parts := strings.Split(pr.HTMLURL, "/")
	if len(parts) < minPRURLParts {
		return errors.New("invalid PR URL")
	}
	owner := parts[3]
	repo := parts[4]

	// Fetch PR details
	url := fmt.Sprintf(apiReposPullsEndpoint, owner, repo, pr.Number)

	githubStart := time.Now()
	err := retry.Do(
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
	
	if err != nil {
		return err
	}

	if debug {
		logger.Printf("GitHub API call for PR #%d took %v", pr.Number, time.Since(githubStart))
	}

	// Enrich with turn server data if available
	if turnClient != nil {
		turnStart := time.Now()
		if debug {
			logger.Printf("Sending turnclient request for PR #%d: URL=%s, UpdatedAt=%s", 
				pr.Number, pr.HTMLURL, pr.UpdatedAt.Format(time.RFC3339))
		}
		
		turnResponse, err := turnClient.Check(ctx, pr.HTMLURL, pr.UpdatedAt)
		if err != nil {
			logger.Printf("Failed to get turn data for PR #%d: %v", pr.Number, err)
			// Don't fail the entire enrichment if turn server is unavailable
		} else {
			pr.TurnResponse = turnResponse
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
		blocking := isBlockingOnUser(pr, username)
		if blocking {
			blockingCount++
		}
		if debug {
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
	}

	// Display header with beautiful styling
	fmt.Print("\n")
	if blockingOnly && blockingCount > 0 {
		header := fmt.Sprintf("🔥 %d PR%s awaiting your review", blockingCount, pluralize(blockingCount))
		fmt.Println(titleStyle.Render(header))
	} else if !blockingOnly {
		fmt.Println(titleStyle.Render("📋 Pull Request Dashboard"))
		
		// Add a summary line
		totalPRs := len(incoming) + len(outgoing)
		summaryText := fmt.Sprintf("📊 %d total PR%s • %d incoming • %d outgoing • %d blocking you", 
			totalPRs, pluralize(totalPRs), len(incoming), len(outgoing), blockingCount)
		fmt.Println(infoStyle.Render(summaryText))
	}

	// Display incoming PRs (authored by others)
	if len(incoming) > 0 && (!blockingOnly || blockingCount > 0) {
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

	// Display outgoing PRs (authored by you) - only if --all flag is used
	if len(outgoing) > 0 && !blockingOnly {
		fmt.Print("\n")
		fmt.Println(headerStyle.Render("⬆️  Your PRs"))
		fmt.Print("\n")
		for _, pr := range outgoing {
			displayPR(pr, username)
		}
	}

	if blockingOnly && blockingCount == 0 {
		fmt.Print("\n")
		fmt.Println(successStyle.Render("✨ No PRs awaiting your review - you're all caught up!"))
	}
	fmt.Print("\n")
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

	// Get PR icon based on status
	icon := getPRIcon(pr)

	// Prepare tags display with colors
	var tagsDisplay string
	if pr.TurnResponse != nil && len(pr.TurnResponse.Tags) > 0 {
		var coloredTags []string
		for _, tag := range pr.TurnResponse.Tags {
			coloredTags = append(coloredTags, getColoredTag(tag))
		}
		tagsDisplay = fmt.Sprintf(" %s", strings.Join(coloredTags, " "))
	}

	// Create styled components
	bullet := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6")).Render("●")
	prIcon := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6")).Render(icon)
	title := prTitleStyle.Render(truncate(pr.Title, maxTitleLength))
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

	// Add a subtle separator line
	separator := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#444444")).
		Render("    ─────────────────────────────────────────────────────────────────")

	// Print with nice spacing
	fmt.Println(prLine)
	fmt.Println(infoLine)
	fmt.Println(separator)
}

func getPRIcon(pr PR) string {
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

func getColoredTag(tag string) string {
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
		return fmt.Sprintf("📅 %dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("📅 %dh ago", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("📅 %dd ago", int(d.Hours()/24))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("📅 %dw ago", int(d.Hours()/(24*7)))
	default:
		return fmt.Sprintf("📅 %dmo ago", int(d.Hours()/(24*30)))
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

func runWatchMode(ctx context.Context, token, username string, blockingOnly bool, notifyMode bool, intervalMinutes int, logger *log.Logger, httpClient *http.Client, turnClient *turn.Client, debug bool, org string) {
	// Clear screen
	fmt.Print("\033[H\033[2J")

	var lastPRs []PR
	ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
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
			displayHeader()
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
				displayHeader()
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
						if !wasPRBefore(pr, lastPRs) {
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

		case <-done:
			fmt.Println("\nExiting...")
			return
		}
	}
}

func displayHeader() {
	header := "🔄 Live PR Dashboard - Press 'q' to quit"
	fmt.Println(titleStyle.Render(header))
	fmt.Println()
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
