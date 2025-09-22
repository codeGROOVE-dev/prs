package main

import (
	"strings"
	"testing"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		length   int
		expected string
	}{
		{
			name:     "short string",
			input:    "hello",
			length:   10,
			expected: "hello",
		},
		{
			name:     "exact length",
			input:    "hello world",
			length:   11,
			expected: "hello world",
		},
		{
			name:     "needs truncation",
			input:    "this is a very long string that needs truncation",
			length:   20,
			expected: "this is a very lo...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.input, tt.length)
			if got != tt.expected {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.length, got, tt.expected)
			}
		})
	}
}

func TestIsBlockingOnUser(t *testing.T) {
	tests := []struct {
		name     string
		pr       PR
		username string
		expected bool
	}{
		{
			name: "user is requested reviewer",
			pr: PR{
				RequestedReviewers: []User{
					{Login: "alice"},
					{Login: "bob"},
				},
			},
			username: "alice",
			expected: true,
		},
		{
			name: "user is not requested reviewer",
			pr: PR{
				RequestedReviewers: []User{
					{Login: "alice"},
					{Login: "bob"},
				},
			},
			username: "charlie",
			expected: false,
		},
		{
			name:     "no requested reviewers",
			pr:       PR{},
			username: "alice",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBlockingOnUser(&tt.pr, tt.username)
			if got != tt.expected {
				t.Errorf("isBlockingOnUser() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestWasBlockingBefore(t *testing.T) {
	pr1 := PR{
		Number: 123,
		Repository: struct {
			FullName string `json:"full_name"`
		}{FullName: "org/repo"},
		RequestedReviewers: []User{{Login: "alice"}},
	}

	pr2 := PR{
		Number: 456,
		Repository: struct {
			FullName string `json:"full_name"`
		}{FullName: "org/repo"},
		RequestedReviewers: []User{{Login: "bob"}},
	}

	lastPRs := []PR{pr1, pr2}

	tests := []struct {
		name     string
		pr       PR
		lastPRs  []PR
		username string
		expected bool
	}{
		{
			name: "was blocking before",
			pr: PR{
				Number: 123,
				Repository: struct {
					FullName string `json:"full_name"`
				}{FullName: "org/repo"},
			},
			lastPRs:  lastPRs,
			username: "alice",
			expected: true,
		},
		{
			name: "was not blocking before",
			pr: PR{
				Number: 456,
				Repository: struct {
					FullName string `json:"full_name"`
				}{FullName: "org/repo"},
			},
			lastPRs:  lastPRs,
			username: "alice",
			expected: false,
		},
		{
			name: "new PR",
			pr: PR{
				Number: 789,
				Repository: struct {
					FullName string `json:"full_name"`
				}{FullName: "org/repo"},
			},
			lastPRs:  lastPRs,
			username: "alice",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wasBlockingBefore(&tt.pr, tt.lastPRs, tt.username)
			if got != tt.expected {
				t.Errorf("wasBlockingBefore() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOrgFromURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "valid github PR URL",
			url:      "https://github.com/owner/repo/pull/123",
			expected: "owner",
		},
		{
			name:     "valid github issue URL",
			url:      "https://github.com/org/project/issues/456",
			expected: "org",
		},
		{
			name:     "non-github URL",
			url:      "https://example.com/something/else",
			expected: "",
		},
		{
			name:     "malformed URL",
			url:      "not-a-url",
			expected: "",
		},
		{
			name:     "github URL with too few parts",
			url:      "https://github.com/",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := orgFromURL(tt.url)
			if got != tt.expected {
				t.Errorf("orgFromURL(%q) = %q, want %q", tt.url, got, tt.expected)
			}
		})
	}
}

func TestCategorizePRs(t *testing.T) {
	prs := []PR{
		{
			Number: 1,
			User:   User{Login: "alice"},
		},
		{
			Number: 2,
			User:   User{Login: "bob"},
		},
		{
			Number: 3,
			User:   User{Login: "alice"},
		},
		{
			Number: 4,
			User:   User{Login: "charlie"},
		},
	}

	incoming, outgoing := categorizePRs(prs, "alice")

	if len(outgoing) != 2 {
		t.Errorf("Expected 2 outgoing PRs, got %d", len(outgoing))
	}
	if len(incoming) != 2 {
		t.Errorf("Expected 2 incoming PRs, got %d", len(incoming))
	}

	// Verify correct categorization
	for _, pr := range outgoing {
		if pr.User.Login != "alice" {
			t.Errorf("Outgoing PR has wrong author: %s", pr.User.Login)
		}
	}
	for _, pr := range incoming {
		if pr.User.Login == "alice" {
			t.Errorf("Incoming PR has wrong author: %s", pr.User.Login)
		}
	}
}

func TestGeneratePRDisplayBlockedFlag(t *testing.T) {
	username := "alice"

	// Create test PRs with blocking/non-blocking scenarios
	incomingBlocked := PR{
		Number:             1,
		Title:              "Incoming blocked PR",
		HTMLURL:            "https://github.com/org/repo/pull/1",
		User:               User{Login: "bob"},
		RequestedReviewers: []User{{Login: "alice"}}, // alice is requested reviewer
	}

	incomingNotBlocked := PR{
		Number:             2,
		Title:              "Incoming non-blocked PR",
		HTMLURL:            "https://github.com/org/repo/pull/2",
		User:               User{Login: "charlie"},
		RequestedReviewers: []User{{Login: "dave"}}, // alice is not requested reviewer
	}

	outgoingBlocked := PR{
		Number:             3,
		Title:              "Outgoing blocked PR",
		HTMLURL:            "https://github.com/org/repo/pull/3",
		User:               User{Login: "alice"},     // alice is author
		RequestedReviewers: []User{{Login: "alice"}}, // alice is requested reviewer (perhaps due to turn server logic)
	}

	outgoingNotBlocked := PR{
		Number:             4,
		Title:              "Outgoing non-blocked PR",
		HTMLURL:            "https://github.com/org/repo/pull/4",
		User:               User{Login: "alice"},   // alice is author
		RequestedReviewers: []User{{Login: "eve"}}, // alice is not requested reviewer
	}

	allPRs := []PR{incomingBlocked, incomingNotBlocked, outgoingBlocked, outgoingNotBlocked}

	tests := []struct {
		name                string
		prs                 []PR
		blockingOnly        bool
		expectIncoming      bool
		expectOutgoing      bool
		expectIncomingCount int
		expectOutgoingCount int
	}{
		{
			name:                "normal mode shows all PRs",
			prs:                 allPRs,
			blockingOnly:        false,
			expectIncoming:      true,
			expectOutgoing:      true,
			expectIncomingCount: 2, // both incoming PRs
			expectOutgoingCount: 2, // both outgoing PRs
		},
		{
			name:                "blocked mode shows only blocked PRs",
			prs:                 allPRs,
			blockingOnly:        true,
			expectIncoming:      true, // has blocked incoming
			expectOutgoing:      true, // has blocked outgoing
			expectIncomingCount: 1,    // only blocked incoming
			expectOutgoingCount: 1,    // only blocked outgoing
		},
		{
			name:                "blocked mode with only incoming blocked",
			prs:                 []PR{incomingBlocked, incomingNotBlocked, outgoingNotBlocked},
			blockingOnly:        true,
			expectIncoming:      true,  // has blocked incoming
			expectOutgoing:      false, // no blocked outgoing
			expectIncomingCount: 1,     // only blocked incoming
			expectOutgoingCount: 0,     // no outgoing shown
		},
		{
			name:                "blocked mode with only outgoing blocked",
			prs:                 []PR{incomingNotBlocked, outgoingBlocked, outgoingNotBlocked},
			blockingOnly:        true,
			expectIncoming:      false, // no blocked incoming
			expectOutgoing:      true,  // has blocked outgoing
			expectIncomingCount: 0,     // no incoming shown
			expectOutgoingCount: 1,     // only blocked outgoing
		},
		{
			name:                "blocked mode with no blocked PRs",
			prs:                 []PR{incomingNotBlocked, outgoingNotBlocked},
			blockingOnly:        true,
			expectIncoming:      false, // no blocked incoming
			expectOutgoing:      false, // no blocked outgoing
			expectIncomingCount: 0,     // no incoming shown
			expectOutgoingCount: 0,     // no outgoing shown
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := generatePRDisplay(tt.prs, username, tt.blockingOnly, false, true, nil)

			// Debug output for failing test
			if tt.name == "blocked mode with only outgoing blocked" {
				t.Logf("Debug output: %q", output)
			}

			// For the case with no blocked PRs, expect empty output
			if !tt.expectIncoming && !tt.expectOutgoing {
				if strings.TrimSpace(output) != "" {
					t.Errorf("Expected empty output for no blocked PRs, got: %q", output)
				}
				return
			}

			// Check for incoming section presence
			hasIncomingSection := strings.Contains(output, "incoming -")
			if hasIncomingSection != tt.expectIncoming {
				t.Errorf("Expected incoming section: %v, got: %v", tt.expectIncoming, hasIncomingSection)
			}

			// Check for outgoing section presence
			hasOutgoingSection := strings.Contains(output, "outgoing -")
			if hasOutgoingSection != tt.expectOutgoing {
				t.Errorf("Expected outgoing section: %v, got: %v", tt.expectOutgoing, hasOutgoingSection)
			}

			// Count actual PRs shown in each section
			if tt.expectIncoming {
				incomingLines := 0
				lines := strings.Split(output, "\n")
				incomingStarted := false
				for _, line := range lines {
					if strings.Contains(line, "incoming -") {
						incomingStarted = true
						continue
					}
					if strings.Contains(line, "outgoing -") {
						break
					}
					if incomingStarted && (strings.HasPrefix(line, "• ") || strings.HasPrefix(line, "  ")) {
						incomingLines++
					}
				}
				if incomingLines != tt.expectIncomingCount {
					t.Errorf("Expected %d incoming PRs shown, got %d", tt.expectIncomingCount, incomingLines)
				}
			}

			if tt.expectOutgoing {
				outgoingLines := 0
				lines := strings.Split(output, "\n")
				outgoingStarted := false
				for _, line := range lines {
					if strings.Contains(line, "outgoing -") {
						outgoingStarted = true
						continue
					}
					if outgoingStarted && (strings.HasPrefix(line, "• ") || strings.HasPrefix(line, "  ")) {
						outgoingLines++
					}
				}
				if outgoingLines != tt.expectOutgoingCount {
					t.Errorf("Expected %d outgoing PRs shown, got %d", tt.expectOutgoingCount, outgoingLines)
				}
			}
		})
	}
}
