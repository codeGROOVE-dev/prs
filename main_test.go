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
