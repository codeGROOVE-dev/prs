package main

import (
	"testing"
	"time"
)

func TestFormatAge(t *testing.T) {
	tests := []struct {
		name     string
		time     time.Time
		expected string
	}{
		{
			name:     "minutes",
			time:     time.Now().Add(-30 * time.Minute),
			expected: "30m",
		},
		{
			name:     "hours",
			time:     time.Now().Add(-5 * time.Hour),
			expected: "5h",
		},
		{
			name:     "days",
			time:     time.Now().Add(-3 * 24 * time.Hour),
			expected: "3d",
		},
		{
			name:     "weeks",
			time:     time.Now().Add(-14 * 24 * time.Hour),
			expected: "2w",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatAge(tt.time)
			if got != tt.expected {
				t.Errorf("formatAge() = %v, want %v", got, tt.expected)
			}
		})
	}
}

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
			got := isBlockingOnUser(tt.pr, tt.username)
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
			got := wasBlockingBefore(tt.pr, tt.lastPRs, tt.username)
			if got != tt.expected {
				t.Errorf("wasBlockingBefore() = %v, want %v", got, tt.expected)
			}
		})
	}
}
