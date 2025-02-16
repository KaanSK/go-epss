package epss_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/KaanSK/go-epss"
)

func TestClientOptions(t *testing.T) {
	tests := []struct {
		name     string
		options  []epss.ClientOption
		validate func(*testing.T, *epss.Client)
	}{
		{
			name:    "default client",
			options: nil,
			validate: func(t *testing.T, c *epss.Client) {
				if c == nil {
					t.Fatal("Expected a client, got nil")
				}
				if c.DataUrl != "https://epss.cyentia.com/epss_scores-current.csv.gz" {
					t.Fatalf("Expected default URL, got %s", c.DataUrl)
				}
				if c.HttpClient == nil {
					t.Fatal("Expected default HTTP client, got nil")
				}
				if c.HttpClient.Timeout != 10*time.Second {
					t.Fatalf("Expected default timeout of 10s, got %s", c.HttpClient.Timeout)
				}
			},
		},
		{
			name: "custom http client",
			options: []epss.ClientOption{
				epss.WithHTTPClient(&http.Client{
					Timeout: 30 * time.Second,
				}),
			},
			validate: func(t *testing.T, c *epss.Client) {
				if c.HttpClient.Timeout != 30*time.Second {
					t.Fatalf("Expected custom timeout of 30s, got %s", c.HttpClient.Timeout)
				}
			},
		},
		{
			name: "custom data url",
			options: []epss.ClientOption{
				epss.WithDataURL("https://example.com/epss_scores-current.csv.gz"),
			},
			validate: func(t *testing.T, c *epss.Client) {
				if c.DataUrl != "https://example.com/epss_scores-current.csv.gz" {
					t.Fatalf("Expected custom URL, got %s", c.DataUrl)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := epss.NewClient(tt.options...)
			tt.validate(t, client)
		})
	}
}

func TestEPSSOperations(t *testing.T) {
	// Create a single client for all tests to minimize network requests
	client := epss.NewClient()

	// First, get all scores which will populate the client's cache
	allScores, err := client.GetAllScores()
	if err != nil {
		t.Fatalf("Failed to get all scores: %v", err)
	}

	// Validate metadata is properly populated
	if client.Metadata == nil {
		t.Fatal("Expected metadata to be present, got nil")
	}
	if client.Metadata.ModelVersion == "" {
		t.Fatal("Expected ModelVersion to be set, got empty string")
	}
	if client.Metadata.ScoreDate.IsZero() {
		t.Fatal("Expected ScoreDate to be set, got zero time")
	}
	if client.LastUpdated.IsZero() {
		t.Fatal("Expected LastUpdated to be set, got zero time")
	}

	// Use the first CVE from allScores for GetScore test
	if len(allScores) == 0 {
		t.Fatal("Expected non-zero scores, got zero")
	}
	firstCVE := allScores[0].CVE

	tests := []struct {
		name     string
		testFunc func(*testing.T)
	}{
		{
			name: "get existing CVE score",
			testFunc: func(t *testing.T) {
				score, err := client.GetScore(firstCVE)
				if err != nil {
					t.Fatalf("Failed to get score for %s: %v", firstCVE, err)
				}
				if score == nil {
					t.Fatal("Expected a score, got nil")
				}
				if score.CVE != firstCVE {
					t.Fatalf("Expected CVE %s, got %s", firstCVE, score.CVE)
				}
			},
		},
		{
			name: "get non-existent CVE score",
			testFunc: func(t *testing.T) {
				_, err := client.GetScore("CVE-9999-9999")
				if err == nil {
					t.Fatal("Expected error for non-existent CVE, got nil")
				}
			},
		},
		{
			name: "get invalid CVE format",
			testFunc: func(t *testing.T) {
				_, err := client.GetScore("NOT-A-CVE")
				if err == nil {
					t.Fatal("Expected error for invalid CVE format, got nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t)
		})
	}
}
