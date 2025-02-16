package epss

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Score struct {
	CVE        string
	EPSS       float32
	Percentile float32
}

type Metadata struct {
	ModelVersion string    `json:"model_version"`
	ScoreDate    time.Time `json:"score_date"`
}

type Client struct {
	scores         map[string]*Score
	updateInterval time.Duration
	mu             sync.RWMutex

	DataUrl     string
	LastUpdated time.Time
	HttpClient  *http.Client
	Metadata    *Metadata
}

type ClientOption func(*Client)

// WithDataURL sets the data URL for the client.
func WithDataURL(dataURL string) ClientOption {
	return func(c *Client) {
		c.DataUrl = dataURL
	}
}

// WithHTTPClient sets the HTTP client for the client.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.HttpClient = httpClient
	}
}

// NewClient creates a new EPSS client with the given options.
func NewClient(options ...ClientOption) *Client {
	client := &Client{
		updateInterval: 24 * time.Hour,
		DataUrl:        "https://epss.cyentia.com/epss_scores-current.csv.gz",
		HttpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		scores:   make(map[string]*Score),
		Metadata: &Metadata{},
	}

	for _, option := range options {
		option(client)
	}

	return client
}

func (epssClient *Client) updateScores() error {
	if epssClient.LastUpdated.Format("2006-01-02") == time.Now().Format("2006-01-02") {
		return nil
	}

	req, err := http.NewRequest("GET", epssClient.DataUrl, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := epssClient.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}

	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	gz, err := gzip.NewReader(io.NopCloser(bytes.NewBuffer(data)))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gz.Close()

	// Use buffered reader for better performance
	bufferedReader := bufio.NewReader(gz)

	// Read and parse metadata line
	metadataLine, err := bufferedReader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read metadata line: %w", err)
	}

	if err := epssClient.parseMetadata(metadataLine); err != nil {
		return fmt.Errorf("failed to parse metadata: %w", err)
	}

	csvReader := csv.NewReader(bufferedReader)
	csvReader.Comment = '#'

	// Read header to validate CSV structure
	header, err := csvReader.Read()
	if err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}
	if len(header) != 3 || header[0] != "cve" || header[1] != "epss" || header[2] != "percentile" {
		return fmt.Errorf("invalid CSV header format: expected [cve,epss,percentile], got %v", header)
	}

	// Count remaining lines for capacity allocation
	data, err = io.ReadAll(bufferedReader)
	if err != nil {
		return fmt.Errorf("failed to read CSV data: %w", err)
	}
	lineCount := bytes.Count(data, []byte{'\n'})

	// Lock the mutex for the entire update operation
	epssClient.mu.Lock()
	newScores := make(map[string]*Score, lineCount)

	// Create new reader from the remaining data
	csvReader = csv.NewReader(bytes.NewReader(data))
	var lineNum int
	for {
		lineNum++
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			epssClient.mu.Unlock()
			return fmt.Errorf("error reading CSV line %d: %w", lineNum, err)
		}

		// Validate record length
		if len(record) != 3 {
			epssClient.mu.Unlock()
			return fmt.Errorf("invalid number of fields at line %d: expected 3, got %d", lineNum, len(record))
		}

		// Validate CVE format (e.g., CVE-YYYY-NNNNN)
		if !strings.HasPrefix(record[0], "CVE-") {
			continue // Skip invalid CVE entries
		}

		// Parse EPSS score
		epssValue, err := strconv.ParseFloat(record[1], 32)
		if err != nil {
			continue // Skip invalid EPSS values
		}
		if epssValue < 0 || epssValue > 1 {
			continue // Skip out-of-range values
		}

		// Parse percentile
		percentileValue, err := strconv.ParseFloat(record[2], 32)
		if err != nil {
			continue // Skip invalid percentile values
		}
		if percentileValue < 0 || percentileValue > 1 {
			continue // Skip out-of-range values
		}

		newScores[record[0]] = &Score{
			CVE:        record[0],
			EPSS:       float32(epssValue),
			Percentile: float32(percentileValue),
		}
	}

	// Atomic update of the scores map
	epssClient.scores = newScores
	epssClient.LastUpdated = time.Now()
	epssClient.mu.Unlock()

	return nil
}

func (epssClient *Client) parseMetadata(line string) error {
	// Remove # prefix and trim spaces
	line = strings.TrimPrefix(line, "#")
	line = strings.TrimSpace(line)

	// Split by comma
	parts := strings.Split(line, ",")
	if len(parts) != 2 {
		return fmt.Errorf("invalid metadata format: expected 2 parts, got %d", len(parts))
	}

	// Parse each key-value pair
	for _, part := range parts {
		// Split on first occurrence of ":"
		idx := strings.Index(part, ":")
		if idx == -1 {
			continue
		}
		key := strings.TrimSpace(part[:idx])
		value := strings.TrimSpace(part[idx+1:])

		switch key {
		case "model_version":
			epssClient.Metadata.ModelVersion = value
		case "score_date":
			scoreDate, err := time.Parse("2006-01-02T15:04:05+0000", value)
			if err != nil {
				return fmt.Errorf("invalid score date format: %w", err)
			}
			epssClient.Metadata.ScoreDate = scoreDate
		}
	}

	if epssClient.Metadata.ModelVersion == "" {
		return fmt.Errorf("model version not found in metadata")
	}

	if epssClient.Metadata.ScoreDate.IsZero() {
		return fmt.Errorf("score date not found in metadata")
	}

	return nil
}

// GetAllScores returns all the scores.
func (epssClient *Client) GetAllScores() ([]*Score, error) {
	if err := epssClient.updateScores(); err != nil {
		return nil, fmt.Errorf("failed to update scores: %w", err)
	}

	scores := make([]*Score, 0, len(epssClient.scores))
	for _, score := range epssClient.scores {
		scores = append(scores, score)
	}

	return scores, nil
}

// GetScore returns the score for the given CVE.
func (epssClient *Client) GetScore(cve string) (*Score, error) {
	if !strings.HasPrefix(cve, "CVE-") {
		return nil, fmt.Errorf("invalid CVE format: %s", cve)
	}

	if err := epssClient.updateScores(); err != nil {
		return nil, fmt.Errorf("failed to update scores: %w", err)
	}

	score, exists := epssClient.scores[cve]
	if !exists {
		return nil, fmt.Errorf("score not found for CVE: %s", cve)
	}

	return score, nil
}
