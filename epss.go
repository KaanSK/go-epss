package epss

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	defaultUpdateInterval = 24 * time.Hour
	epssDataURL           = "https://epss.cyentia.com/epss_scores-current.csv.gz"
)

type HttpClient interface {
	Get(url string) (*http.Response, error)
}

type Score struct {
	CVE        string
	EPSS       float32
	Percentile float32
}

type Client struct {
	scores         map[string]*Score
	lastUpdated    time.Time
	updateInterval time.Duration
	mu             sync.RWMutex
	httpClient     HttpClient
	dataURL        string
}

var sharedHttpClient = &http.Client{
	Timeout: 10 * time.Second,
}

type ClientOption func(*Client)

// WithUpdateInterval sets the update interval for the client.
func WithUpdateInterval(updateInterval time.Duration) ClientOption {
	return func(c *Client) {
		if updateInterval < 0 {
			updateInterval = defaultUpdateInterval
		}
		c.updateInterval = updateInterval
	}
}

// WithDataURL sets the data URL for the client.
func WithDataURL(dataURL string) ClientOption {
	return func(c *Client) {
		c.dataURL = dataURL
	}
}

// WithHTTPClient sets the HTTP client for the client.
func WithHTTPClient(httpClient HttpClient) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// NewClient creates a new EPSS client with the given options.
func NewClient(options ...ClientOption) *Client {
	client := &Client{
		updateInterval: defaultUpdateInterval,
		dataURL:        epssDataURL,
		httpClient:     sharedHttpClient,
		scores:         make(map[string]*Score),
	}

	for _, option := range options {
		option(client)
	}

	client.updateScores()
	return client
}

// GetLastUpdated returns the last updated time of the scores.
func (c *Client) GetLastUpdated() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastUpdated
}

// GetUpdateInterval returns the update interval of the scores.
func (c *Client) GetUpdateInterval() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.updateInterval
}

// updateScores updates the scores from the data source.
func (c *Client) updateScores() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.httpClient.Get(c.dataURL)
	if err != nil || resp.StatusCode != http.StatusOK || resp.Body == nil {
		return fmt.Errorf("failed to download EPSS scores: %w", err)
	}
	defer resp.Body.Close()

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gz.Close()

	scores := make(map[string]*Score)

	csvReader := csv.NewReader(gz)
	csvReader.Comment = '#'

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading EPSS CSV: %w", err)
		}
		if len(record) != 3 {
			return fmt.Errorf("number of fields do not match expected number")
		}

		epssValue, err := convertToFloat32(record[1])
		if err != nil {
			continue
		}
		percentileValue, err := convertToFloat32(record[2])
		if err != nil {
			continue
		}

		scores[record[0]] = &Score{
			CVE:        record[0],
			EPSS:       epssValue,
			Percentile: percentileValue,
		}
	}

	c.scores = scores
	c.lastUpdated = time.Now()
	return nil
}

// needsUpdate returns whether the scores need to be updated
func (c *Client) needsUpdate() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Since(c.lastUpdated) >= c.updateInterval
}

// GetAllScores returns all the scores.
func (c *Client) GetAllScores() ([]*Score, error) {
	if c.needsUpdate() {
		if err := c.updateScores(); err != nil {
			return nil, err
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	scores := make([]*Score, 0, len(c.scores))
	for _, score := range c.scores {
		scores = append(scores, score)
	}

	return scores, nil
}

// GetScore returns the score for the given CVE.
func (c *Client) GetScore(cve string) (*Score, error) {
	if c.needsUpdate() {
		if err := c.updateScores(); err != nil {
			return nil, err
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	score, ok := c.scores[cve]
	if !ok {
		return nil, fmt.Errorf("Score not found for CVE: %s", cve)
	}

	return score, nil
}

// convertToFloat32 converts a string to a float32 value.
func convertToFloat32(value string) (float32, error) {
	parsedValue, err := strconv.ParseFloat(value, 32)
	if err != nil {
		return 0, err
	}
	return float32(parsedValue), nil
}
