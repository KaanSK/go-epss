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

type EPSSError struct {
	message string
}

func (e *EPSSError) Error() string {
	return e.message
}

type HttpClient interface {
	Get(url string) (*http.Response, error)
}

type Score struct {
	CVE        string
	EPSS       float32
	Percentile float32
}

type Client struct {
	scores         []*Score
	lastUpdated    time.Time
	updateInterval time.Duration
	mu             sync.Mutex
	httpClient     HttpClient
	DataURL        string
}

// Initializes a new EPSS client
func NewClient() *Client {
	client := &Client{
		updateInterval: defaultUpdateInterval,
		DataURL:        epssDataURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	return client
}

// Used for getting last update time of client data
func (c *Client) GetLastUpdated() time.Time {
	return c.lastUpdated
}

// Sets user preferred HttpClient as EPSS HttpClient.
func (c *Client) SetHttpClient(httpClient HttpClient) {
	c.httpClient = httpClient
}

// Sets Data URL for fetching the scores. Default: "https://epss.cyentia.com/epss_scores-current.csv.gz"
func (c *Client) SetDataURL(url string) {
	c.DataURL = epssDataURL
}

// Sets update interval for updating EPSS scores.
func (c *Client) SetUpdateInterval(updateInterval time.Duration) {
	if updateInterval < 0 {
		updateInterval = defaultUpdateInterval
	}

	c.updateInterval = updateInterval
}

func (c *Client) updateScores() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := c.httpClient.Get(c.DataURL)
	if err != nil {
		return &EPSSError{message: fmt.Sprintf("Failed to download EPSS scores: %s", err)}
	}
	defer resp.Body.Close()

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return &EPSSError{message: fmt.Sprintf("Failed to download EPSS scores: %s", err)}
	}
	defer gz.Close()

	scores := make([]*Score, 0)

	csvReader := csv.NewReader(gz)
	csvReader.Comment = '#'

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &EPSSError{message: fmt.Sprintf("Error reading EPSS CSV: %s", err)}
		}
		if len(record) != 3 {
			return &EPSSError{message: fmt.Sprintf("Number of fields do not match expected number: %s", record)}
		}

		epssValue, err := convertToFloat32(record[1])
		if err != nil {
			continue
		}
		percentileValue, err := convertToFloat32(record[2])
		if err != nil {
			continue
		}

		scores = append(scores, &Score{
			CVE:        record[0],
			EPSS:       epssValue,
			Percentile: percentileValue,
		})
	}

	c.scores = scores
	c.lastUpdated = time.Now()

	return nil
}

func (c *Client) checkForUpdate() error {
	if time.Since(c.lastUpdated) > c.updateInterval {
		err := c.updateScores()
		if err != nil {
			return err
		}
	}
	return nil
}

// Returns all EPSS Scores.
func (c *Client) GetAllScores() ([]*Score, error) {
	err := c.checkForUpdate()
	if err != nil {
		return nil, &EPSSError{message: fmt.Sprintf("Failed to update EPSS scores: %s", err)}
	}

	return c.scores, nil
}

// Returns individual Score by CVE ID.
func (c *Client) GetScore(cve string) (*Score, error) {
	err := c.checkForUpdate()
	if err != nil {
		return nil, &EPSSError{message: fmt.Sprintf("Failed to update EPSS scores: %s", err)}
	}

	for _, score := range c.scores {
		if score.CVE == cve {
			return score, nil
		}
	}

	return &Score{}, nil
}

func convertToFloat32(value string) (float32, error) {
	parsedValue, err := strconv.ParseFloat(value, 32)
	if err != nil {
		return 0, err
	}
	return float32(parsedValue), nil
}
