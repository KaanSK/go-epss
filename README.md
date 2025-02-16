<h1><p align="center">Go-EPSS</p></h1>
<p align="center">
  <img src="https://goreportcard.com/badge/github.com/KaanSK/go-epss" />
</p>
<p align="center">
A Golang library for interacting with the EPSS (Exploit Prediction Scoring System).
</p>

# Data Set
EPSS (Exploit Prediction Scoring System) is a framework used to assess the likelihood of a vulnerability being exploited. [FIRST](https://www.first.org/) organization regularly updates and publishes this data through their [website](https://www.first.org/epss/data_stats).

# Key Features
* Fetch latest EPSS data directly from source
* Local EPSS querying interface instead of [FIRST remote API](https://www.first.org/epss/api)
* Access individual CVE scores
* Access EPSS metadata (model version and score date)
* Efficient in-memory caching to minimize API requests
* Leverages Golang's concurrency features for efficient performance
* Custom `*http.Client` can be injected

# Getting Started
1. Install `Go-EPSS` package:
    ```bash
    go get github.com/KaanSK/go-epss
    ```
2. Import the package and create a client with default values:
    ```go
    import (
        "github.com/KaanSK/go-epss"
    )

    client := epss.NewClient()
    ```

## Providing Client Options and Custom `*http.Client`
```go
import (
    "github.com/KaanSK/go-epss"
)

client := epss.NewClient(
    epss.WithHTTPClient(&http.Client{Timeout: 10 * time.Second}),
    epss.WithDataURL("test.com"),
)
```

## Caching Behavior
The library implements efficient in-memory caching to minimize API requests:

- Data is cached in memory with thread-safe access
- Cache is automatically validated based on the daily update interval
- Cached data is used when available and valid, reducing API load
- Cache is automatically refreshed when expired
- No disk I/O overhead, ideal for high-performance applications

## Getting All Score List
Use the client to retrieve scores (uses cache when available):
```go
scores, err := client.GetAllScores()
if err != nil {
    // Handle error
}

for _, score := range scores {
    fmt.Printf("CVE: %s, EPSS: %.4f, Percentile: %.4f\n", score.CVE, score.EPSS, score.Percentile)
}
```

## Getting Individual Score for CVE ID
Use the client to retrieve individual CVE score (uses cache when available):
```go
score, err := client.GetScore("CVE-1999-0002")
if err != nil {
    // Handle error
}

fmt.Printf("CVE: %s, EPSS: %.4f, Percentile: %.4f\n", score.CVE, score.EPSS, score.Percentile)
```

## Accessing EPSS Metadata
The client provides access to EPSS metadata including model version and score date:
```go
fmt.Printf("Model Version: %s\n", client.Metadata.ModelVersion)
fmt.Printf("Score Date: %s\n", client.Metadata.ScoreDate.Format(time.RFC3339))
```

# Testing
To run tests:
```bash
go test -v
```

# Disclaimer
* EPSS data retrieved from [FIRST organization](https://www.first.org/epss/data_stats). As of the project's publishing date, data is [open-sourced and available for individual projects](https://www.first.org/epss/faq#:~:text=Can%20I%20use%20this%20in%20my%20commercial%20product%3F%20What%20Licensing%20limitations%20exist%3F).
* Software uses caching for optimal usage of API requests. Be mindful of not overloading the API with concurrent requests.
* The project is still under development and may contain bugs. Please report any issues to the [GitHub repository](https://github.com/KaanSK/go-epss/issues).