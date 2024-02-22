<h1><p align="center">Go-EPSS</p></h1>
<p align="center">
  <img src="https://goreportcard.com/badge/github.com/KaanSK/go-epss" />
</p>
<p align="center">
 A Golang library for interacting with the EPSS (Exploit Prediction Scoring System).
</p>

# Key Features
* Fetch latest EPSS data directly from source;
* Access individual CVE scores;
* Manage update intervals to ensure fresh data;
* Leverages Golang's concurrency features for efficient performance.

# Getting Started
1. Install `Go-EPSS` package:
    ```bash
    go get github.com/KaanSK/go-epss
    ```
2. Import the package and create a client:
    ```go
    import (
        "github.com/KaanSK/go-epss"
    )

    client := epss.NewClient()
    ...
    ```
# Getting All Score List
Use the client to retrieve scores:
```go
    scores, err := client.GetAllScores()
    if err != nil {
        // Handle error
    }

    for _, score := range scores {
        fmt.Printf("CVE: %s, EPSS: %.4f, Percentile: %.4f\n", score.CVE, score.EPSS, score.Percentile)
    }
    ...
```

# Getting Individual Score for CVE ID
Use the client to retrieve individual CVE score:
```go
    score, err := client.GetScore("CVE-1999-0002")
    if err != nil {
        // Handle error
    }

    fmt.Printf("CVE: %s, EPSS: %.4f, Percentile: %.4f\n", score.CVE, score.EPSS, score.Percentile)
    ...
```

# Injecting Custom `http.Client` for Data Fetching
Use the client `SetHttpClient` method to inject custom `http.Client`:
```go
    import (
        "github.com/your-package/epss"
    )

    client := epss.NewClient()
    client.SetHttpClient(&http.Client{
		Timeout: 10 * time.Second,
	})
    ...
```

# Setting Custom Update Interval
Use the client `SetUpdateInterval` method to set new UpdateInterval (default is 24 hours):
```go
    import (
        "github.com/your-package/epss"
    )

    client := epss.NewClient()
    client.SetUpdateInterval(30 * time.Second)
    ...
```