package epss_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/KaanSK/go-epss"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

const (
	epssDataURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
)

type HttpClient interface {
	Get(url string) (*http.Response, error)
}

type MockHTTPClient struct {
	mock.Mock
}

func (m *MockHTTPClient) Get(url string) (*http.Response, error) {
	args := m.Called(url)
	return args.Get(0).(*http.Response), args.Error(1)
}

type ClientTestSuite struct {
	suite.Suite
	EPSSClient     *epss.Client
	MockHttpClient HttpClient
	EPSSDataURL    string
}

func (suite *ClientTestSuite) SetupTest() {
	suite.EPSSDataURL = epssDataURL

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	data := `#model_version:v2023.03.01,score_date:2024-02-22T00:00:00+0000
	cve,epss,percentile
	CVE-1999-0001,0.00383,0.72361
	CVE-1999-0002,0.02091,0.88751`
	data = strings.ReplaceAll(data, "\t", "")

	if _, err := gz.Write([]byte(data)); err != nil {
		suite.FailNow(err.Error())
	}

	gz.Close()

	responseBody := io.NopCloser(bytes.NewReader(buf.Bytes()))

	mockClient := new(MockHTTPClient)
	mockClient.On("Get", suite.EPSSDataURL).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       responseBody},
		nil)

	suite.MockHttpClient = mockClient
	suite.EPSSClient = epss.NewClient(epss.WithHTTPClient(suite.MockHttpClient))
}

func TestClientTestSuite(t *testing.T) {
	suite.Run(t, new(ClientTestSuite))
}

func (suite *ClientTestSuite) TestGetAllScores() {
	scores, err := suite.EPSSClient.GetAllScores()
	suite.NoError(err)
	suite.Len(scores, 2)
}

func (suite *ClientTestSuite) TestGetScore() {
	score, err := suite.EPSSClient.GetScore("CVE-1999-0001")
	suite.NoError(err)
	suite.Equal("CVE-1999-0001", score.CVE)
	suite.Equal(float32(0.00383), score.EPSS)
	suite.Equal(float32(0.72361), score.Percentile)
}

func (suite *ClientTestSuite) TestGetScoreNotFound() {
	_, err := suite.EPSSClient.GetScore("CVE-1999-0003")
	suite.Error(err)
}

func (suite *ClientTestSuite) TestGetScoreInvalidCVE() {
	_, err := suite.EPSSClient.GetScore("invalid-cve")
	suite.Error(err)
}

func (suite *ClientTestSuite) TestGetScoreInvalidEPSS() {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	data := `#model_version:v2023.03.01,score_date:2024-02-22T00:00:00+0000
	cve,epss,percentile
	CVE-1999-0001,invalid-epss,0.72361
	CVE-1999-0002,0.02091,0.88751`
	data = strings.ReplaceAll(data, "\t", "")

	if _, err := gz.Write([]byte(data)); err != nil {
		suite.FailNow(err.Error())
	}

	gz.Close()

	responseBody := io.NopCloser(bytes.NewReader(buf.Bytes()))

	mockClient := new(MockHTTPClient)
	mockClient.On("Get", suite.EPSSDataURL).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       responseBody},
		nil)

	epssClient := epss.NewClient(epss.WithHTTPClient(suite.MockHttpClient))

	_, err := epssClient.GetScore("CVE-1999-0001")
	suite.Error(err)
}

func (suite *ClientTestSuite) TestGetScoreInvalidPercentile() {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	data := `#model_version:v2023.03.01,score_date:2024-02-22T00:00:00+0000
	cve,epss,percentile
	CVE-1999-0001,0.00383,invalid-percentile
	CVE-1999-0002,0.02091,0.88751`
	data = strings.ReplaceAll(data, "\t", "")

	if _, err := gz.Write([]byte(data)); err != nil {
		suite.FailNow(err.Error())
	}

	gz.Close()

	responseBody := io.NopCloser(bytes.NewReader(buf.Bytes()))

	mockClient := new(MockHTTPClient)
	mockClient.On("Get", suite.EPSSDataURL).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       responseBody},
		nil)

	epssClient := epss.NewClient(epss.WithHTTPClient(suite.MockHttpClient))

	_, err := epssClient.GetScore("CVE-1999-0001")
	suite.Error(err)
}

func (suite *ClientTestSuite) TestGetScoreInvalidCSV() {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	data := `#model_version:v2023.03.01,score_date:2024-02-22T00:00:00+0000
	cve,epss,percentile
	CVE-1999-0001,0.00383,0.72361
	CVE-1999-0002,0.02091`
	data = strings.ReplaceAll(data, "\t", "")

	if _, err := gz.Write([]byte(data)); err != nil {
		suite.FailNow(err.Error())
	}

	gz.Close()

	responseBody := io.NopCloser(bytes.NewReader(buf.Bytes()))

	mockClient := new(MockHTTPClient)
	mockClient.On("Get", suite.EPSSDataURL).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       responseBody},
		nil)

	epssClient := epss.NewClient(epss.WithHTTPClient(suite.MockHttpClient))

	_, err := epssClient.GetScore("CVE-1999-0001")
	suite.Error(err)
}

func (suite *ClientTestSuite) TestGetScoreInvalidCSVFields() {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	data := `#model_version:v2023.03.01,score_date:2024-02-22T00:00:00+0000
	cve,epss,percentile
	CVE-1999-0001,0.00383,0.72361,extra-field
	CVE-1999-0002,0.02091,0.88751`
	data = strings.ReplaceAll(data, "\t", "")

	if _, err := gz.Write([]byte(data)); err != nil {
		suite.FailNow(err.Error())
	}

	gz.Close()

	responseBody := io.NopCloser(bytes.NewReader(buf.Bytes()))

	mockClient := new(MockHTTPClient)
	mockClient.On("Get", suite.EPSSDataURL).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       responseBody},
		nil)

	epssClient := epss.NewClient(epss.WithHTTPClient(suite.MockHttpClient))

	_, err := epssClient.GetScore("CVE-1999-0001")
	suite.Error(err)
}

func (suite *ClientTestSuite) TestGetScoreInvalidCSVFieldsCount() {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	data := `#model_version:v2023.03.01,score_date:2024-02-22T00:00:00+0000
	cve,epss,percentile
	CVE-1999-0001,0.00383
	CVE-1999-0002,0.02091,0.88751`
	data = strings.ReplaceAll(data, "\t", "")

	if _, err := gz.Write([]byte(data)); err != nil {
		suite.FailNow(err.Error())
	}

	gz.Close()

	responseBody := io.NopCloser(bytes.NewReader(buf.Bytes()))

	mockClient := new(MockHTTPClient)
	mockClient.On("Get", suite.EPSSDataURL).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       responseBody},
		nil)

	epssClient := epss.NewClient(epss.WithHTTPClient(suite.MockHttpClient))

	_, err := epssClient.GetScore("CVE-1999-0001")
	suite.Error(err)
}

func (suite *ClientTestSuite) TestGetScoreInvalidCSVFieldsCountZero() {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	data := `#model_version:v2023.03.01,score_date:2024-02-22T00:00:00+0000
	cve,epss,percentile
	CVE-1999-0001,0.00383
	CVE-1999-0002`
	data = strings.ReplaceAll(data, "\t", "")

	if _, err := gz.Write([]byte(data)); err != nil {
		suite.FailNow(err.Error())
	}

	gz.Close()

	responseBody := io.NopCloser(bytes.NewReader(buf.Bytes()))

	mockClient := new(MockHTTPClient)
	mockClient.On("Get", suite.EPSSDataURL).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       responseBody},
		nil)

	epssClient := epss.NewClient(epss.WithHTTPClient(suite.MockHttpClient))

	_, err := epssClient.GetScore("CVE-1999-0001")
	suite.Error(err)
}

func (suite *ClientTestSuite) TestGetScoreInvalidCSVFieldsCountMoreThanThree() {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	data := `#model_version:v2023.03.01,score_date:2024-02-22T00:00:00+0000
	cve,epss,percentile
	CVE-1999-0001,0.00383,0.72361,extra-field,extra-field
	CVE-1999-0002,0.02091,0.88751`
	data = strings.ReplaceAll(data, "\t", "")

	if _, err := gz.Write([]byte(data)); err != nil {
		suite.FailNow(err.Error())
	}

	gz.Close()

	responseBody := io.NopCloser(bytes.NewReader(buf.Bytes()))

	mockClient := new(MockHTTPClient)
	mockClient.On("Get", suite.EPSSDataURL).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       responseBody},
		nil)

	epssClient := epss.NewClient(epss.WithHTTPClient(suite.MockHttpClient))

	_, err := epssClient.GetScore("CVE-1999-0001")
	suite.Error(err)
}

func (suite *ClientTestSuite) TestGetAllScoresError() {
	mockClient := new(MockHTTPClient)
	mockClient.On("Get", suite.EPSSDataURL).Return(&http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       nil},
		nil)

	epssClient := epss.NewClient(epss.WithHTTPClient(mockClient))

	_, err := epssClient.GetAllScores()
	suite.Error(err)
}

func (suite *ClientTestSuite) TestGetScoreError() {
	mockClient := new(MockHTTPClient)
	mockClient.On("Get", suite.EPSSDataURL).Return(&http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       nil},
		nil)

	epssClient := epss.NewClient(epss.WithHTTPClient(mockClient))

	_, err := epssClient.GetScore("CVE-1999-0001")
	suite.Error(err)
}

func (suite *ClientTestSuite) TestLastUpdated() {
	suite.EPSSClient.GetAllScores()
	suite.NotEqual(int64(0), suite.EPSSClient.GetLastUpdated().Unix())
	suite.True(time.Now().After(suite.EPSSClient.GetLastUpdated()))
}

// Benchmarking
type ClientBenchmarkSuite struct {
	suite.Suite
	EPSSClient     *epss.Client
	MockHttpClient HttpClient
	EPSSDataURL    string
}

func (suite *ClientBenchmarkSuite) SetupTest() {
	suite.EPSSDataURL = epssDataURL
	suite.EPSSClient = epss.NewClient()
}

func TestClientBenchmarkSuite(t *testing.T) {
	suite.Run(t, new(ClientBenchmarkSuite))
}

func (suite *ClientBenchmarkSuite) TestGetScore() {
	suite.EPSSClient.GetScore("CVE-2010-0001")
}

func BenchmarkGetScore(b *testing.B) {
	suite := new(ClientBenchmarkSuite)
	suite.SetupTest()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.TestGetScore()
	}
}

func BenchmarkGetAllScores(b *testing.B) {
	suite := new(ClientBenchmarkSuite)
	suite.SetupTest()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.EPSSClient.GetAllScores()
	}
}

func BenchmarkGetScoreNotFound(b *testing.B) {
	suite := new(ClientBenchmarkSuite)
	suite.SetupTest()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.EPSSClient.GetScore("CVE-1999-0003")
	}
}

func BenchmarkGetScoreInvalidCVE(b *testing.B) {
	suite := new(ClientBenchmarkSuite)
	suite.SetupTest()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.EPSSClient.GetScore("invalid-cve")
	}
}

func BenchmarkGetScoreInvalidEPSS(b *testing.B) {
	suite := new(ClientBenchmarkSuite)
	suite.SetupTest()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.EPSSClient.GetScore("CVE-1999-0001")
	}
}

func BenchmarkGetScoreInvalidPercentile(b *testing.B) {
	suite := new(ClientBenchmarkSuite)
	suite.SetupTest()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		suite.EPSSClient.GetScore("CVE-1999-0001")
	}
}
