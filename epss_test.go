package epss_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/KaanSK/go-epss"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type HTTPClient interface {
	Get(url string) (*http.Response, error)
}

type MockHTTPClient struct {
	mock.Mock
}

func (m *MockHTTPClient) Get(url string) (*http.Response, error) {
	args := m.Called(url)
	return args.Get(0).(*http.Response), args.Error(1)
}

type EpssTestSuite struct {
	suite.Suite
	EPSSClient *epss.Client
}

func (suite *EpssTestSuite) SetupSuite() {
	suite.EPSSClient = epss.NewClient()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	defer gz.Close()

	data := `#model_version:v2023.03.01,score_date:2024-02-22T00:00:00+0000
	cve,epss,percentile
	CVE-1999-0001,0.00383,0.72361
	CVE-1999-0002,0.02091,0.88751`
	data = strings.ReplaceAll(data, "\t", "")
	if _, err := gz.Write([]byte(data)); err != nil {
		suite.FailNow(err.Error())
	}

	mockClient := new(MockHTTPClient)
	responseBody := io.NopCloser(&buf)
	mockClient.On("Get", "https://epss.cyentia.com/epss_scores-current.csv.gz").Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       responseBody},
		nil)

	suite.EPSSClient.SetHttpClient(mockClient)

}
func TestAlertTestSuite(t *testing.T) {
	suite.Run(t, new(EpssTestSuite))
}

func (suite *EpssTestSuite) TestGetAllScores() {
	scores, _ := suite.EPSSClient.GetAllScores()
	suite.Greater(len(scores), 0)
}

func (suite *EpssTestSuite) TestGetScore() {
	score, err := suite.EPSSClient.GetScore("CVE-1999-0002")
	if err != nil {
		suite.FailNow(err.Error())
	}
	suite.Equal("CVE-1999-0002", score.CVE)
	suite.Equal(float32(0.02091), score.EPSS)
	suite.Equal(float32(0.88751), score.Percentile)
}

func (suite *EpssTestSuite) TestTriggerUpdate() {
	epssClient := epss.NewClient()
	epssClient.SetUpdateInterval(0)
	lastUpdated := epssClient.GetLastUpdated()
	epssClient.GetAllScores()
	suite.NotEqual(epssClient.GetLastUpdated(), lastUpdated)
}
