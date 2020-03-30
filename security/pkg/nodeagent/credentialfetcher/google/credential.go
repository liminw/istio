// Copyright 2020 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This is Google plugin of credentialfetcher.
package google

import (
	"crypto/tls"
	"crypto/x509"
  "encoding/json"
  "fmt"
  "io/ioutil"
  "net/http"
  "time"

	"istio.io/pkg/log"
)

const (
  metadataServerEndpoint = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

	httpTimeOutInSec = 5
)

var (
	googleCredlLog = log.RegisterScope("googleCred", "Google plugin for credential fetcher", 0)
)

func CreatePlugin() (*Plugin, error) {
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		googleCredlLog.Errorf("Failed to get SystemCertPool: %v", err)
		return nil, err
	}
	p := &Plugin{
		httpClient: &http.Client{
			Timeout: httpTimeOutInSec * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
		},
  }
  return p, nil
}

type Plugin struct {
	httpClient  *http.Client
}

type credentialResponse struct {
  AccessToken string `json:"access_token"`
}

// curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"
// { "access_token":$TOKEN,"expires_in":3599,"token_type":"Bearer"}
func (p *Plugin) FetchCredential() (string, error) {
	req, err := http.NewRequest("POST", metadataServerEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create fetch native credential request: %+v", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

  resp, err := p.httpClient.Do(req)
  if err != nil {
		return "", fmt.Errorf("failed to request native credential: %+v", err)
  }
  defer resp.Body.Close()

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    return "", fmt.Errorf("failed to read from credential response: %v", err)
  }
	respData := &credentialResponse{}
	if err := json.Unmarshal(body, respData); err != nil {
    return "", fmt.Errorf("failed to unmarshal credential response: %v", err)
  }

  token := respData.AccessToken
  googleCredlLog.Infof("fetched native credential: %s", token)
  return token, nil
}