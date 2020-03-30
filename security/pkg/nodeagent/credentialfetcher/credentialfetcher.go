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

// credentailfetcher fetches workload credentials through platform plugins.
package credentialfetcher

import (
  "bytes"
	"crypto/tls"
	"crypto/x509"
  "encoding/base64"
  "encoding/json"
  "fmt"
  "io/ioutil"
  "net/http"
  "strings"
  "time"

	"istio.io/pkg/log"
	"istio.io/istio/security/pkg/nodeagent/credentialfetcher/google"
)

const (
// Platform type: GoogleComputeEngine
  GoogleComputeEngine = "GoogleComputeEngine"

  apiServerCertPath = "/etc/certs/k8srootca.pem"

	httpTimeOutInSec = 5
)

var (
	credentialLog = log.RegisterScope("credential", "Credential fetcher for SDS agent", 0)

	tokenRequestEndpoint = "https://%s/api/v1/namespaces/%s/serviceaccounts/%s/token"
)

type CredentailFetcher interface {
  // Get k8s credential for the workload.
  Getk8sJwt(string) (string, error)

  // Fetch workload credential provided by the platform.
  FetchNativeCredential() (string, error)
}

// Platform specific plugin
type Plugin interface {
  // Fetch workload credential.
  FetchCredential() (string, error)
}

type CredFetcher struct {
  httpClient *http.Client

  // Platform specific plugin to fetch workload credential
  plugin Plugin

  // k8s JWT file path
  jwtPath string

  // trust domain
  trustdomain string

  // k8s namespace of the workload
  k8sns string

  // k8s service account of the workload
  k8ssa string

  // IP of k8s API server
  apiserverip string
}

func NewCredFetcher(platform, jwtPath, trustdomain, k8sns, k8ssa, apiserverip string) (*CredFetcher, error) {
  cf := &CredFetcher{
    httpClient: nil,
    plugin: nil,
    jwtPath: jwtPath,
    trustdomain: trustdomain,
    k8sns: k8sns,
    k8ssa: k8ssa,
    apiserverip: apiserverip,
  }

	switch platform {
	case GoogleComputeEngine:
	  if p, err := google.CreatePlugin(); err == nil {
	    cf.plugin = p
	  }
	}

  if apiServerCertPath == "" {
    credentialLog.Infof("apiServerCertPath is empty")
    return cf, nil
  }

  apiServerCert, err := ioutil.ReadFile(apiServerCertPath)
  if err != nil {
    return cf, fmt.Errorf("failed to read apiServerCertPath: %v", err)
  }

  if apiServerCert != nil {
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(apiServerCert)

    cf.httpClient = &http.Client{
			Timeout: httpTimeOutInSec * time.Second,
      Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
          RootCAs: caCertPool,
        },
      },
    }
  }

  return cf, nil
}

func (cred *CredFetcher) Getk8sJwt() (string, error) {
		tok, err := ioutil.ReadFile(cred.jwtPath)
		if err == nil {
		  token := string(tok)
		  if (token != "" && validToken(token)) {
		    credentialLog.Infof("Found JWT: %s", token)
		    return token, nil
		  }
		}

	  credentialLog.Infof("k8s JWT file does not exist or JWT expired: %v", err)
	  nativeToken, err := cred.plugin.FetchCredential()
	  if err != nil {
	     credentialLog.Errorf("failed to fetch native token: %v", err)
	     return "", err
	  }
	  k8sToken := cred.requestk8sToken(nativeToken)
	  if k8sToken == "" {
	     return "", fmt.Errorf("failed to fetch k8s token")
	  }
    return k8sToken, nil
}

type tokenRequestSpec struct {
  Audiences []string `json:"audiences"`
}

type tokenRequestBody struct {
  Kind        string `json:"kind"`
  ApiVersion  string `json:"apiVersion"`
  Spec        tokenRequestSpec `json:"spec"`
}

type tokenRequestResponseStatus struct {
  Token      string `json:"token"`
}

type tokenRequestResponse struct {
  Status tokenRequestResponseStatus `json:"status"`
}

//
// curl -H "Content-Type: application/json" -XPOST
// https://${APISERVERIP}/api/v1/namespaces/${k8s_namespace}/serviceaccounts/${k8s_serviceaccount}/token -d
// '{"kind":"TokenRequest","apiVersion":"authentication.k8s.io/v1","spec":{"audiences":["${IDNS}"]}}'
// -H 'Authorization: Bearer ${NATIVE_TOKEN}'
//
// Response:
// {
//   "kind": "TokenRequest",
//   "apiVersion": "authentication.k8s.io/v1",
//   "metadata": {
//     "selfLink": "/api/v1/namespaces/default/serviceaccounts/default/token",
//     "creationTimestamp": null
//   },
//   "spec": {
//     "audiences": [
//       ""$IDNS"
//     ],
//     "expirationSeconds": 3600,
//     "boundObjectRef": null
//   },
//   "status": {
//     "token": $Token
//     "expirationTimestamp": "2020-03-26T23:04:51Z"
//   }
// }
func (cred *CredFetcher) constructk8sTokenRequest(nativeToken string) *http.Request {
  if nativeToken == "" {
    credentialLog.Errorf("nativeToken is empty")
    return nil
  }

	body := tokenRequestBody{
	   Kind: "TokenRequest",
	   ApiVersion: "authentication.k8s.io/v1",
	   Spec: tokenRequestSpec{
	     Audiences: []string{ cred.trustdomain },
	   },
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
	  credentialLog.Errorf("failed to marshal body for tokenrequest: %+v", err)
	  return nil
	}
	endpoint := fmt.Sprintf(tokenRequestEndpoint, cred.apiserverip, cred.k8sns, cred.k8ssa)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
	  credentialLog.Errorf("failed to create tokenrequest: %+v", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+ nativeToken)
  return req
}

// requestk8sToken exchanges local credential for a k8s service account token.
func (cred *CredFetcher) requestk8sToken(nativeToken string) (k8sToken string) {
	req := cred.constructk8sTokenRequest(nativeToken)
	if req == nil {
    credentialLog.Errorf("empty token request")
		return ""
	}

	resp, err := cred.httpClient.Do(req)
	if err != nil {
	  credentialLog.Errorf("Token request error: %v", err)
	  return ""
	}
  defer resp.Body.Close()

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    credentialLog.Errorf("failed to read from tokenrequest response: %v", err)
    return ""
  }
	respData := &tokenRequestResponse{}
	if err := json.Unmarshal(body, respData); err != nil {
    credentialLog.Errorf("failed to unmarshal tokenrequest response: %v", err)
    return ""
  }

  token := respData.Status.Token
  credentialLog.Infof("fetched k8s token %s", token)
  if err := ioutil.WriteFile(cred.jwtPath, []byte(token), 0777); err != nil {
    credentialLog.Errorf("failed to write k8s token to file: %v", err)
  }
  return token
}

func validToken(jwt string) bool {
  type payload struct {
    Exp string `json:"exp"`
  }

  jwtSplit := strings.Split(jwt, ".")
	if len(jwtSplit) != 3 {
		credentialLog.Errorf("jwt is invalid: %s", jwt)
		return false
	}
	payloadData := jwtSplit[1]

	payloadBytes, err := base64.RawStdEncoding.DecodeString(payloadData)
	if err != nil {
		credentialLog.Errorf("failed to decode jwt: %v", err)
		return false
	}

	structuredPayload := &payload{}
	err = json.Unmarshal(payloadBytes, &structuredPayload)
	if err != nil {
		credentialLog.Errorf("failed to unmarshal jwt: %v", err)
		return false
	}

  expTime, err := time.Parse(time.RFC3339, structuredPayload.Exp)
  if err != nil {
    credentialLog.Errorf("failed to parse the time: %v", err)
    return false
  }
  return time.Now().Before(expTime)
}

func (cred *CredFetcher) FetchNativeCredential() (string, error) {
  return cred.plugin.FetchCredential()
}