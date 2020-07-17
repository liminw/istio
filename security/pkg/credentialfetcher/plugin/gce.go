// Copyright Istio Authors
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
package plugin

import (
	"fmt"
	"io/ioutil"

	"cloud.google.com/go/compute/metadata"

	"istio.io/pkg/log"
)

const (
	GCE = "gce"
)

// The plugin object.
type GCEPlugin struct {
	// Log scope
	credlog *log.Scope

	// aud is the unique URI agreed upon by both the instance and the system verifying the instance's identity.
	// For more info: https://cloud.google.com/compute/docs/instances/verifying-instance-identity
	aud string

	// The location to save the identity token
	jwtPath string
}

// CreateGCEPlugin creates a Google credential fetcher plugin. Return the pointer to the created plugin.
func CreateGCEPlugin(scope *log.Scope, audience, jwtPath string) *GCEPlugin {
	p := &GCEPlugin{
		credlog: scope,
		aud:     audience,
		jwtPath: jwtPath,
	}
	return p
}

// GetPlatformCredential fetches the GCE VM identity jwt token from its metadata server,
// and write it to jwtPath.
// Note: this function only works in a GCE VM environment.
func (p *GCEPlugin) GetPlatformCredential() (string, error) {
	if p.jwtPath == "" {
		return "", fmt.Errorf("jwtPath is unset")
	}
	uri := fmt.Sprintf("instance/service-accounts/default/identity?audience=%s&format=full", p.aud)
	token, err := metadata.Get(uri)
	if err != nil {
		p.credlog.Errorf("Failed to get vm identity token from metadata server: %v", err)
		return "", err
	}
	p.credlog.Debugf("Got GCE identity token: %d", len(token))
	tokenbytes := []byte(token)
	err = ioutil.WriteFile(p.jwtPath, tokenbytes, 0666)
	if err != nil {
		p.credlog.Errorf("Encountered error when writing vm identity token: %v", err)
		return "", err
	}
	return token, nil
}

// GetPlatform returns the platform type.
func (p *GCEPlugin) GetPlatform() string {
	return GCE
}
