// Copyright 2016-2017 Authors of Cilium
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

package api

import (
	"fmt"
	"regexp"
)

// MismatchAction specifies what to do when there is no header match
// Empty string is the default for making the rule to fail the match.
// Otherwise the rule is still considered as matching, but the mismatches
// are logged in the access log.
type MismatchAction string

const (
	MismatchActionLog     MismatchAction = "LOG"     // Keep checking other matches
	MismatchActionAdd     MismatchAction = "ADD"     // Add the missing value to a possibly multi-valued header
	MismatchActionDelete  MismatchAction = "DELETE"  // Remove the whole mismatching header
	MismatchActionReplace MismatchAction = "REPLACE" // Replace (of add if missing) the header
)

// HeaderMatch extends the HeaderValue for matching requirement of a
// named header field against an immediate string, a secret value, or
// a regex.  If none of the optional fields is present, then the
// header value is not matched, only presence of the header is enough.
type HeaderMatch struct {
	// Mismatch identifies what to do in case there is no match. The default is
	// to drop the request. Otherwise the overall rule is still considered as
	// matching, but the mismatches are logged in the access log.
	//
	// +kubebuilder:validation:Enum=LOG;ADD;DELETE;REPLACE
	// +kubebuilder:validation:Optional
	Mismatch MismatchAction `json:"mismatch,omitempty"`

	// Name identifies the header.
	Name string `json:"name"`

	// Secret refers to a secret that contains the value to be matched against.
	// The secret must only contain one entry. If the referred secret does not
	// exist, and there is no "Value" specified, the match will fail.
	//
	// +kubebuilder:validation:Optional
	Secret *Secret `json:"secret,omitempty"`

	// Value matches the exact value of the header. Can be specified either
	// alone or together with "Secret"; will be used as the header value if the
	// secret can not be found in the latter case.
	//
	// +kubebuilder:validation:Optional
	Value string `json:"value,omitempty"`
}

// when using a external identity provider envoy will need to fetch
// a json file from service provider server. For that reason an upstream
// cluster is necessary. The ProviderSrvc is used  to select the correct
// cluster configuration accondingly with the used provider.
type ProviderSrvc string

const (
	ProviderAuth0 ProviderSrvc = "AUTH0"
	ProviderGcp   ProviderSrvc = "GCP"
)

// cluster configurations to be used along with external identity providers.
// all supported services should have its own cluster configuration. In the
// future should be possible to use "Dynamic Forward Proxy" because today it's
// not working as expected (alpha version).
type JwksProviderCluster string

const (
	JwksProviderAuth0Cluster JwksProviderCluster = "Auth0_remote_jwks_fetching_cluster"
	JwksProviderGcpCluster   JwksProviderCluster = "Gcp_remote_jwks_fetching_cluster"
)

type MatchJWT struct {
	// Fields is a list of jwt_authN fields.
	//
	// +kubebuilder:validation:Optional
	Provider    ProviderSrvc `json:"provider,omitempty"`
	Issuer      string       `json:"issuer,omitempty"`
	Audiences   []string     `json:"audiences,omitempty"`
	JwksUrl     string       `json:"jwksUrl,omitempty"`
	Forward     bool         `json:"forward,omitempty"`
	FromHeaders bool         `json:"fromHeaders,omitempty"`
	FromParams  bool         `json:"fromParams,omitempty"`
}

// PortRuleHTTP is a list of HTTP protocol constraints. All fields are
// optional, if all fields are empty or missing, the rule does not have any
// effect.
//
// All fields of this type are extended POSIX regex as defined by IEEE Std
// 1003.1, (i.e this follows the egrep/unix syntax, not the perl syntax)
// matched against the path of an incoming request. Currently it can contain
// characters disallowed from the conventional "path" part of a URL as defined
// by RFC 3986.
type PortRuleHTTP struct {
	// Path is an extended POSIX regex matched against the path of a
	// request. Currently it can contain characters disallowed from the
	// conventional "path" part of a URL as defined by RFC 3986.
	//
	// If omitted or empty, all paths are all allowed.
	//
	// +kubebuilder:validation:Optional
	Path string `json:"path,omitempty"`

	// Method is an extended POSIX regex matched against the method of a
	// request, e.g. "GET", "POST", "PUT", "PATCH", "DELETE", ...
	//
	// If omitted or empty, all methods are allowed.
	//
	// +kubebuilder:validation:Optional
	Method string `json:"method,omitempty"`

	// Host is an extended POSIX regex matched against the host header of a
	// request, e.g. "foo.com"
	//
	// If omitted or empty, the value of the host header is ignored.
	//
	// +kubebuilder:validation:Format=idn-hostname
	// +kubebuilder:validation:Optional
	Host string `json:"host,omitempty"`

	// Headers is a list of HTTP headers which must be present in the
	// request. If omitted or empty, requests are allowed regardless of
	// headers present.
	//
	// +kubebuilder:validation:Optional
	Headers []string `json:"headers,omitempty"`

	// HeaderMatches is a list of HTTP headers which must be
	// present and match against the given values. Mismatch field can be used
	// to specify what to do when there is no match.
	//
	// +kubebuilder:validation:Optional
	HeaderMatches []*HeaderMatch `json:"headerMatches,omitempty"`

	// RuleID is an integer which holds the policy name in a map
	//
	// +kubebuilder:validation:Optional
	RuleID uint16 `json:"ruleID,omitempty"`

	// AuditMode is a boolean used in envoy to process the rule in audit mode
	//
	// +kubebuilder:validation:Optional
	AuditMode bool `json:"auditMode,omitempty"`

	// MatchJWT is list of identity providers used to authenticate
	// and authorize requests on micro-segmentation basis using jwt
	// tokens
	//
	// +kubebuilder:validation:Optional
	MatchJWT []*MatchJWT `json:"matchJWT,omitempty"`
}

// Sanitize sanitizes HTTP rules. It ensures that the path and method fields
// are valid regular expressions. Note that the proxy may support a wider-range
// of regular expressions (e.g. that specified by ECMAScript), so this function
// may return some false positives. If the rule is invalid, returns an error.
func (h *PortRuleHTTP) Sanitize() error {

	if h.Path != "" {
		_, err := regexp.Compile(h.Path)
		if err != nil {
			return err
		}
	}

	if h.Method != "" {
		_, err := regexp.Compile(h.Method)
		if err != nil {
			return err
		}
	}

	// Headers are not sanitized.

	// But HeaderMatches are
	for _, m := range h.HeaderMatches {
		if m.Name == "" {
			return fmt.Errorf("Header name missing")
		}
		if m.Mismatch != "" &&
			m.Mismatch != MismatchActionLog && m.Mismatch != MismatchActionAdd &&
			m.Mismatch != MismatchActionDelete && m.Mismatch != MismatchActionReplace {
			return fmt.Errorf("Invalid header action: %s", m.Mismatch)
		}
		if m.Secret != nil && m.Secret.Name == "" {
			return fmt.Errorf("Secret name missing")
		}
	}

	// and about matchJWT?

	return nil
}

func (h *MatchJWT) Equal(o *MatchJWT) bool {
	if h.Provider != o.Provider ||
		h.Issuer != o.Issuer ||
		!h.strSliceCmp(h.Audiences, o.Audiences) ||
		h.JwksUrl != o.JwksUrl ||
		h.Forward != o.Forward ||
		h.FromHeaders != o.FromHeaders ||
		h.FromParams != o.FromParams {
		return false
	}
	return true
}

func (h *MatchJWT) strSliceCmp(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
