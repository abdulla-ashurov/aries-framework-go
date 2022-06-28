/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

const (
	// HTTPClientOpt http client opt.
	HTTPClientOpt = "httpClient"

	// UseHTTPOpt use http option.
	UseHTTPOpt = "useHTTP"
)

var logger = log.New("aries-framework/pkg/vdr/web")

// Read resolves a did:web did.
func (v *VDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	httpClient := &http.Client{}

	// didOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}
	// // Apply options
	// for _, opt := range opts {
	// 	opt(didOpts)
	// }

	// k, ok := didOpts.Values[HTTPClientOpt]
	// if ok {
	// 	httpClient, ok = k.(*http.Client)

	// 	if !ok {
	// 		return nil, fmt.Errorf("failed to cast http client opt to http client struct")
	// 	}
	// }

	// useHTTP := false

	// _, ok = didOpts.Values[UseHTTPOpt]
	// if ok {
	// 	useHTTP = true
	// }

	// address, _, err := parseDIDWeb(didID, useHTTP)
	// if err != nil {
	// 	return nil, fmt.Errorf("error resolving did:web did --> could not parse did:web did --> %w", err)
	// }

	address := "https://resolver.cheqd.net/1.0/identifiers/did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY#key1"

	resp, err := httpClient.Get(address)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> http request unsuccessful --> %w", err)
	}

	defer closeResponseBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http server returned status code [%d]", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> error reading http response body: %s --> %w", body, err)
	}

	raw := &RawDocCheqd{}
	if err = json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("JSON UNMARSHAL ERROR!")
	}

	// // Verification Method constants.
	var vmController interface{} = raw.DidDocument.VerificationMethod[0].Controller
	var vmId interface{} = raw.DidDocument.VerificationMethod[0].ID
	var vmPublicKeyMultibase interface{} = raw.DidDocument.VerificationMethod[0].PublicKeyMultibase
	var vmType interface{} = raw.DidDocument.VerificationMethod[0].Type

	// // Service constants.
	var serviceId interface{} = raw.DidDocument.Service[0].ID
	var serviceEndpoint interface{} = raw.DidDocument.Service[0].ServiceEndpoint
	var serviceType interface{} = raw.DidDocument.Service[0].Type

	// Authatication constants.
	authentication := make([]interface{}, len(raw.DidDocument.Authentication))
	for i := 0; i < len(raw.DidDocument.Authentication); i++ {
		authentication[i] = raw.DidDocument.Authentication[i]
	}

	raw2 := &rawDoc{
		ID: raw.DidDocument.ID,
		VerificationMethod: []map[string]interface{}{
			{"controller": vmController, "id": vmId, "publicKeyMultibase": vmPublicKeyMultibase, "type": vmType},
		},
		Service: []map[string]interface{}{
			{"id": serviceId, "serviceEndpoint": serviceEndpoint, "type": serviceType},
		},
		Authentication: authentication,
	}
	// raw2.Authentication = append(raw2.Authentication, authentication)
	// raw2.Context = `@context": ["https://w3id.org/did/v1"]`

	body, err = json.Marshal(raw2)
	if err != nil {
		return nil, fmt.Errorf("error json marshal")
	}

	doc, err := did.ParseDocument(body)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> error parsing did doc --> %w", err)
	}

	return &did.DocResolution{DIDDocument: doc}, nil
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		logger.Errorf("Failed to close response body: %v", e)
	}
}

// rawDoc type.
type rawDoc struct {
	Context              interface{}              `json:"@context,omitempty"`
	ID                   string                   `json:"id,omitempty"`
	VerificationMethod   []map[string]interface{} `json:"verificationMethod,omitempty"`
	PublicKey            []map[string]interface{} `json:"publicKey,omitempty"`
	Service              []map[string]interface{} `json:"service,omitempty"`
	Authentication       []interface{}            `json:"authentication,omitempty"`
	AssertionMethod      []interface{}            `json:"assertionMethod,omitempty"`
	CapabilityDelegation []interface{}            `json:"capabilityDelegation,omitempty"`
	CapabilityInvocation []interface{}            `json:"capabilityInvocation,omitempty"`
	KeyAgreement         []interface{}            `json:"keyAgreement,omitempty"`
	Created              *time.Time               `json:"created,omitempty"`
	Updated              *time.Time               `json:"updated,omitempty"`
	Proof                []interface{}            `json:"proof,omitempty"`
}

// RawDocCheqd type.
type RawDocCheqd struct {
	DidDocument           DidDocument           `json:"didDocument"`
	DidDocumentMetadata   DidDocumentMetadata   `json:"didDocumentMetadata"`
	DidResolutionMetadata DidResolutionMetadata `json:"didResolutionMetadata"`
}

// DidDocument type.
type DidDocument struct {
	Authentication     []string             `json:"authentication"`
	ID                 string               `json:"id"`
	Service            []Service            `json:"service"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
}

// Service type.
type Service struct {
	ID              string `json:"id"`
	ServiceEndpoint string `json:"serviceEndpoint"`
	Type            string `json:"type"`
}

// VerificationMethod type.
type VerificationMethod struct {
	Controller         string `json:"controller"`
	ID                 string `json:"id"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	Type               string `json:"type"`
}

// DidDocumentMetadata type.
type DidDocumentMetadata struct {
	Created   string `json:"created"`
	VersionID string `json:"versionId"`
}

// DidResolutionMetadata type.
type DidResolutionMetadata struct {
	ContentType string `json:"contentType"`
	Retrieved   string `json:"retrieved"`
	DID         DID    `json:"did"`
}

// DID type.
type DID struct {
	DIDString        string `json:"didString"`
	MethodSpecificID string `json:"methodSpecificId"`
	Method           string `json:"method"`
}
