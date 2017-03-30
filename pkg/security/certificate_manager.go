// Copyright 2017 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.
//
// Author: Marc Berhault (marc@cockroachlabs.com)

package security

import (
	"sync"

	"github.com/pkg/errors"
)

type ProcessRole uint32

type CertificateManager struct {
	// Immutable fields after object construction.
	certsDir string

	// mu protects all remaining fields.
	mu sync.RWMutex

	// If false, this is the first load. Needed to ensure we do not drop certain certs.
	initialized bool
	// Set of certs. These are swapped in during Load(), and never mutated afterwards.
	caCert      *CertInfo
	nodeCert    *CertInfo
	clientCerts map[string]*CertInfo
}

// NewCertificateManager creates a new certificate manager.
func NewCertificateManager(certsDir string) (*CertificateManager, error) {
	cm := &CertificateManager{certsDir: certsDir}
	return cm, cm.LoadCertificates()
}

// CACert returns the CA cert. May be nil.
func (cm *CertificateManager) CACert() *CertInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.caCert
}

// NodeCert returns the Node cert. May be nil.
func (cm *CertificateManager) NodeCert() *CertInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.nodeCert
}

// ClientCerts returns the Client certs.
func (cm *CertificateManager) ClientCerts() map[string]*CertInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.clientCerts
}

// LoadCertificates creates a CertificateLoader to load all certs and keys.
func (cm *CertificateManager) LoadCertificates() error {
	cl := NewCertificateLoader(cm.certsDir)
	if err := cl.Load(); err != nil {
		return errors.Wrap(err, "problem loading certs directory")
	}

	var caCert, nodeCert *CertInfo
	clientCerts := make(map[string]*CertInfo)
	for _, ci := range cl.Certificates() {
		switch ci.FileUsage {
		case caPem:
			caCert = ci
		case nodePem:
			nodeCert = ci
		case clientPem:
			clientCerts[ci.Name] = ci
		}
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()
	if cm.initialized {
		if cm.caCert != nil && caCert == nil {
			return errors.New("aborting Load(), CA certificate has disappeared")
		}
		if cm.nodeCert != nil && nodeCert == nil {
			return errors.New("aborting Load(), node certificate has disappeared")
		}
		// TODO(mberhault): should we check client certs?
	}

	// Swap everything.
	cm.caCert = caCert
	cm.nodeCert = nodeCert
	cm.clientCerts = clientCerts

	return nil
}
