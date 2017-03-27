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
	"context"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/cockroachdb/cockroach/pkg/util/log"
	"github.com/pkg/errors"
)

//go:generate stringer -type=pemType

type CertificateManager struct {
	certDir string
}

type pemType uint32
type pemUsage uint32

const (
	_ pemType = iota
	certPem
	keyPem

	_ pemUsage = iota
	caPem
	nodePem
	clientPem

	// Maximum allowable permissions.
	maxKeyPermissions os.FileMode = 0700
)

// certFile describe a certificate file and optional key file.
type pemFile struct {
	filename  string
	fileType  pemType
	fileUsage pemUsage

	// the name is the blob in the middle of the filename. eg: username for client certs.
	name string

	// blank if none found or loaded.
	keyFilename string
}

func exceedsPermissions(objectMode, allowedMode os.FileMode) bool {
	mask := os.FileMode(0777) ^ allowedMode
	return mask&objectMode != 0
}

func (c *CertificateManager) validateCertDir() error {
	info, err := os.Stat(c.certDir)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return errors.Errorf("%s is not a directory", c.certDir)
	}

	return nil
}

func (c *CertificateManager) Reload() error {
	if err := c.validateCertDir(); err != nil {
		return err
	}

	fileInfos, err := ioutil.ReadDir(c.certDir)
	if err != nil {
		return err
	}

	for _, info := range fileInfos {
		filename := info.Name()
		fullPath := path.Join(c.certDir, filename)
		if info.IsDir() {
			if log.V(3) {
				log.Infof(context.Background(), "skipping sub-directory %s", fullPath)
			}
			continue
		}

		pf, err := pemFileFromName(filename)
		if err != nil {
			log.Warningf(context.Background(), "bad filename %s: %v", filename, err)
			continue
		}
		log.Infof(context.Background(), "found %+v", pf)
	}

	return nil
}

func pemFileFromName(filename string) (pemFile, error) {
	parts := strings.Split(filename, `.`)
	numParts := len(parts)

	if numParts < 2 {
		return pemFile{}, errors.New("not enough parts found")
	}

	var pu pemUsage
	prefix := parts[1]
	switch parts[0] {
	case `ca`:
		pu = caPem
	case `node`:
		pu = nodePem
	case `client`:
		pu = clientPem
	default:
		return pemFile{}, errors.Errorf("unknown prefix %q", prefix)
	}

	var pt pemType
	suffix := parts[numParts-1]
	switch parts[numParts-1] {
	case `cert`, `crt`:
		pt = certPem
	case `key`:
		pt = keyPem
	default:
		return pemFile{}, errors.Errorf("unknown suffix %q", suffix)
	}

	name := strings.Join(parts[1:numParts-1], `.`)

	return pemFile{filename: filename, fileType: pt, fileUsage: pu, name: name}, nil
}

func NewCertificateManager(certDirectory string) *CertificateManager {
	return &CertificateManager{certDir: certDirectory}
}

//		if exceedsPermissions(filePerm, maxKeyPermissions) {
//			return nil, errors.Errorf("private key file has permissions %s, cannot be more than %s",
//				filePerm, maxKeyPermissions)
//		}
