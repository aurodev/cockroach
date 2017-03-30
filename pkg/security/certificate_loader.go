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
	"crypto/tls"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/cockroach/pkg/util/envutil"
	"github.com/cockroachdb/cockroach/pkg/util/log"
	"github.com/pkg/errors"
)

// AssetLoader describes the functions necessary to read certificate and
// key files, either from a few filesystem, or the embedded assets.
type AssetLoader struct {
	ReadDir  func(dirname string) ([]os.FileInfo, error)
	ReadFile func(filename string) ([]byte, error)
	Stat     func(name string) (os.FileInfo, error)
}

// defaultAssetLoader uses real filesystem calls.
var defaultAssetLoader = AssetLoader{
	ReadDir:  ioutil.ReadDir,
	ReadFile: ioutil.ReadFile,
	Stat:     os.Stat,
}

// assetLoaderImpl is used to list/read/stat security assets.
var assetLoaderImpl = defaultAssetLoader

// SetAssetLoader overrides the asset loader with the passed-in one.
func SetAssetLoader(al AssetLoader) {
	assetLoaderImpl = al
}

// ResetAssetLoader restores the asset loader to the default value.
func ResetAssetLoader() {
	assetLoaderImpl = defaultAssetLoader
}

type pemUsage uint32

const (
	_ pemUsage = iota
	caPem
	nodePem
	clientPem

	// Maximum allowable permissions.
	maxKeyPermissions os.FileMode = 0700
)

func (p pemUsage) String() string {
	switch p {
	case caPem:
		return "Certificate Authority"
	case nodePem:
		return "Node"
	case clientPem:
		return "Client"
	default:
		return "unknown"
	}
}

// CertInfo describe a certificate file and optional key file.
// To obtain the full path, Filename and KeyFilename must be joined
// with the certs directory.
type CertInfo struct {
	Filename  string
	FileUsage pemUsage

	// the name is the blob in the middle of the filename. eg: username for client certs.
	Name string

	// blank if none found.
	KeyFilename string
}

func exceedsPermissions(objectMode, allowedMode os.FileMode) bool {
	mask := os.FileMode(0777) ^ allowedMode
	return mask&objectMode != 0
}

func isCertificateFile(filename string) bool {
	return strings.HasSuffix(filename, `.crt`)
}

// CertificateLoader searches for certificates and keys in the certs directory.
type CertificateLoader struct {
	certsDir             string
	skipPermissionChecks bool
	certificates         []*CertInfo
}

func (cl *CertificateLoader) Certificates() []*CertInfo {
	return cl.certificates
}

// NewCertificateLoader creates a new instance of the certificate loader.
func NewCertificateLoader(certsDir string) *CertificateLoader {
	return &CertificateLoader{
		certsDir:             certsDir,
		skipPermissionChecks: envutil.EnvOrDefaultBool("COCKROACH_SKIP_KEY_PERMISSION_CHECK", false),
		certificates:         make([]*CertInfo, 0, 0),
	}
}

// Load examines all .crt files in the certs directory, determines their
// usage, and looks for their keys.
// It populates the certificates field.
func (cl *CertificateLoader) Load() error {
	fileInfos, err := assetLoaderImpl.ReadDir(cl.certsDir)
	if err != nil {
		return err
	}

	// Walk the directory contents.
	for _, info := range fileInfos {
		filename := info.Name()
		fullPath := path.Join(cl.certsDir, filename)

		if info.IsDir() {
			// Skip subdirectories.
			if log.V(3) {
				log.Infof(context.Background(), "skipping sub-directory %s", fullPath)
			}
			continue
		}

		if !isCertificateFile(filename) {
			continue
		}

		// Build the info struct from the filename.
		ci, err := certInfoFromFilename(filename)
		if err != nil {
			log.Warningf(context.Background(), "bad filename %s: %v", fullPath, err)
			continue
		}

		// Look for the associated key.
		if err := cl.findKey(ci); err != nil {
			log.Warningf(context.Background(), "error finding key for %s: %v", fullPath, err)
			continue
		}

		cl.certificates = append(cl.certificates, ci)
	}

	return nil
}

// certInfoFromFilename takes a filename and attempts to determine the
// certificate usage (ca, node, etc..).
func certInfoFromFilename(filename string) (*CertInfo, error) {
	parts := strings.Split(filename, `.`)
	numParts := len(parts)

	if numParts < 2 {
		return nil, errors.New("not enough parts found")
	}

	var pu pemUsage
	prefix := parts[0]
	switch parts[0] {
	case `ca`:
		pu = caPem
	case `node`:
		pu = nodePem
	case `client`:
		pu = clientPem
	default:
		return nil, errors.Errorf("unknown prefix %q", prefix)
	}

	// strip prefix and suffix and re-join middle parts.
	name := strings.Join(parts[1:numParts-1], `.`)

	return &CertInfo{Filename: filename, FileUsage: pu, Name: name}, nil
}

// findKey takes a CertInfo and looks for the corresponding key file.
// If found, sets the 'keyFilename' and returns nil, returns error otherwise.
func (cl *CertificateLoader) findKey(ci *CertInfo) error {
	keyFilename := strings.TrimSuffix(ci.Filename, `.crt`) + `.key`
	fullKeyPath := filepath.Join(cl.certsDir, keyFilename)

	// Stat the file. This follows symlinks.
	info, err := assetLoaderImpl.Stat(fullKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File does not exist. We allow some certs without keys.
			return nil
		}
		return errors.Errorf("could not stat key file %s: %v", fullKeyPath, err)
	}

	// Only regular files are supported (after following symlinks).
	fileMode := info.Mode()
	if !fileMode.IsRegular() {
		return errors.Errorf("key file %s is not a regular file", fullKeyPath)
	}

	if !cl.skipPermissionChecks {
		// Check permissions bits.
		filePerm := fileMode.Perm()
		if exceedsPermissions(filePerm, maxKeyPermissions) {
			return errors.Errorf("key file %s has permissions %s, exceeds %s",
				fullKeyPath, filePerm, maxKeyPermissions)
		}
	}

	// Load files and make sure they really are a pair.
	fullCertPath := filepath.Join(cl.certsDir, ci.Filename)
	certPEMBlock, err := assetLoaderImpl.ReadFile(fullCertPath)
	if err != nil {
		return errors.Errorf("could not read certificate file %s: %v", fullCertPath, err)
	}

	keyPEMBlock, err := assetLoaderImpl.ReadFile(fullKeyPath)
	if err != nil {
		return errors.Errorf("could not read key file %s: %v", fullKeyPath, err)
	}

	if _, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock); err != nil {
		return errors.Errorf("error loading x509 key pair {%s,%s}: %v",
			fullCertPath, fullKeyPath, err)
	}

	ci.KeyFilename = keyFilename
	return nil
}
