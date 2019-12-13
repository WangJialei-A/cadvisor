// Copyright 2019 Google Inc. All Rights Reserved.
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
// generated by build/assets.sh; DO NOT EDIT

// Code generated by go-bindata. DO NOT EDIT.
// sources:
// pages/assets/html/containers.html (10.242kB)

package pages

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes  []byte
	info   os.FileInfo
	digest [sha256.Size]byte
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _pagesAssetsHtmlContainersHtml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xc4\x5a\x4d\x73\xdb\x38\xd2\x3e\xbf\xfa\x15\x1d\xd6\x7b\x98\xad\x0a\x29\x3b\xce\x65\xb3\xb2\xaa\x34\x4a\xb2\xa3\x1d\xc7\x4e\x59\xf6\x4c\xcd\x11\x24\x5b\x24\x62\x10\xc0\x00\xa0\x64\xad\x4b\xff\x7d\x0b\x20\x29\x93\x14\x29\xcb\xb6\xca\xc9\x25\x32\xd0\x78\xfa\xe9\x2f\xa0\x41\x72\xf4\xce\xf7\x07\x00\x53\x21\xd7\x8a\x26\xa9\x81\x0f\x27\xa7\x1f\xe1\xdf\x42\x24\x0c\x61\xc6\xa3\x00\x26\x8c\xc1\xb5\x9d\xd2\x70\x8d\x1a\xd5\x12\xe3\x60\x30\x00\xb8\xa0\x11\x72\x8d\x31\xe4\x3c\x46\x05\x26\x45\x98\x48\x12\xa5\x58\xcd\xbc\x87\x3f\x50\x69\x2a\x38\x7c\x08\x4e\xe0\x17\x2b\xe0\x95\x53\xde\x3f\xfe\x35\x00\x58\x8b\x1c\x32\xb2\x06\x2e\x0c\xe4\x1a\xc1\xa4\x54\xc3\x82\x32\x04\xbc\x8f\x50\x1a\xa0\x1c\x22\x91\x49\x46\x09\x8f\x10\x56\xd4\xa4\x4e\x4d\x09\x12\x0c\x00\xfe\x2a\x21\x44\x68\x08\xe5\x40\x20\x12\x72\x0d\x62\x51\x97\x03\x62\x2c\x5f\xfb\x2f\x35\x46\x7e\x1a\x0e\x57\xab\x55\x40\x1c\xd7\x40\xa8\x64\xc8\x0a\x39\x3d\xbc\x98\x4d\xbf\x5c\xce\xbf\xf8\x1f\x82\x13\xbb\xe2\x96\x33\xd4\x1a\x14\xfe\x9d\x53\x85\x31\x84\x6b\x20\x52\x32\x1a\x91\x90\x21\x30\xb2\x02\xa1\x80\x24\x0a\x31\x06\x23\x2c\xdb\x95\xa2\x86\xf2\xe4\x3d\x68\xb1\x30\x2b\xa2\x70\x00\x10\x53\x6d\x14\x0d\x73\xd3\x70\x55\xc5\x8d\xea\x86\x80\xe0\x40\x38\x78\x93\x39\xcc\xe6\x1e\xfc\x3a\x99\xcf\xe6\xef\x07\x00\x7f\xce\x6e\x7e\xbb\xba\xbd\x81\x3f\x27\xd7\xd7\x93\xcb\x9b\xd9\x97\x39\x5c\x5d\xc3\xf4\xea\xf2\xf3\xec\x66\x76\x75\x39\x87\xab\xaf\x30\xb9\xfc\x0b\x7e\x9f\x5d\x7e\x7e\x0f\x48\x4d\x8a\x0a\xf0\x5e\x2a\xcb\x5f\x28\xa0\xd6\x89\x36\x6e\x00\x73\xc4\x06\x81\x85\x28\x08\x69\x89\x11\x5d\xd0\x08\x18\xe1\x49\x4e\x12\x84\x44\x2c\x51\x71\xca\x13\x90\xa8\x32\xaa\x6d\x28\x35\x10\x1e\x0f\x00\x18\xcd\xa8\x21\xc6\x8d\xec\x18\x15\x0c\x7c\x7f\x3c\x18\x8c\x52\x93\x31\xf7\x3f\x92\x78\x3c\x00\x18\x19\x6a\x18\x8e\xa3\x49\xbc\xa4\x5a\x28\xf0\xe1\xe1\x21\xf8\x4c\xb5\x64\x64\x7d\x49\x32\xdc\x6c\x46\xc3\x42\xc4\x0a\xeb\x48\x51\x69\x40\xab\xe8\xdc\x7b\x78\x08\xae\x85\x30\x9b\x8d\xb6\x4a\xa3\xa1\x14\x52\xa2\x0a\x32\xca\x83\x1f\xda\x1b\x8f\x86\x85\xb0\x5b\xf7\xce\xf7\xe1\x82\x18\xd4\xc6\x25\x0f\x65\x18\x5b\xd2\x90\x51\x4e\x17\x14\x63\x98\xce\xe7\x60\x09\x02\x8c\x18\xe5\x77\xa0\x90\x9d\x7b\xda\xac\x19\xea\x14\xd1\x78\x90\x2a\x5c\xec\xea\x0c\x85\x30\xda\x28\x22\xfd\x8f\xc1\x49\x70\xe2\x87\x68\x48\xf0\xc1\x71\x88\xb4\xf6\xc6\x83\x4a\xf9\x95\xb4\x7e\x21\xcc\xba\x24\xc3\xd7\xa9\x72\x10\xfe\x59\x70\x1a\x9c\xb6\x34\x3d\x07\x2f\x12\xdc\x96\x07\x2a\xdd\xa2\xba\xd7\x4f\xff\x21\x4b\x32\x2f\x82\x50\xda\xb0\x2f\x24\x3f\xfe\xce\x51\xad\xfd\x33\xeb\x9b\xee\xc0\xec\x5b\xbd\xc7\xb9\x7d\x38\x66\x2d\xf1\xdc\x33\x78\x6f\x86\x3f\xc8\x92\x14\xa3\x5e\x37\x7c\xe2\xf6\x33\xff\x87\x26\x92\xb6\x00\x5f\x88\x58\x73\xe9\x51\x08\x46\x29\x51\xa6\x8d\x35\x1a\x16\xa5\x33\x18\x85\x22\x5e\x3b\xec\x98\x2e\x21\x62\x44\xeb\x73\x6f\x4b\xa1\x48\x34\x5f\xa7\x62\x15\x11\x8d\xde\xd8\xed\x76\x23\xd2\xce\x06\xef\x71\x25\xf3\x75\xe6\x9f\x7e\xf0\x80\xc6\xe7\x1e\x13\x89\xa8\x16\x0d\x49\xf9\xa3\xa1\xa8\x12\x1f\x97\xfb\x68\x7d\x56\x92\x04\x7d\xcb\x13\xd5\x76\x1e\x60\x94\x9e\x8e\x77\xab\x3b\x3d\xdd\x22\x0c\x63\xba\xdc\xfe\x21\x58\x85\x16\x2a\x24\x71\xa4\xf2\x2c\xac\x81\x3d\x3c\x28\xc2\x13\x84\xff\x97\x44\x21\x37\xd3\xad\xe1\x9f\xce\x21\xf8\xde\x1c\xd3\x9b\xcd\x23\x09\x46\xc7\x35\x37\xb4\x97\x07\x17\x94\xdf\x6d\x36\xde\xb8\x63\xea\x06\xef\x8d\x65\x4c\xc6\xa3\x21\xa3\x75\x2a\xc8\xe3\xad\x8a\xd1\x50\xb0\xca\x71\x5b\x7b\x1e\x1e\xe8\x02\x82\x99\x2e\x9c\x7e\x88\x37\xd3\x8f\x8f\x34\x83\x60\x18\x8b\xe8\xce\x3a\xf3\xb3\xfb\x1f\x1e\x4d\x2b\xe8\xa4\x1f\x3b\x54\x3e\xb2\x2a\xd4\xcf\xf3\x30\x6a\xbb\xe4\xf5\x31\x3d\x1b\x37\x70\x47\xc3\xf4\xac\x3b\xa0\x35\x2c\x46\xb5\xf1\x13\x25\x72\xd9\x15\x51\x5d\xc3\x73\xe1\xec\x22\xde\x4a\xe7\xc6\xa2\x2a\x88\xbb\xea\x7c\x6a\x30\x73\xc1\x6d\xc8\x3f\x46\xb6\x37\xa8\x5b\x4b\xf6\xba\xb8\x08\xcf\xdc\x10\x93\x1f\xd3\xc3\x9f\x15\x5d\xa2\x82\x02\xb7\xdf\xc3\x39\x3b\xcc\xc1\x45\x32\x69\x87\xe6\x1c\xdc\x41\xbb\xac\x95\x5e\x17\x8e\xb4\x24\xbc\x9a\xb5\x50\x3e\x23\x21\x32\xe7\xdb\x3a\x7e\xf0\x3b\xae\xad\x6b\xad\xf8\x18\xda\x93\x7f\x10\x96\xbb\x5d\xa0\xbf\x9e\x9a\xae\x2d\x3c\x71\x1c\xa6\x73\x23\x14\x49\x70\x14\xaa\x71\xc9\x6f\x8b\xf7\xb4\x33\x9b\x0e\x75\xac\x76\x1c\xda\x43\xf6\x55\xae\xad\x69\xda\x75\x6d\x7d\xb2\x74\x6d\x53\x6b\xc3\xcf\x5d\xbe\xb6\x32\x39\xab\x65\x5f\x6d\x45\x7d\xa6\xbe\xee\x80\x8a\x98\x65\x24\xc1\x63\x56\x44\x01\xb8\x7f\xb3\xb1\xe7\x58\x91\x6d\x3e\x75\xe2\xf6\x1c\xad\x0b\xd9\xc0\x87\xea\x80\xb2\xbe\x46\x2d\x72\x15\xa1\x9e\x2c\x09\x65\xb6\xd5\x3f\xa6\x29\x5a\x30\xd7\x36\xf7\x5a\x53\x90\x98\xca\xbc\xad\xfe\xe9\x34\xed\xcf\x33\x20\x91\xa1\x4b\x7b\xdb\x28\xd5\xfb\xae\xcf\x06\x49\x38\xb2\xe2\xb7\x37\x9e\x7e\xbf\x6d\xd7\xa6\x3b\x49\x24\x46\x96\x4f\x70\x61\x7b\xfe\x57\xd7\x61\x4a\x94\x8d\x65\x95\xc7\x52\x51\x6e\x8a\xc1\x5d\x55\xe0\x60\x1a\x39\x5c\x42\xe6\x9c\x6e\x21\x75\x1d\xf2\x90\xdd\x65\xab\xe6\x1b\xb9\x3f\x8a\x51\xdf\xc8\x3d\x38\xa0\x96\x5d\x53\xd1\x34\xeb\x51\xdf\x61\x96\x45\xe2\xc5\x86\xe9\xbb\xd7\x1a\x35\x61\x4c\xac\xec\x75\xa9\x46\xa2\x46\xb8\x34\xd1\x6a\x6a\x29\x86\xe0\x1b\x89\x52\xca\x71\xc6\x17\x22\xb8\xcc\x33\x87\xb0\x7f\xe3\xef\xdb\x6e\x2a\xcb\xbe\x61\x26\xd4\xfa\xcd\x4b\xa2\x50\xdb\x5b\x15\xc5\x74\x50\x3c\x16\x71\x20\xaf\x75\x7a\x0d\xaa\x5d\x23\xf4\xbf\x78\x88\x5a\x80\x06\x78\x3d\x9d\x4a\xa4\x5b\x4e\xcd\x1e\xa4\xe7\xe6\x5b\x89\x71\x94\x42\xea\x2a\xa2\x5d\xc3\x9f\x55\x43\xbd\x46\x97\x28\x2f\x34\x77\xbe\x22\xf2\x38\x1b\xe2\x8a\xc8\xce\xcd\x63\xd7\xee\x2e\x9d\x2f\x09\x77\x0d\xe7\x00\xeb\x0f\xe8\x04\x8e\x71\x32\xde\x6a\xdb\x9e\x1d\x72\xa1\x70\x15\x5a\xd6\xa9\x54\x34\x23\x6a\x5d\xc7\x6a\x4b\x3a\x75\x94\x27\x8d\x7e\x6e\x94\x9e\x35\x85\xca\x82\xbf\x5a\xa2\x5a\x52\x5c\xd5\x89\xb4\xa8\xd4\x1a\x8e\xdc\x72\xf6\x13\x92\x27\xe8\x35\xe1\xec\x7d\xbd\xdd\x81\xfc\x0c\x7b\xbe\x2b\x11\xa1\xd6\xcd\xee\xa9\xdf\x20\x59\x89\xfb\x46\xc8\x83\x4d\x7a\x6b\x9b\x50\x2d\x60\x2a\x72\x6e\x50\x3d\x6d\x56\x87\x0d\x0d\x1d\x1f\xc7\xd3\xef\xb3\xc7\x4b\x75\xcb\x21\x91\xa4\xbe\x7b\x34\xd3\xb2\x7c\xbb\x76\x1d\x31\xec\x5f\x6d\x67\xf7\xae\x9f\x71\x6d\x54\x1e\x95\x1d\x61\x37\x0a\x7d\x94\xe9\xc1\xea\x0c\xca\x01\xfd\xe4\x1b\x05\xcc\x35\x96\xaf\x8f\xd3\x8d\x30\x84\x41\xb5\x4f\xf4\xc5\x2b\xf7\x8d\x95\xf3\x8b\xda\xec\xf5\xfd\x3b\xdf\x2f\x83\x7f\x0b\x17\x82\xc4\x30\x59\xa2\xda\x22\xff\xdf\x0e\x28\x13\x24\x6e\xa2\x95\x0f\x45\xeb\x0c\x1d\x37\x90\xee\x99\x8d\xda\x4f\x52\xa2\xf2\x6d\x7b\xf7\x14\xcf\x2d\xea\xaf\x0a\xc9\x5d\x2c\x56\xfd\x79\x62\x61\x0b\xb4\xb0\x92\x7d\x46\xbe\x54\xd9\xf2\x8c\xde\xeb\x8d\xd2\xa7\x6a\xc2\xde\x26\x83\x32\xa7\xed\xa9\xb0\x84\x0a\x86\x3b\xcb\x4b\x02\x4a\xac\x60\xf7\x14\x3c\x38\x9e\x9d\xc7\xe9\x3f\x5b\x38\x2d\x93\x95\x48\x14\xba\x27\xfb\x00\x4f\x8b\xf9\x21\x51\x50\xff\xc3\x8f\x09\x4f\x50\x79\xd5\x19\x50\x4c\xa4\xc2\xf8\x85\x37\x3a\x70\x5b\x7d\x87\x56\xbe\xe0\x6c\xed\x8d\x7f\x13\x06\xaa\x80\xb5\xaf\x0c\x9d\xa1\x7b\x1e\x51\xca\x17\xa2\x45\x33\x12\x2c\x7e\x3e\xcf\xa9\x60\xf1\x4b\x88\x76\x0c\x76\x0d\xed\x46\xf0\xcc\xab\xa7\x97\xc1\xfb\xce\xbc\x7a\x4d\x9d\x5e\xa2\x59\x09\x75\xf7\xf3\x0a\xb5\x24\xf0\xea\x4a\xad\x89\xc4\x4a\x48\x5b\x24\xed\x32\x0a\x73\x63\xc4\x36\xaa\xa1\xe1\x10\x1a\xee\xc7\xb8\x20\x39\x33\x50\xad\xf2\x8d\x48\x12\x86\x5e\xf9\x2a\xa6\x58\x54\xc4\x81\x17\x5c\x7d\x8d\x0c\x8b\xa3\x75\xab\xaa\x15\xf1\x98\x18\x52\x02\xd5\xf8\x00\x51\x94\xf8\x29\xd1\x52\xc8\x5c\x9e\x7b\x46\xe5\x58\x0e\xe2\xbd\x24\x3c\xc6\xf8\xdc\x5b\x10\xb6\x7d\x1d\xd3\x4e\xc8\x6e\x12\x55\x5e\x74\x65\x64\x23\x91\x23\xa2\xb0\x47\x72\x34\x2c\x0c\x6d\x8d\xe6\xac\x5b\xa7\xd7\xf6\xb5\x9f\x21\xcf\x3d\x50\xc2\x1a\x5c\xfc\x76\x76\xb9\x6b\x05\xc3\x38\x5c\xef\x75\x5f\x9b\x4c\xfd\x09\xe3\xfe\x0c\x3f\x7c\x1f\x4f\x95\xc8\x93\x54\xe6\xa6\x77\x1b\xaf\x08\x86\x6b\x83\xfa\x90\x63\xf0\x60\xe5\x5f\x94\x12\xee\xd5\xc7\x7e\xc5\xe8\xc4\x8e\x72\x00\x7f\xdd\x79\x14\xf9\x76\x35\xfd\x95\x32\xd4\x6b\x6d\x30\x3b\xec\x06\xb1\xd8\xca\x17\x47\x68\xe7\x25\xe2\x85\x7e\x98\xe6\xda\x88\xec\x1b\x1a\x45\xa3\x9f\xe8\x92\x49\xf1\x0d\x88\xcd\x7a\x28\xc9\x1c\x65\xcb\x73\x3d\x9c\x33\xd1\xcf\x0a\xd8\xa3\x64\x4f\xe3\x85\xda\xcf\xf3\x5a\xef\x8b\xc3\x97\x37\x73\x12\x6c\xf7\xee\xda\xa9\x4f\xcd\x4d\x87\x72\x99\x9b\x46\xaf\x5d\x7f\x05\xe8\xc7\xc5\x5b\x69\x3f\xb2\x97\xc8\x6d\x86\x76\x8a\x38\x24\x0f\x96\x84\xe5\x78\x7e\x7a\xd2\xdc\xca\x9e\xe8\xef\x1b\x80\x8d\x86\xf2\xe8\x1b\xa2\x90\x65\x33\xf3\x84\x3b\xca\xf6\xe3\xad\x3c\xd2\x68\xbd\x0a\x30\x25\x18\xab\xa1\x85\x4c\x44\x77\xed\x33\xa3\xf3\xf4\x6b\x35\xe8\x07\x3b\xf8\x29\x27\xf7\x16\x50\xe7\x5b\xa2\xed\xe0\xfe\xaf\x3c\x8a\x65\xda\x10\x65\xbe\x93\x04\x7f\x79\x78\x08\xb6\xaf\xf1\x2f\x49\x86\xb0\xd9\xbc\x07\x3b\x58\xbb\x97\x57\x63\xad\xfb\x56\x35\x7c\x2d\x84\xa9\x7e\x17\x1f\x17\xc0\x66\xe3\xbe\xa3\x03\x88\x15\x59\x15\x6f\xc9\xac\xa6\xfa\x6b\xb8\x4a\xa6\xfe\x51\x49\xf1\x31\xc9\x60\x34\x74\x1f\x68\xfd\x2f\x00\x00\xff\xff\x54\x5d\x1c\x74\x02\x28\x00\x00")

func pagesAssetsHtmlContainersHtmlBytes() ([]byte, error) {
	return bindataRead(
		_pagesAssetsHtmlContainersHtml,
		"pages/assets/html/containers.html",
	)
}

func pagesAssetsHtmlContainersHtml() (*asset, error) {
	bytes, err := pagesAssetsHtmlContainersHtmlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "pages/assets/html/containers.html", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0xb4, 0x1e, 0x16, 0x1, 0x57, 0xd, 0xd6, 0x83, 0xf, 0x58, 0xc6, 0x3, 0xf9, 0x97, 0xdc, 0x6, 0xdd, 0x50, 0xcf, 0x99, 0x35, 0xb8, 0xf4, 0x3f, 0x35, 0x37, 0xd5, 0xc0, 0xbf, 0x27, 0xc5, 0xb9}}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// AssetString returns the asset contents as a string (instead of a []byte).
func AssetString(name string) (string, error) {
	data, err := Asset(name)
	return string(data), err
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// MustAssetString is like AssetString but panics when Asset would return an
// error. It simplifies safe initialization of global variables.
func MustAssetString(name string) string {
	return string(MustAsset(name))
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetDigest returns the digest of the file with the given name. It returns an
// error if the asset could not be found or the digest could not be loaded.
func AssetDigest(name string) ([sha256.Size]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("AssetDigest %s can't read by error: %v", name, err)
		}
		return a.digest, nil
	}
	return [sha256.Size]byte{}, fmt.Errorf("AssetDigest %s not found", name)
}

// Digests returns a map of all known files and their checksums.
func Digests() (map[string][sha256.Size]byte, error) {
	mp := make(map[string][sha256.Size]byte, len(_bindata))
	for name := range _bindata {
		a, err := _bindata[name]()
		if err != nil {
			return nil, err
		}
		mp[name] = a.digest
	}
	return mp, nil
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"pages/assets/html/containers.html": pagesAssetsHtmlContainersHtml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"},
// AssetDir("data/img") would return []string{"a.png", "b.png"},
// AssetDir("foo.txt") and AssetDir("notexist") would return an error, and
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		canonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(canonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"pages": {nil, map[string]*bintree{
		"assets": {nil, map[string]*bintree{
			"html": {nil, map[string]*bintree{
				"containers.html": {pagesAssetsHtmlContainersHtml, map[string]*bintree{}},
			}},
		}},
	}},
}}

// RestoreAsset restores an asset under the given directory.
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	return os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
}

// RestoreAssets restores an asset under the given directory recursively.
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(canonicalName, "/")...)...)
}
