package descriptor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"testing"

	// crypto libraries included for go-digest
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/opencontainers/go-digest"

	"github.com/regclient/regclient/types/errs"
	"github.com/regclient/regclient/types/mediatype"
	"github.com/regclient/regclient/types/platform"
)

func TestCompare(t *testing.T) {
	t.Parallel()
	digA := digest.FromString("test A")
	digB := digest.FromString("test B")
	tt := []struct {
		name        string
		d1, d2      Descriptor
		expectEqual bool
		expectSame  bool
	}{
		{
			name:        "empty",
			expectEqual: true,
			expectSame:  true,
		},
		{
			name: "empty d1",
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
			},
			expectEqual: false,
			expectSame:  false,
		},
		{
			name: "empty d2",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
			},
			expectEqual: false,
			expectSame:  false,
		},
		{
			name: "same simple manifest",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
			},
			expectEqual: true,
			expectSame:  true,
		},
		{
			name: "converting OCI media type",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
			},
			d2: Descriptor{
				MediaType: mediatype.OCI1Manifest,
				Size:      1234,
				Digest:    digA,
			},
			expectEqual: false,
			expectSame:  true,
		},
		{
			name: "different media type",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2ManifestList,
				Size:      1234,
				Digest:    digA,
			},
			expectEqual: false,
			expectSame:  false,
		},
		{
			name: "different size",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      4321,
				Digest:    digA,
			},
			expectEqual: false,
			expectSame:  false,
		},
		{
			name: "different digest",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digB,
			},
			expectEqual: false,
			expectSame:  false,
		},
		{
			name: "annotation eq",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				Annotations: map[string]string{
					"key a": "value a",
					"key b": "value b",
				},
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				Annotations: map[string]string{
					"key b": "value b",
					"key a": "value a",
				},
			},
			expectEqual: true,
			expectSame:  true,
		},
		{
			name: "annotation diff",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				Annotations: map[string]string{
					"key a": "value a",
					"key b": "value b",
				},
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				Annotations: map[string]string{
					"key a": "value c",
					"key d": "value b",
				},
			},
			expectEqual: false,
			expectSame:  true,
		},
		{
			name: "annotation missing",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				Annotations: map[string]string{
					"key a": "value a",
					"key b": "value b",
				},
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
			},
			expectEqual: false,
			expectSame:  true,
		},
		{
			name: "urls eq",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				URLs: []string{
					"url a",
					"url b",
				},
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				URLs: []string{
					"url a",
					"url b",
				},
			},
			expectEqual: true,
			expectSame:  true,
		},
		{
			name: "urls diff",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				URLs: []string{
					"url a",
					"url b",
				},
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				URLs: []string{
					"url c",
					"url d",
				},
			},
			expectEqual: false,
			expectSame:  true,
		},
		{
			name: "urls missing",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				URLs: []string{
					"url a",
					"url b",
				},
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
			},
			expectEqual: false,
			expectSame:  true,
		},
		{
			name: "platform eq",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				Platform: &platform.Platform{
					OS:           "linux",
					Architecture: "amd64",
				},
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				Platform: &platform.Platform{
					OS:           "linux",
					Architecture: "amd64",
				},
			},
			expectEqual: true,
			expectSame:  true,
		},
		{
			name: "platform diff",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				Platform: &platform.Platform{
					OS:           "linux",
					Architecture: "amd64",
				},
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				Platform: &platform.Platform{
					OS:           "linux",
					Architecture: "arm64",
				},
			},
			expectEqual: false,
			expectSame:  true,
		},
		{
			name: "platform missing",
			d1: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
				Platform: &platform.Platform{
					OS:           "linux",
					Architecture: "amd64",
				},
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
			},
			expectEqual: false,
			expectSame:  true,
		},
		{
			name: "artifactType eq",
			d1: Descriptor{
				MediaType:    mediatype.Docker2Manifest,
				Size:         1234,
				Digest:       digA,
				ArtifactType: "application/vnd.example.test",
			},
			d2: Descriptor{
				MediaType:    mediatype.Docker2Manifest,
				Size:         1234,
				Digest:       digA,
				ArtifactType: "application/vnd.example.test",
			},
			expectEqual: true,
			expectSame:  true,
		},
		{
			name: "artifactType diff",
			d1: Descriptor{
				MediaType:    mediatype.Docker2Manifest,
				Size:         1234,
				Digest:       digA,
				ArtifactType: "application/vnd.example.test",
			},
			d2: Descriptor{
				MediaType:    mediatype.Docker2Manifest,
				Size:         1234,
				Digest:       digA,
				ArtifactType: "application/vnd.example.test2",
			},
			expectEqual: false,
			expectSame:  true,
		},
		{
			name: "artifactType missing",
			d1: Descriptor{
				MediaType:    mediatype.Docker2Manifest,
				Size:         1234,
				Digest:       digA,
				ArtifactType: "application/vnd.example.test",
			},
			d2: Descriptor{
				MediaType: mediatype.Docker2Manifest,
				Size:      1234,
				Digest:    digA,
			},
			expectEqual: false,
			expectSame:  true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if tc.d1.Equal(tc.d2) != tc.expectEqual {
				t.Errorf("equal is not %v", tc.expectEqual)
			}
			if tc.d1.Same(tc.d2) != tc.expectSame {
				t.Errorf("same is not %v", tc.expectSame)
			}
		})
	}
}

func TestGetDataDescriptor(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name     string
		d        Descriptor
		wantData []byte
		wantErr  error
	}{
		{
			name: "No Data",
			d: Descriptor{
				MediaType: mediatype.Docker2LayerGzip,
				Size:      941,
				Digest:    digest.Digest("sha256:f6e2d7fa40092cf3d9817bf6ff54183d68d108a47fdf5a5e476c612626c80e14"),
			},
			wantErr: errs.ErrParsingFailed,
		},
		{
			name: "Bad Digest",
			d: Descriptor{
				MediaType: mediatype.OCI1LayerGzip,
				Size:      12,
				Digest:    digest.Digest("sha256:e4a380728755139f156563e8b795581d5915dcc947fe937c524c6d52fd604b99"),
				Data:      []byte("example data"),
			},
			wantErr: errs.ErrParsingFailed,
		},
		{
			name: "Bad Digest 512",
			d: Descriptor{
				MediaType: mediatype.OCI1LayerGzip,
				Size:      12,
				Digest:    digest.Digest("sha512:1239c5759a9ece516cec0c0623142d0e9fe70a27d750eee7fd38f4550d50addd873d0fa1a51fc823c1e3d5cada203f4a05d8325caacb7d3e0727a701f3f07e5f"),
				Data:      []byte("example data"),
			},
			wantErr: errs.ErrParsingFailed,
		},
		{
			name: "Bad Size",
			d: Descriptor{
				MediaType: mediatype.OCI1LayerGzip,
				Size:      1000,
				Digest:    digest.Digest("sha256:44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"),
				Data:      []byte("example data"),
			},
			wantErr: errs.ErrParsingFailed,
		},
		{
			name: "Good data",
			d: Descriptor{
				MediaType: mediatype.OCI1LayerGzip,
				Size:      12,
				Digest:    digest.Digest("sha256:44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"),
				Data:      []byte("example data"),
			},
			wantData: []byte("example data"),
		},
		{
			name: "Good data 512",
			d: Descriptor{
				MediaType: mediatype.OCI1LayerGzip,
				Size:      12,
				Digest:    digest.Digest("sha512:ed59c5759a9ece516cec0c0623142d0e9fe70a27d750eee7fd38f4550d50addd873d0fa1a51fc823c1e3d5cada203f4a05d8325caacb7d3e0727a701f3f07e5f"),
				Data:      []byte("example data"),
			},
			wantData: []byte("example data"),
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.d.GetData()
			if tc.wantErr != nil {
				if err == nil || (!errors.Is(err, tc.wantErr) && err.Error() != tc.wantErr.Error()) {
					t.Errorf("expected error %v, received %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Errorf("received error %v", err)
				return
			}
			if !bytes.Equal(out, tc.wantData) {
				t.Errorf("data mismatch, expected %s, received %s", string(tc.wantData), string(out))
			}
		})
	}
}

func TestGetDataJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		dJSON    []byte
		wantData []byte
		wantErr  error
	}{
		{
			name: "No Data",
			dJSON: []byte(`{
				"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
				"digest":    "sha256:f6e2d7fa40092cf3d9817bf6ff54183d68d108a47fdf5a5e476c612626c80e14",
				"size":      941
			}`),
			wantErr: errs.ErrParsingFailed,
		},
		{
			name: "Bad Data",
			dJSON: []byte(`{
				"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
				"digest":    "sha256:f6e2d7fa40092cf3d9817bf6ff54183d68d108a47fdf5a5e476c612626c80e14",
				"size":      1234,
				"data":      "Invalid data string"
			}`),
			wantErr: fmt.Errorf("illegal base64 data at input byte 7"),
		},
		{
			name: "Bad Digest",
			dJSON: []byte(`{
				"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
				"digest":    "sha256:e4a380728755139f156563e8b795581d5915dcc947fe937c524c6d52fd604b99",
				"size":      10,
				"data":      "ZXhhbXBsZSBkYXRh"
			}`),
			wantErr: errs.ErrParsingFailed,
		},
		{
			name: "Bad Size",
			dJSON: []byte(`{
				"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
				"digest":    "sha256:44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061",
				"size":      1000,
				"data":      "ZXhhbXBsZSBkYXRh"
			}`),
			wantErr: errs.ErrParsingFailed,
		},
		{
			name: "Good data",
			dJSON: []byte(`{
				"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
				"digest":    "sha256:44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061",
				"size":      12,
				"data":      "ZXhhbXBsZSBkYXRh"
			}`),
			wantData: []byte("example data"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := Descriptor{}
			err := json.Unmarshal(tt.dJSON, &desc)
			if err != nil {
				if tt.wantErr == nil {
					t.Errorf("failed to parse json: %v", err)
				} else if !errors.Is(err, tt.wantErr) && err.Error() != tt.wantErr.Error() {
					t.Errorf("expected error %v, received %v", tt.wantErr, err)
				}
				return
			}
			out, err := desc.GetData()
			if tt.wantErr != nil {
				if err == nil || (!errors.Is(err, tt.wantErr) && err.Error() != tt.wantErr.Error()) {
					t.Errorf("expected error %v, received %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("received error %v", err)
			}
			if !bytes.Equal(out, tt.wantData) {
				t.Errorf("data mismatch, expected %s, received %s", string(tt.wantData), string(out))
			}
		})
	}
}

func TestListSearch(t *testing.T) {
	t.Parallel()
	dAMD64 := Descriptor{
		MediaType: mediatype.OCI1Manifest,
		Size:      12345,
		Digest:    EmptyDigest,
		Platform: &platform.Platform{
			OS:           "linux",
			Architecture: "amd64",
		},
	}
	dAMD64Win := Descriptor{
		MediaType: mediatype.OCI1Manifest,
		Size:      12345,
		Digest:    EmptyDigest,
		Platform: &platform.Platform{
			OS:           "windows",
			Architecture: "amd64",
		},
	}
	dARM64 := Descriptor{
		MediaType: mediatype.OCI1Manifest,
		Size:      12345,
		Digest:    EmptyDigest,
		Platform: &platform.Platform{
			OS:           "linux",
			Architecture: "arm64",
		},
	}
	dAnnotations := Descriptor{
		MediaType: mediatype.OCI1Manifest,
		Size:      12345,
		Digest:    EmptyDigest,
		Platform: &platform.Platform{
			OS:           "linux",
			Architecture: "amd64",
		},
		Annotations: map[string]string{
			"runtime": "special runtime",
			"version": "1.2.3",
			"date":    "2022-01-01 12:34:56",
		},
	}
	dAnnotations2 := Descriptor{
		MediaType: mediatype.OCI1Manifest,
		Size:      12345,
		Digest:    EmptyDigest,
		Platform: &platform.Platform{
			OS:           "linux",
			Architecture: "amd64",
		},
		Annotations: map[string]string{
			"runtime": "special runtime",
			"version": "1.3.0",
			"date":    "2022-04-01 01:02:03",
		},
	}
	dArtifact := Descriptor{
		MediaType:    mediatype.OCI1Manifest,
		Size:         12345,
		Digest:       EmptyDigest,
		ArtifactType: "application/example.artifact",
		Annotations: map[string]string{
			"version": "1.2.3",
			"date":    "2022-01-01 12:34:56",
		},
	}
	dArtifact2 := Descriptor{
		MediaType:    mediatype.OCI1Manifest,
		Size:         12345,
		Digest:       EmptyDigest,
		ArtifactType: "application/example.artifact",
		Annotations: map[string]string{
			"version": "1.2.9",
			"date":    "2022-04-01 01:02:03",
			"unique":  "x",
		},
	}
	dArtifact3 := Descriptor{
		MediaType:    mediatype.OCI1Manifest,
		Size:         12345,
		Digest:       EmptyDigest,
		ArtifactType: "application/example.artifact",
		Annotations: map[string]string{
			"version": "1.3.0",
			"date":    "2022-02-28 02:04:08",
		},
	}
	testDL := []Descriptor{
		dAMD64,
		dARM64,
		dAMD64Win,
		dAnnotations,
		dAnnotations2,
		dArtifact,
		dArtifact2,
		dArtifact3,
	}
	tt := []struct {
		name   string
		dl     []Descriptor
		opt    MatchOpt
		expect Descriptor
		err    error
	}{
		{
			name: "empty",
			err:  errs.ErrNotFound,
		},
		{
			name: "amd64",
			dl:   testDL,
			opt: MatchOpt{
				Platform: &platform.Platform{
					OS:           "linux",
					Architecture: "amd64",
				},
			},
			expect: dAMD64,
		},
		{
			name: "amd64 compat",
			dl:   testDL,
			opt: MatchOpt{
				Platform: &platform.Platform{
					OS:           "darwin",
					Architecture: "amd64",
				},
			},
			expect: dAMD64,
		},
		{
			name: "amd64 windows",
			dl:   testDL,
			opt: MatchOpt{
				Platform: &platform.Platform{
					OS:           "windows",
					Architecture: "amd64",
				},
			},
			expect: dAMD64Win,
		},
		{
			name: "amd64 annotations",
			dl:   testDL,
			opt: MatchOpt{
				Annotations: map[string]string{
					"runtime": "special runtime",
				},
				Platform: &platform.Platform{
					OS:           "linux",
					Architecture: "amd64",
				},
			},
			expect: dAnnotations,
		},
		{
			name: "artifact missing",
			dl:   testDL,
			opt: MatchOpt{
				ArtifactType: "application/example.artifact",
				Platform: &platform.Platform{
					OS:           "linux",
					Architecture: "amd64",
				},
			},
			err: errs.ErrNotFound,
		},
		{
			name: "artifact",
			dl:   testDL,
			opt: MatchOpt{
				ArtifactType: "application/example.artifact",
				Annotations:  map[string]string{},
			},
			expect: dArtifact,
		},
		{
			name: "artifact sort",
			dl:   testDL,
			opt: MatchOpt{
				ArtifactType:   "application/example.artifact",
				Annotations:    map[string]string{},
				SortAnnotation: "date",
			},
			expect: dArtifact,
		},
		{
			name: "artifact sort desc",
			dl:   testDL,
			opt: MatchOpt{
				ArtifactType:   "application/example.artifact",
				Annotations:    map[string]string{},
				SortAnnotation: "date",
				SortDesc:       true,
			},
			expect: dArtifact2,
		},
		{
			name: "artifact sort unset",
			dl:   testDL,
			opt: MatchOpt{
				ArtifactType:   "application/example.artifact",
				Annotations:    map[string]string{},
				SortAnnotation: "unique",
			},
			expect: dArtifact2,
		},
		{
			name: "artifact sort unset desc",
			dl:   testDL,
			opt: MatchOpt{
				ArtifactType:   "application/example.artifact",
				Annotations:    map[string]string{},
				SortAnnotation: "unique",
				SortDesc:       true,
			},
			expect: dArtifact2,
		},
		{
			name: "artifact sort all unique desc",
			dl:   testDL,
			opt: MatchOpt{
				SortAnnotation: "unique",
				SortDesc:       true,
			},
			expect: dArtifact2,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			result, err := DescriptorListSearch(tc.dl, tc.opt)
			if tc.err != nil {
				if err == nil {
					t.Error("did not fail")
				} else if !errors.Is(err, tc.err) && err.Error() != tc.err.Error() {
					t.Errorf("unexpected error, expected %v, received %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error, received %v", err)
			}
			if !tc.expect.Equal(result) {
				t.Errorf("unexpected result, expected %v, received %v", tc.expect, result)
			}
		})
	}
}

func TestMatchOptMerge(t *testing.T) {
	tt := []struct {
		name    string
		orig    MatchOpt
		changes MatchOpt
		expect  MatchOpt
	}{
		{
			name: "empty",
		},
		{
			name:    "new ArtifactType",
			changes: MatchOpt{ArtifactType: "application/vnd.example.artifact"},
			expect:  MatchOpt{ArtifactType: "application/vnd.example.artifact"},
		},
		{
			name:    "add Platform",
			orig:    MatchOpt{ArtifactType: "application/vnd.example.artifact"},
			changes: MatchOpt{Platform: &platform.Platform{OS: "linux", Architecture: "amd64"}},
			expect: MatchOpt{
				ArtifactType: "application/vnd.example.artifact",
				Platform:     &platform.Platform{OS: "linux", Architecture: "amd64"},
			},
		},
		{
			name: "add Annotations",
			orig: MatchOpt{
				ArtifactType: "application/vnd.example.artifact",
				Platform:     &platform.Platform{OS: "linux", Architecture: "amd64"},
			},
			changes: MatchOpt{
				Annotations: map[string]string{
					"annotation1": "value1",
					"annotation2": "value2",
				},
			},
			expect: MatchOpt{
				ArtifactType: "application/vnd.example.artifact",
				Platform:     &platform.Platform{OS: "linux", Architecture: "amd64"},
				Annotations: map[string]string{
					"annotation1": "value1",
					"annotation2": "value2",
				},
			},
		},
		{
			name: "add SortAnnotation and desc",
			orig: MatchOpt{
				ArtifactType: "application/vnd.example.artifact",
				Platform:     &platform.Platform{OS: "linux", Architecture: "amd64"},
				Annotations: map[string]string{
					"annotation1": "value1",
					"annotation2": "value2",
				},
			},
			changes: MatchOpt{
				SortAnnotation: "annotationSort",
				SortDesc:       true,
			},
			expect: MatchOpt{
				ArtifactType: "application/vnd.example.artifact",
				Platform:     &platform.Platform{OS: "linux", Architecture: "amd64"},
				Annotations: map[string]string{
					"annotation1": "value1",
					"annotation2": "value2",
				},
				SortAnnotation: "annotationSort",
				SortDesc:       true,
			},
		},
		{
			name: "add third annotation",
			orig: MatchOpt{
				ArtifactType: "application/vnd.example.artifact",
				Platform:     &platform.Platform{OS: "linux", Architecture: "amd64"},
				Annotations: map[string]string{
					"annotation1": "value1",
					"annotation2": "value2",
				},
				SortAnnotation: "annotationSort",
				SortDesc:       true,
			},
			changes: MatchOpt{
				Annotations: map[string]string{
					"annotation3": "value3",
				},
			},
			expect: MatchOpt{
				ArtifactType: "application/vnd.example.artifact",
				Platform:     &platform.Platform{OS: "linux", Architecture: "amd64"},
				Annotations: map[string]string{
					"annotation1": "value1",
					"annotation2": "value2",
					"annotation3": "value3",
				},
				SortAnnotation: "annotationSort",
				SortDesc:       true,
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.orig.Merge(tc.changes)
			if result.ArtifactType != tc.expect.ArtifactType {
				t.Errorf("ArtifactType mismatch, expected %s, received %s", tc.expect.ArtifactType, result.ArtifactType)
			}
			if result.Platform == nil || tc.expect.Platform == nil {
				if result.Platform != tc.expect.Platform {
					t.Errorf("Platform mismatch, expected %v, received %v", tc.expect.Platform, result.Platform)
				}
			} else if result.Platform.String() != tc.expect.Platform.String() {
				t.Errorf("Platform mismatch, expected %s, received %s", tc.expect.Platform.String(), result.Platform.String())
			}
			if result.SortAnnotation != tc.expect.SortAnnotation {
				t.Errorf("SortAnnotation mismatch, expected %s, received %s", tc.expect.SortAnnotation, result.SortAnnotation)
			}
			if result.SortDesc != tc.expect.SortDesc {
				t.Errorf("SortDesc mismatch, expected %t, received %t", tc.expect.SortDesc, result.SortDesc)
			}
			if !maps.Equal(result.Annotations, tc.expect.Annotations) {
				t.Errorf("Annotations mismatch, expected %v, received %v", tc.expect.Annotations, result.Annotations)
			}
		})
	}
}

func TestDigestAlgorithm(t *testing.T) {
	dig256 := digest.SHA256.FromString("hello world")
	dig512 := digest.SHA512.FromString("hello world")
	digInvalidHash := digest.Digest("sha512:1234")
	digInvalidFormat := digest.Digest("unknown")
	digInvalidAlgorithm := digest.Digest("sha123:123412341234")
	tt := []struct {
		name         string
		d            Descriptor
		setPref      digest.Algorithm
		expectSetErr error
		expectAlgo   digest.Algorithm
	}{
		{
			name:       "empty",
			d:          Descriptor{},
			expectAlgo: digest.Canonical,
		},
		{
			name: "valid-sha256",
			d: Descriptor{
				Digest: dig256,
			},
			expectAlgo: digest.SHA256,
		},
		{
			name: "valid-sha512",
			d: Descriptor{
				Digest: dig512,
			},
			expectAlgo: digest.SHA512,
		},
		{
			name: "invalid-hash",
			d: Descriptor{
				Digest: digInvalidHash,
			},
			expectAlgo: digest.Canonical,
		},
		{
			name: "invalid-format",
			d: Descriptor{
				Digest: digInvalidFormat,
			},
			expectAlgo: digest.Canonical,
		},
		{
			name: "invalid-algorithm",
			d: Descriptor{
				Digest: digInvalidAlgorithm,
			},
			expectAlgo: digest.Canonical,
		},
		{
			name:       "empty-prefer-512",
			d:          Descriptor{},
			setPref:    digest.SHA512,
			expectAlgo: digest.SHA512,
		},
		{
			name: "valid-sha256-prefer-512",
			d: Descriptor{
				Digest: dig256,
			},
			setPref:    digest.SHA512,
			expectAlgo: digest.SHA256,
		},
		{
			name:         "empty-set-invalid",
			d:            Descriptor{},
			setPref:      digest.Algorithm("invalid"),
			expectSetErr: errs.ErrUnsupported,
			expectAlgo:   digest.Canonical,
		},
		{
			name: "invalid-hash-failed-set",
			d: Descriptor{
				Digest: digInvalidHash,
			},
			setPref:      digest.Algorithm("invalid"),
			expectSetErr: errs.ErrUnsupported,
			expectAlgo:   digest.Canonical,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setPref != "" {
				err := tc.d.DigestAlgoPrefer(tc.setPref)
				if tc.expectSetErr != nil {
					if err == nil {
						t.Errorf("setting preferred algorithm to %s did not fail, expected %v", tc.setPref, tc.expectSetErr)
					} else if !errors.Is(err, tc.expectSetErr) && err.Error() != tc.expectSetErr.Error() {
						t.Errorf("unexpected error, expected %v, received %v", tc.expectSetErr, err)
					}
				} else if err != nil {
					t.Errorf("failed to set preferred algorithm: %v", err)
				}
			}
			algo := tc.d.DigestAlgo()
			if algo != tc.expectAlgo {
				t.Errorf("expected %s, received %s", tc.expectAlgo.String(), algo.String())
			}
		})
	}
}
