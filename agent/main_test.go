// Toolchain
// Copyright (c) 2026 AllSageTech
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildPodPatchRewritesKnownImagesOnly(t *testing.T) {
	raw := json.RawMessage(`{"metadata":{"labels":{}},"spec":{"containers":[{"image":"docker.io/library/nginx:1.27"},{"image":"example.test/untouched:1"}],"initContainers":[{"image":"busybox:1.37"}]}}`)
	mappings := map[string]string{
		"docker.io/library/nginx:1.27": "registry.example/nginx@sha256:abc",
		"busybox:1.37":                 "registry.example/busybox@sha256:def",
	}
	patch, err := buildPodPatch(raw, mappings, "all", "toolchain-registry")
	if err != nil {
		t.Fatal(err)
	}
	if len(patch) != 3 {
		t.Fatalf("expected two image replacements and one pull secret, got %d", len(patch))
	}
	if patch[0].Path != "/spec/containers/0/image" || patch[1].Path != "/spec/initContainers/0/image" {
		t.Fatalf("unexpected image patch paths: %#v", patch)
	}
	if patch[2].Path != "/spec/imagePullSecrets" {
		t.Fatalf("expected pull secret patch, got %#v", patch[2])
	}
}

func TestRegistryWriteAuthentication(t *testing.T) {
	if registryWriteMethod(http.MethodGet) || registryWriteMethod(http.MethodHead) || !registryWriteMethod(http.MethodPut) || !registryWriteMethod(http.MethodDelete) {
		t.Fatal("registry methods were classified incorrectly")
	}
	request := httptest.NewRequest(http.MethodPut, "http://registry.test/v2/repo/manifests/tag", nil)
	request.SetBasicAuth("toolchain-push", "secret")
	if !validBasicAuth(request, "toolchain-push", "secret") {
		t.Fatal("valid registry credentials were rejected")
	}
	if validBasicAuth(request, "toolchain-push", "different") {
		t.Fatal("invalid registry credentials were accepted")
	}
}

func TestBuildPodPatchHonorsMutationLabels(t *testing.T) {
	mapping := map[string]string{"a:1": "mirror/a:1"}
	ignored := json.RawMessage(`{"metadata":{"labels":{"toolchain.dev/agent":"ignore"}},"spec":{"containers":[{"image":"a:1"}]}}`)
	patch, err := buildPodPatch(ignored, mapping, "all", "")
	if err != nil || len(patch) != 0 {
		t.Fatalf("ignored pod was mutated: %#v, %v", patch, err)
	}
	unlabeled := json.RawMessage(`{"metadata":{"labels":{}},"spec":{"containers":[{"image":"a:1"}]}}`)
	patch, err = buildPodPatch(unlabeled, mapping, "labeled", "")
	if err != nil || len(patch) != 0 {
		t.Fatalf("unlabeled pod was mutated in labeled mode: %#v, %v", patch, err)
	}
	labeled := json.RawMessage(`{"metadata":{"labels":{"toolchain.dev/agent":"mutate"}},"spec":{"containers":[{"image":"a:1"}]}}`)
	patch, err = buildPodPatch(labeled, mapping, "labeled", "")
	if err != nil || len(patch) != 1 {
		t.Fatalf("labeled pod was not mutated: %#v, %v", patch, err)
	}
}

func TestReadMappingsRejectsUnsafeEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.json")
	if err := os.WriteFile(path, []byte(`{"source":"target with whitespace"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readMappings(path); err == nil {
		t.Fatal("expected an unsafe mapping to fail")
	}
}

func TestNewServerCertificateCoversServiceName(t *testing.T) {
	certificate, caPEM, err := newServerCertificate([]string{"toolchain-agent.toolchain-system.svc"})
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.Certificate) == 0 || len(caPEM) == 0 {
		t.Fatal("certificate material was not generated")
	}
}
