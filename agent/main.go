// Toolchain
// Copyright (c) 2026 AllSageTech
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const (
	maxAdmissionBody = 4 << 20
	agentLabel       = "toolchain.dev/agent"
)

type admissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *admissionRequest  `json:"request,omitempty"`
	Response   *admissionResponse `json:"response,omitempty"`
}

type admissionRequest struct {
	UID       string          `json:"uid"`
	Namespace string          `json:"namespace"`
	Object    json.RawMessage `json:"object"`
}

type admissionResponse struct {
	UID       string          `json:"uid"`
	Allowed   bool            `json:"allowed"`
	Patch     json.RawMessage `json:"patch,omitempty"`
	PatchType *string         `json:"patchType,omitempty"`
	Status    *status         `json:"status,omitempty"`
}

type status struct {
	Message string `json:"message"`
}

type pod struct {
	Metadata struct {
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		Containers          []container      `json:"containers"`
		InitContainers      []container      `json:"initContainers"`
		EphemeralContainers []container      `json:"ephemeralContainers"`
		ImagePullSecrets    []localObjectRef `json:"imagePullSecrets"`
	} `json:"spec"`
}

type container struct {
	Image string `json:"image"`
}

type localObjectRef struct {
	Name string `json:"name"`
}

type patchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

type agent struct {
	mappingsPath string
	policy       string
	pullSecret   string
	ready        atomic.Bool
}

func main() {
	switch getenv("TOOLCHAIN_MODE", "admission") {
	case "admission":
		runAdmission()
	case "registry-gateway":
		runRegistryGateway()
	default:
		log.Fatal("TOOLCHAIN_MODE must be admission or registry-gateway")
	}
}

func runAdmission() {
	a := &agent{
		mappingsPath: getenv("TOOLCHAIN_MAPPINGS_PATH", "/etc/toolchain-agent/mappings.json"),
		policy:       getenv("TOOLCHAIN_MUTATION_POLICY", "all"),
		pullSecret:   os.Getenv("TOOLCHAIN_PULL_SECRET"),
	}
	if a.policy != "all" && a.policy != "labeled" {
		log.Fatalf("invalid TOOLCHAIN_MUTATION_POLICY %q", a.policy)
	}

	certificate, caPEM, err := newServerCertificate([]string{
		"toolchain-agent",
		"toolchain-agent.toolchain-system",
		"toolchain-agent.toolchain-system.svc",
	})
	if err != nil {
		log.Fatalf("generate webhook certificate: %v", err)
	}

	listener, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", a.handleMutate)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !a.ready.Load() {
			http.Error(w, "webhook trust is not established", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	go a.establishWebhookTrust(caPEM)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("Toolchain admission agent listening on :8443")
	if err := server.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
}

func runRegistryGateway() {
	upstream, err := url.Parse(getenv("TOOLCHAIN_REGISTRY_UPSTREAM", "http://toolchain-registry.toolchain-system.svc:5000"))
	if err != nil || upstream.Scheme != "http" || upstream.Host == "" || upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" {
		log.Fatal("TOOLCHAIN_REGISTRY_UPSTREAM must be a plain HTTP origin without credentials, query, or fragment")
	}
	username := os.Getenv("TOOLCHAIN_REGISTRY_USERNAME")
	password := os.Getenv("TOOLCHAIN_REGISTRY_PASSWORD")
	if username == "" || password == "" {
		log.Fatal("registry gateway credentials are required")
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, proxyErr error) {
		log.Printf("registry upstream: %v", proxyErr)
		http.Error(w, "registry upstream unavailable", http.StatusBadGateway)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			request, requestErr := http.NewRequestWithContext(r.Context(), http.MethodGet, upstream.String()+"/v2/", nil)
			if requestErr != nil {
				http.Error(w, "registry upstream unavailable", http.StatusServiceUnavailable)
				return
			}
			response, requestErr := (&http.Client{Transport: proxy.Transport, Timeout: 5 * time.Second}).Do(request)
			if requestErr != nil {
				http.Error(w, "registry upstream unavailable", http.StatusServiceUnavailable)
				return
			}
			response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode >= 400 {
				http.Error(w, "registry upstream unavailable", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path != "/v2/" && !strings.HasPrefix(r.URL.Path, "/v2/") {
			http.NotFound(w, r)
			return
		}
		if registryWriteMethod(r.Method) && !validBasicAuth(r, username, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Toolchain registry"`)
			http.Error(w, "registry write authentication required", http.StatusUnauthorized)
			return
		}
		proxy.ServeHTTP(w, r)
	})
	server := &http.Server{
		Addr:              ":5000",
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("Toolchain registry gateway listening on :5000")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve registry gateway: %v", err)
	}
}

func registryWriteMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func validBasicAuth(r *http.Request, expectedUsername, expectedPassword string) bool {
	username, password, ok := r.BasicAuth()
	if !ok {
		return false
	}
	usernameMatches := subtle.ConstantTimeCompare([]byte(username), []byte(expectedUsername)) == 1
	passwordMatches := subtle.ConstantTimeCompare([]byte(password), []byte(expectedPassword)) == 1
	return usernameMatches && passwordMatches
}

func getenv(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func (a *agent) handleMutate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAdmissionBody))
	if err != nil {
		http.Error(w, "invalid admission request", http.StatusBadRequest)
		return
	}
	var review admissionReview
	if err := json.Unmarshal(body, &review); err != nil || review.Request == nil {
		http.Error(w, "invalid AdmissionReview", http.StatusBadRequest)
		return
	}

	response := &admissionResponse{UID: review.Request.UID, Allowed: true}
	mappings, err := readMappings(a.mappingsPath)
	if err == nil {
		var operations []patchOperation
		operations, err = buildPodPatch(review.Request.Object, mappings, a.policy, a.pullSecret)
		if err == nil && len(operations) > 0 {
			patch, marshalErr := json.Marshal(operations)
			if marshalErr != nil {
				err = marshalErr
			} else {
				patchType := "JSONPatch"
				response.PatchType = &patchType
				response.Patch = patch
			}
		}
	}
	if err != nil {
		response.Allowed = false
		response.Status = &status{Message: err.Error()}
	}

	w.Header().Set("Content-Type", "application/json")
	result := admissionReview{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview", Response: response}
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("write AdmissionReview response: %v", err)
	}
}

func readMappings(path string) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read image mappings: %w", err)
	}
	var mappings map[string]string
	if err := json.Unmarshal(data, &mappings); err != nil {
		return nil, fmt.Errorf("parse image mappings: %w", err)
	}
	for source, target := range mappings {
		if strings.TrimSpace(source) == "" || strings.TrimSpace(target) == "" || strings.ContainsAny(source+target, "\r\n\t ") {
			return nil, fmt.Errorf("invalid image mapping")
		}
	}
	return mappings, nil
}

func buildPodPatch(raw json.RawMessage, mappings map[string]string, policy, pullSecret string) ([]patchOperation, error) {
	var object pod
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("parse Pod: %w", err)
	}
	label := object.Metadata.Labels[agentLabel]
	if label == "ignore" || (policy == "labeled" && label != "mutate") {
		return nil, nil
	}

	operations := make([]patchOperation, 0)
	changed := false
	groups := []struct {
		path       string
		containers []container
	}{
		{path: "/spec/containers", containers: object.Spec.Containers},
		{path: "/spec/initContainers", containers: object.Spec.InitContainers},
		{path: "/spec/ephemeralContainers", containers: object.Spec.EphemeralContainers},
	}
	for _, group := range groups {
		for index, item := range group.containers {
			if target, ok := mappings[item.Image]; ok && target != item.Image {
				operations = append(operations, patchOperation{Op: "replace", Path: fmt.Sprintf("%s/%d/image", group.path, index), Value: target})
				changed = true
			}
		}
	}
	if changed && pullSecret != "" {
		for _, secret := range object.Spec.ImagePullSecrets {
			if secret.Name == pullSecret {
				return operations, nil
			}
		}
		secret := localObjectRef{Name: pullSecret}
		if object.Spec.ImagePullSecrets == nil {
			operations = append(operations, patchOperation{Op: "add", Path: "/spec/imagePullSecrets", Value: []localObjectRef{secret}})
		} else {
			operations = append(operations, patchOperation{Op: "add", Path: "/spec/imagePullSecrets/-", Value: secret})
		}
	}
	return operations, nil
}

func newServerCertificate(dnsNames []string) (tls.Certificate, []byte, error) {
	now := time.Now().UTC()
	caKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "Toolchain Admission CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "toolchain-agent.toolchain-system.svc"},
		DNSNames:     dnsNames,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return certificate, caPEM, nil
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(err)
	}
	return serial
}

func (a *agent) establishWebhookTrust(caPEM []byte) {
	established := false
	for {
		if err := patchWebhook(context.Background(), caPEM); err != nil {
			log.Printf("establish webhook trust: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if !established {
			a.ready.Store(true)
			log.Printf("webhook trust established; failure policy is Fail")
			established = true
		}
		time.Sleep(30 * time.Second)
	}
}

func patchWebhook(ctx context.Context, caPEM []byte) error {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := getenv("KUBERNETES_SERVICE_PORT_HTTPS", "443")
	if host == "" {
		return errors.New("KUBERNETES_SERVICE_HOST is not set")
	}
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	clusterCA, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil || !roots.AppendCertsFromPEM(clusterCA) {
		return errors.New("load Kubernetes service CA")
	}
	operations := []patchOperation{
		{Op: "replace", Path: "/webhooks/0/clientConfig/caBundle", Value: base64.StdEncoding.EncodeToString(caPEM)},
		{Op: "replace", Path: "/webhooks/0/failurePolicy", Value: "Fail"},
	}
	body, _ := json.Marshal(operations)
	url := fmt.Sprintf("https://%s:%s/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/toolchain-agent", host, port)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json-patch+json")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("Kubernetes API returned %s: %s", resp.Status, strings.TrimSpace(string(message)))
	}
	return nil
}
