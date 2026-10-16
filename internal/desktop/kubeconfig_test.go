package desktop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func testRemoteKubeconfig() kubeDocument {
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	return kubeDocument{
		"apiVersion": "v1", "kind": "Config", "current-context": "default",
		"clusters": []any{map[string]any{"name": "default", "cluster": map[string]any{"server": "https://100.96.0.1:6443", "certificate-authority-data": encode("TEST-CA")}}},
		"users":    []any{map[string]any{"name": "default", "user": map[string]any{"client-certificate-data": encode("TEST-CERT"), "client-key-data": encode("SECRET-KEY")}}},
		"contexts": []any{map[string]any{"name": "default", "context": map[string]any{"cluster": "default", "user": "default"}}},
	}
}

func testKubeClient() Config {
	return Config{Hub: "root@hub.example", StateDir: "/var/lib/deepai-connect", OverlayIP: "100.96.0.1"}
}

func managedTestKubeconfig(t *testing.T) kubeDocument {
	t.Helper()
	doc, err := desktopKubeconfig(testRemoteKubeconfig(), testKubeClient(), "deepai-connect", defaultTunnelPort, false)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestDesktopKubeconfigUsesVerifiedLoopbackTLS(t *testing.T) {
	remote := testRemoteKubeconfig()
	remote["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)["proxy-url"] = "http://untrusted"
	remote["users"].([]any)[0].(map[string]any)["user"].(map[string]any)["exec"] = map[string]any{"command": "untrusted"}
	for _, direct := range []bool{false, true} {
		doc, err := desktopKubeconfig(remote, testKubeClient(), "laptop", 16443, direct)
		if err != nil {
			t.Fatal(err)
		}
		cluster := doc["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)
		want := "https://127.0.0.1:16443"
		if direct {
			want = "https://100.96.0.1:6443"
		}
		if cluster["server"] != want || cluster["tls-server-name"] != "100.96.0.1" || cluster["certificate-authority-data"] == nil {
			t.Fatalf("wrong verified endpoint: %v", cluster)
		}
		user := doc["users"].([]any)[0].(map[string]any)["user"].(map[string]any)
		if user["exec"] != nil || cluster["proxy-url"] != nil || cluster["insecure-skip-tls-verify"] != nil {
			t.Fatal("unsafe transport/auth options copied from hub")
		}
	}
}

func TestDesktopKubeconfigRejectsInsecureOrIncompleteCredentials(t *testing.T) {
	for _, problem := range []string{"insecure", "missing-ca", "file-key", "context-mismatch"} {
		t.Run(problem, func(t *testing.T) {
			remote := testRemoteKubeconfig()
			cluster := remote["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)
			user := remote["users"].([]any)[0].(map[string]any)["user"].(map[string]any)
			switch problem {
			case "insecure":
				cluster["insecure-skip-tls-verify"] = true
			case "missing-ca":
				delete(cluster, "certificate-authority-data")
			case "file-key":
				delete(user, "client-key-data")
				user["client-key"] = "/hub/secret.key"
			case "context-mismatch":
				remote["current-context"] = "missing"
			}
			if _, err := desktopKubeconfig(remote, testKubeClient(), "test", 16443, false); err == nil {
				t.Fatal("unsafe or incomplete kubeconfig accepted")
			}
		})
	}
}

func TestMergeKubeconfigPreservesOtherContextsAndCurrentSelection(t *testing.T) {
	existing := testRemoteKubeconfig()
	existing["extensions"] = []any{map[string]any{"name": "existing", "extension": map[string]any{"keep": true}}}
	original, _ := json.Marshal(existing)
	managed := managedTestKubeconfig(t)
	merged, err := mergeKubeconfig(existing, managed, "deepai-connect", false)
	if err != nil {
		t.Fatal(err)
	}
	if merged["current-context"] != "default" || !reflect.DeepEqual(existing["extensions"], merged["extensions"]) {
		t.Fatal("existing preferences changed")
	}
	for _, key := range []string{"clusters", "users", "contexts"} {
		entries := merged[key].([]any)
		if len(entries) != 2 || !reflect.DeepEqual(entries[0], existing[key].([]any)[0]) {
			t.Fatalf("existing %s not preserved", key)
		}
	}
	unchanged, _ := json.Marshal(existing)
	if !bytes.Equal(original, unchanged) {
		t.Fatal("merge mutated its input")
	}
	merged["contexts"].([]any)[1].(map[string]any)["context"].(map[string]any)["namespace"] = "workloads"
	refreshed, err := mergeKubeconfig(merged, managedTestKubeconfig(t), "deepai-connect", true)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed["current-context"] != "deepai-connect" || len(refreshed["contexts"].([]any)) != 2 || refreshed["contexts"].([]any)[1].(map[string]any)["context"].(map[string]any)["namespace"] != "workloads" {
		t.Fatal("repeat installation duplicated contexts or lost namespace/selection")
	}
}

func TestMergeKubeconfigRejectsNameCollisions(t *testing.T) {
	for key, inner := range map[string]string{"clusters": "cluster", "users": "user", "contexts": "context"} {
		t.Run(key, func(t *testing.T) {
			existing := testRemoteKubeconfig()
			existing[key] = []any{map[string]any{"name": "deepai-connect", inner: map[string]any{}}}
			before, _ := json.Marshal(existing)
			if _, err := mergeKubeconfig(existing, managedTestKubeconfig(t), "deepai-connect", false); err == nil {
				t.Fatal("unmanaged collision accepted")
			}
			after, _ := json.Marshal(existing)
			if !bytes.Equal(before, after) {
				t.Fatal("failed merge changed original")
			}
		})
	}
	otherHub := managedTestKubeconfig(t)
	otherHub["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)["extensions"].([]any)[0].(map[string]any)["extension"].(map[string]any)["hub"] = "root@other.example"
	if _, err := mergeKubeconfig(otherHub, managedTestKubeconfig(t), "deepai-connect", false); err == nil {
		t.Fatal("different hub ownership accepted")
	}
}

func TestMergeKubeconfigPreservesUnsetCurrentContext(t *testing.T) {
	for _, absent := range []bool{false, true} {
		existing := testRemoteKubeconfig()
		existing["current-context"] = ""
		if absent {
			delete(existing, "current-context")
		}
		merged, err := mergeKubeconfig(existing, managedTestKubeconfig(t), "deepai-connect", false)
		if err != nil {
			t.Fatal(err)
		}
		current, present := merged["current-context"]
		if present == absent || (present && current != "") {
			t.Fatal("an unselected existing configuration was switched to the new context")
		}
	}
}

func TestKubeconfigDestinationSelection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", "")
	path, err := kubeconfigPath("")
	if err != nil || path != filepath.Join(home, ".kube", "config") {
		t.Fatalf("unexpected default path: %q, %v", path, err)
	}
	t.Setenv("KUBECONFIG", filepath.Join(home, "one")+string(os.PathListSeparator)+filepath.Join(home, "two"))
	if _, err := kubeconfigPath(""); err == nil {
		t.Fatal("multiple KUBECONFIG targets silently accepted")
	}
	if path, err := kubeconfigPath(filepath.Join(home, "chosen")); err != nil || path != filepath.Join(home, "chosen") {
		t.Fatal("explicit output did not override KUBECONFIG")
	}
	if _, err := kubeconfigPath("-"); err == nil {
		t.Fatal("credential output to terminal permitted")
	}
}

func TestKubeconfigAtomicWritePermissionsAndConcurrentChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config")
	if err := writeKubeconfigFile(path, []byte("initial"), nil, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("kubeconfig is not private")
	}
	if err := writeKubeconfigFile(path, []byte("replacement"), []byte("stale"), true); err == nil {
		t.Fatal("concurrent change overwritten")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "initial" {
		t.Fatal("destination changed on failure")
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readKubeconfigFile(link); err == nil {
		t.Fatal("symlink destination accepted")
	}
}

func TestTunnelBindsOnlyLoopbackAndRetainsSSHVerification(t *testing.T) {
	args, err := tunnelArgs(testKubeClient(), 16443)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-N", "127.0.0.1:16443:100.96.0.1:6443", "ExitOnForwardFailure=yes", "ServerAliveInterval=30", "BatchMode=yes", "ConnectTimeout=10"} {
		if !slices.Contains(args, want) {
			t.Fatalf("missing tunnel option %q", want)
		}
	}
	if strings.Contains(strings.Join(args, " "), "StrictHostKeyChecking") || args[len(args)-1] != "root@hub.example" {
		t.Fatal("SSH verification or destination changed")
	}
	for _, port := range []int{0, 443, 65536} {
		if _, err := tunnelArgs(testKubeClient(), port); err == nil {
			t.Fatalf("unsafe port %d accepted", port)
		}
	}
}

func TestKubeconfigFailureDoesNotRevealRemoteCredentials(t *testing.T) {
	t.Setenv("DEEPAI_CONNECT_CONFIG", filepath.Join(t.TempDir(), "client.json"))
	if err := saveConfig(testKubeClient()); err != nil {
		t.Fatal(err)
	}
	old := runProcess
	t.Cleanup(func() { runProcess = old })
	runProcess = func(_ context.Context, _ string, _ []string, _ io.Reader, stdout, stderr io.Writer) error {
		io.WriteString(stdout, "PRIVATE-KEY-SECRET")
		io.WriteString(stderr, "PRIVATE-KEY-SECRET")
		return errors.New("PRIVATE-KEY-SECRET")
	}
	path := filepath.Join(t.TempDir(), "config")
	err := runKubeconfig(context.Background(), []string{"export", "--out", path})
	if err == nil || strings.Contains(err.Error(), "PRIVATE-KEY-SECRET") {
		t.Fatalf("remote credential leak: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed export created a destination")
	}
}

func TestInstallKubeconfigFlattensFilesWithoutExecutingAuthPlugin(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl is not installed")
	}
	dir := t.TempDir()
	t.Setenv("DEEPAI_CONNECT_CONFIG", filepath.Join(dir, "client.json"))
	if err := saveConfig(testKubeClient()); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "plugin-ran")
	plugin := filepath.Join(dir, "auth-plugin")
	if err := os.WriteFile(plugin, []byte("#!/bin/sh\ntouch '"+marker+"'\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("EXISTING-CA"), 0600); err != nil {
		t.Fatal(err)
	}
	existing := testRemoteKubeconfig()
	cluster := existing["clusters"].([]any)[0].(map[string]any)["cluster"].(map[string]any)
	delete(cluster, "certificate-authority-data")
	cluster["certificate-authority"] = "ca.pem"
	existing["users"] = []any{map[string]any{"name": "default", "user": map[string]any{"exec": map[string]any{"apiVersion": "client.authentication.k8s.io/v1", "command": plugin, "interactiveMode": "Never"}}}}
	path := filepath.Join(dir, "config")
	raw, _ := json.Marshal(existing)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	old := runProcess
	t.Cleanup(func() { runProcess = old })
	runProcess = func(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
		if name == "ssh" {
			data, _ := json.Marshal(testRemoteKubeconfig())
			_, err := stdout.Write(data)
			return err
		}
		return execProcess(ctx, name, args, stdin, stdout, stderr)
	}
	for range 2 {
		if err := runKubeconfig(context.Background(), []string{"install", "--out", path}); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(path)
	installed, err := decodeKubeconfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if installed["current-context"] != "default" || len(installed["contexts"].([]any)) != 2 {
		t.Fatal("repeated installation lost the current context or duplicated entries")
	}
	for _, raw := range installed["clusters"].([]any) {
		entry := raw.(map[string]any)
		if entry["name"] == "default" {
			body := entry["cluster"].(map[string]any)
			if body["certificate-authority"] != nil || body["certificate-authority-data"] != base64.StdEncoding.EncodeToString([]byte("EXISTING-CA")) {
				t.Fatal("existing relative CA reference was not flattened")
			}
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("credential plugin executed during config view")
	}
	malformed := []byte("apiVersion: [ PRIVATE-KEY-SECRET")
	if err := os.WriteFile(path, malformed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runKubeconfig(context.Background(), []string{"install", "--out", path}); err == nil || strings.Contains(err.Error(), "PRIVATE-KEY-SECRET") {
		t.Fatalf("malformed config accepted or exposed: %v", err)
	}
	remaining, _ := os.ReadFile(path)
	if !bytes.Equal(remaining, malformed) {
		t.Fatal("malformed existing file was overwritten")
	}
}
