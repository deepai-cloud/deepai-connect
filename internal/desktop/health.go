package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type inspectState struct {
	Address, Phase string
	Ready          bool
	Peers          int
	LastSync       time.Time
	Expires        time.Time
}

func parseInspect(data []byte) (inspectState, error) {
	var state inspectState
	fields := strings.Fields(string(data))
	if len(fields) < 2 || fields[0] != "hub" {
		return state, errors.New("SSH destination is not an installed Connect hub")
	}
	values := map[string]string{}
	for _, field := range fields {
		if k, v, ok := strings.Cut(field, "="); ok {
			values[k] = v
		}
	}
	state.Address, state.Phase = values["address"], values["phase"]
	var err error
	if state.Ready, err = strconv.ParseBool(values["ready"]); err != nil {
		return state, errors.New("hub inspect output has no valid overlay readiness")
	}
	if state.Peers, err = strconv.Atoi(values["peers"]); err != nil || state.Peers < 0 {
		return state, errors.New("hub inspect output has no valid peer count")
	}
	if state.LastSync, err = time.Parse(time.RFC3339, values["last-sync"]); err != nil {
		return state, errors.New("hub inspect output has no valid last sync time")
	}
	if state.Expires, err = time.Parse(time.RFC3339, values["cache-expires"]); err != nil {
		return state, errors.New("hub inspect output has no valid cache expiry")
	}
	if state.Address == "" || state.Phase == "" {
		return state, errors.New("hub inspect output is missing installation metadata")
	}
	return state, nil
}

func (s inspectState) health(now time.Time) error {
	if s.Phase != "ready" {
		return fmt.Errorf("installation phase=%s; inspect the hub's Connect service logs", s.Phase)
	}
	if !s.Ready || !s.Expires.After(now) {
		return errors.New("overlay is not ready or its cache expired; inspect deepai-connect-agent.service on the hub")
	}
	if now.Sub(s.LastSync) > 2*time.Minute {
		return fmt.Errorf("coordinator sync is stale (%s ago); check the coordinator and mesh connectivity", now.Sub(s.LastSync).Round(time.Second))
	}
	return nil
}

func report(ctx context.Context, cfg Config, doctor bool, out io.Writer) error {
	fmt.Fprintf(out, "Hub: %s  API: https://%s:6443\n", cfg.Hub, cfg.OverlayIP)
	failures := 0
	check := func(name string, probe func(context.Context) (string, error)) {
		bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		detail, err := probe(bounded)
		if err != nil {
			failures++
			fmt.Fprintf(out, "FAIL %s: %v\n", name, err)
		} else {
			fmt.Fprintf(out, "PASS %s: %s\n", name, detail)
		}
	}
	check("mesh", func(ctx context.Context) (string, error) {
		data, err := captureRemote(ctx, cfg, "/usr/local/bin/deepai-connect", "inspect", "--dir", cfg.StateDir)
		if err != nil {
			return "", fmt.Errorf("hub inspection failed; check SSH and the Connect agent: %w", err)
		}
		s, err := parseInspect(data)
		if err != nil {
			return "", err
		}
		if s.Address != cfg.OverlayIP {
			return "", errors.New("hub address differs from saved configuration; run setup again")
		}
		if err = s.health(time.Now()); err != nil {
			return "", err
		}
		return fmt.Sprintf("address=%s peers=%d last-sync=%s cache-expires=%s", s.Address, s.Peers, s.LastSync.Format(time.RFC3339), s.Expires.Format(time.RFC3339)), nil
	})
	for _, unit := range []string{"deepai-connect-agent.service", "deepai-connect-k3s.service"} {
		check(unit, func(ctx context.Context) (string, error) {
			data, err := captureRemote(ctx, cfg, "systemctl", "is-active", unit)
			if err != nil || strings.TrimSpace(string(data)) != "active" {
				return "", fmt.Errorf("not active or unreachable; check journalctl -u %s on the hub", unit)
			}
			return "active", nil
		})
	}
	if doctor {
		check("Kubernetes API", func(ctx context.Context) (string, error) {
			data, err := captureKube(ctx, cfg, "get", "--raw=/readyz?verbose")
			if err != nil {
				return "", fmt.Errorf("readiness failed; inspect K3s and its overlay endpoint: %w", err)
			}
			if !strings.Contains(string(data), "readyz check passed") && strings.TrimSpace(string(data)) != "ok" {
				return "", errors.New("API returned an unexpected readiness response")
			}
			return "ready", nil
		})
	}
	check("nodes", func(ctx context.Context) (string, error) {
		data, err := captureKube(ctx, cfg, "get", "nodes", "-o", "json")
		if err != nil {
			return "", fmt.Errorf("cannot read nodes: %w", err)
		}
		return healthyNodes(data)
	})
	if doctor {
		check("system controllers", func(ctx context.Context) (string, error) {
			data, err := captureKube(ctx, cfg, "get", "deployments,daemonsets", "--all-namespaces", "-o", "json")
			if err != nil {
				return "", fmt.Errorf("cannot read system deployments and daemonsets: %w", err)
			}
			return healthyControllers(data)
		})
		check("system pods", func(ctx context.Context) (string, error) {
			data, err := captureKube(ctx, cfg, "get", "pods", "--all-namespaces", "-o", "json")
			if err != nil {
				return "", fmt.Errorf("cannot read pods: %w", err)
			}
			return healthyPods(data)
		})
	}
	if cfg.VM != "" {
		check("local VM "+cfg.VM, func(ctx context.Context) (string, error) {
			state, err := vmState(ctx, cfg.VM)
			if err != nil {
				return "", err
			}
			if state != "Running" {
				return "", fmt.Errorf("state=%s; start the worker with multipass start %s", state, cfg.VM)
			}
			return state, nil
		})
	}
	if failures != 0 {
		return fmt.Errorf("%d health check(s) failed", failures)
	}
	return nil
}

func healthyControllers(data []byte) (string, error) {
	var workloads struct {
		Items []struct {
			Kind     string
			Metadata struct {
				Name, Namespace string
				Generation      int64
			}
			Spec   struct{ Replicas *int }
			Status struct {
				ObservedGeneration                                   int64
				ReadyReplicas, AvailableReplicas, UpdatedReplicas    int
				DesiredNumberScheduled, NumberReady, NumberAvailable int
				UpdatedNumberScheduled                               int
			}
		}
	}
	if err := json.Unmarshal(data, &workloads); err != nil {
		return "", errors.New("invalid Kubernetes controller response")
	}
	expected := []string{
		"Deployment/deepai-system/connect-coordinator",
		"DaemonSet/deepai-system/connect-relay",
		"DaemonSet/deepai-system/connect-gateway",
		"Deployment/kube-system/coredns",
		"Deployment/kube-system/traefik",
	}
	found := make(map[string]bool, len(expected))
	for _, key := range expected {
		found[key] = false
	}
	var problems []string
	for _, w := range workloads.Items {
		key := w.Kind + "/" + w.Metadata.Namespace + "/" + w.Metadata.Name
		if _, required := found[key]; !required {
			continue
		}
		found[key] = true
		desired, ready, available, updated := 1, w.Status.ReadyReplicas, w.Status.AvailableReplicas, w.Status.UpdatedReplicas
		if w.Spec.Replicas != nil {
			desired = *w.Spec.Replicas
		}
		if w.Kind == "DaemonSet" {
			desired, ready, available, updated = w.Status.DesiredNumberScheduled, w.Status.NumberReady, w.Status.NumberAvailable, w.Status.UpdatedNumberScheduled
		}
		if desired < 1 || ready < desired || available < desired || updated < desired || w.Status.ObservedGeneration < w.Metadata.Generation {
			problems = append(problems, fmt.Sprintf("%s: desired=%d ready=%d available=%d updated=%d", key, desired, ready, available, updated))
		}
	}
	for _, key := range expected {
		if !found[key] {
			problems = append(problems, key+": missing")
		}
	}
	if len(problems) != 0 {
		return "", fmt.Errorf("%s; inspect deployments and daemonsets with deepai-connect kubectl", strings.Join(problems, "; "))
	}
	return "coordinator, relay, gateway, CoreDNS and Traefik available", nil
}

type condition struct {
	Type, Status, Reason string
}

func healthyNodes(data []byte) (string, error) {
	var nodes struct {
		Items []struct {
			Metadata struct{ Name string }
			Status   struct{ Conditions []condition }
		}
	}
	if err := json.Unmarshal(data, &nodes); err != nil {
		return "", errors.New("invalid Kubernetes node response")
	}
	if len(nodes.Items) == 0 {
		return "", errors.New("the cluster has no nodes")
	}
	var problems, names []string
	for _, n := range nodes.Items {
		ready := false
		for _, c := range n.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				ready = true
			}
			if c.Status == "True" && (c.Type == "DiskPressure" || c.Type == "MemoryPressure" || c.Type == "PIDPressure" || c.Type == "NetworkUnavailable") {
				problems = append(problems, n.Metadata.Name+": "+c.Type)
			}
		}
		if !ready {
			problems = append(problems, n.Metadata.Name+": not Ready")
		}
		names = append(names, n.Metadata.Name)
	}
	if len(problems) > 0 {
		return "", fmt.Errorf("%s; run deepai-connect kubectl describe node NAME", strings.Join(problems, "; "))
	}
	return fmt.Sprintf("%d Ready (%s)", len(names), strings.Join(names, ", ")), nil
}

func healthyPods(data []byte) (string, error) {
	var pods struct {
		Items []struct {
			Metadata struct{ Name, Namespace string }
			Status   struct {
				Phase      string
				Conditions []condition
			}
		}
	}
	if err := json.Unmarshal(data, &pods); err != nil {
		return "", errors.New("invalid Kubernetes pod response")
	}
	counts := map[string]int{"kube-system": 0, "deepai-system": 0}
	var problems []string
	for _, p := range pods.Items {
		if _, system := counts[p.Metadata.Namespace]; !system {
			continue
		}
		if p.Status.Phase == "Succeeded" {
			continue
		}
		counts[p.Metadata.Namespace]++
		ready := false
		for _, c := range p.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				ready = true
			}
		}
		if p.Status.Phase != "Running" || !ready {
			problems = append(problems, fmt.Sprintf("%s/%s: %s, ready=%t", p.Metadata.Namespace, p.Metadata.Name, p.Status.Phase, ready))
		}
	}
	for _, ns := range []string{"kube-system", "deepai-system"} {
		if counts[ns] == 0 {
			problems = append(problems, "no active pods in "+ns)
		}
	}
	if len(problems) > 0 {
		return "", fmt.Errorf("%s; use deepai-connect containers and deepai-connect logs", strings.Join(problems, "; "))
	}
	return fmt.Sprintf("%d Ready in kube-system and deepai-system", counts["kube-system"]+counts["deepai-system"]), nil
}

func vmState(ctx context.Context, name string) (string, error) {
	var out bytes.Buffer
	if err := runProcess(ctx, "multipass", []string{"info", "--format", "json", name}, nil, &out, io.Discard); err != nil {
		return "", fmt.Errorf("multipass info %s failed (install Multipass or check the VM): %w", name, err)
	}
	var info struct {
		Info map[string]struct{ State string }
	}
	if err := json.Unmarshal(out.Bytes(), &info); err != nil || info.Info[name].State == "" {
		return "", errors.New("Multipass returned no state for the configured VM")
	}
	return info.Info[name].State, nil
}
