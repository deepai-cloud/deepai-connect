package cluster

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const serviceLeaseName = "connect-services-reconcile"
const serviceRegistryExtension = "cluster-services-v1"
const serviceLeaseDuration = 60 * time.Second

// Kubernetes Lease timestamps use metav1.MicroTime, whose decoder requires
// exactly six fractional digits. time.Time's RFC3339Nano JSON encoding is not
// compatible, even after truncation when the last microsecond digit is zero.
type leaseTime struct{ time.Time }

func (t leaseTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.UTC().Format("2006-01-02T15:04:05.000000Z07:00"))
}

type servicesLease struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		ResourceVersion string `json:"resourceVersion,omitempty"`
	} `json:"metadata"`
	Spec struct {
		HolderIdentity       string     `json:"holderIdentity"`
		LeaseDurationSeconds int        `json:"leaseDurationSeconds"`
		AcquireTime          *leaseTime `json:"acquireTime,omitempty"`
		RenewTime            *leaseTime `json:"renewTime,omitempty"`
		LeaseTransitions     int        `json:"leaseTransitions"`
	} `json:"spec"`
}

// ApplyRegisteredServices serializes service reconciliation across hubs. It
// reloads the latest durable desired configuration after acquiring the Lease,
// preventing a slow publisher from applying a stale manifest over a new hub.
// NetworkState changes can continue while the lease is held: their writers then
// acquire the same lease and reconcile the newest state after this holder exits.
func (m *Manager) ApplyRegisteredServices(ctx context.Context) error {
	if m.Config.Role != "hub" {
		return errors.New("only hubs can reconcile cluster services")
	}
	return m.withServicesLease(ctx, func(held context.Context) error {
		data, err := m.kubectl(held, nil, "-n", Namespace, "get", "networkstate", "default", "-o", "json")
		if err != nil {
			return err
		}
		var resource struct {
			Spec struct {
				Extensions map[string]json.RawMessage `json:"extensions"`
			} `json:"spec"`
		}
		if err = json.Unmarshal(data, &resource); err != nil {
			return errors.New("invalid durable service registry")
		}
		var desired ServiceConfig
		if err = json.Unmarshal(resource.Spec.Extensions[serviceRegistryExtension], &desired); err != nil {
			return errors.New("missing durable service configuration")
		}
		if desired.Namespace != "" && desired.Namespace != Namespace {
			return errors.New("service registry namespace differs from coordination namespace")
		}
		// Credentials are created only during first-hub initialization. Never
		// accept secret material smuggled into the public desired-state registry.
		if len(desired.BootstrapSecret) > 0 || len(desired.TLSKey) > 0 || len(desired.TLSCertificate) > 0 {
			return errors.New("durable service configuration contains private credentials")
		}
		return m.ApplyServices(held, desired)
	})
}

func (m *Manager) readServicesLease(ctx context.Context) (*servicesLease, error) {
	b, err := m.kubectl(ctx, nil, "-n", Namespace, "get", "lease", serviceLeaseName, "--ignore-not-found", "-o", "json")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(b)) == "" {
		return nil, nil
	}
	var lease servicesLease
	if err = json.Unmarshal(b, &lease); err != nil {
		return nil, errors.New("invalid service reconciliation lease")
	}
	if lease.Metadata.Name != serviceLeaseName || lease.Metadata.Namespace != Namespace || lease.Metadata.ResourceVersion == "" {
		return nil, errors.New("service reconciliation lease lacks identity or version")
	}
	return &lease, nil
}

func (m *Manager) writeServicesLease(ctx context.Context, lease *servicesLease, create bool) error {
	data, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	verb := "replace"
	if create {
		verb = "create"
	}
	out, err := m.kubectl(ctx, data, verb, "-f", "-", "-o", "json")
	if err != nil {
		return err
	}
	var stored servicesLease
	if err = json.Unmarshal(out, &stored); err != nil || stored.Metadata.ResourceVersion == "" {
		return errors.New("Kubernetes did not confirm service lease version")
	}
	*lease = stored
	return nil
}

func leaseExpired(lease *servicesLease, now time.Time) (bool, error) {
	if lease.Spec.HolderIdentity == "" {
		return true, nil
	}
	stamp := lease.Spec.RenewTime
	if stamp == nil {
		stamp = lease.Spec.AcquireTime
	}
	if stamp == nil || lease.Spec.LeaseDurationSeconds < 1 {
		return false, errors.New("active service lease has no valid expiration")
	}
	return !now.Before(stamp.Add(time.Duration(lease.Spec.LeaseDurationSeconds) * time.Second)), nil
}

func (m *Manager) acquireServicesLease(ctx context.Context, holder string) error {
	for {
		lease, err := m.readServicesLease(ctx)
		if err != nil {
			return err
		}
		create := lease == nil
		previousVersion := ""
		now := time.Now().UTC()
		if create {
			lease = &servicesLease{APIVersion: "coordination.k8s.io/v1", Kind: "Lease"}
			lease.Metadata.Name = serviceLeaseName
			lease.Metadata.Namespace = Namespace
		} else {
			previousVersion = lease.Metadata.ResourceVersion
			expired, err := leaseExpired(lease, now)
			if err != nil {
				return err
			}
			if !expired {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(250 * time.Millisecond):
					continue
				}
			}
			lease.Spec.LeaseTransitions++
		}
		lease.Spec.HolderIdentity = holder
		lease.Spec.LeaseDurationSeconds = int(serviceLeaseDuration / time.Second)
		lease.Spec.AcquireTime = &leaseTime{now}
		lease.Spec.RenewTime = &leaseTime{now}
		if err = m.writeServicesLease(ctx, lease, create); err == nil {
			return nil
		}
		// Distinguish a lost create/CAS race from an authorization or API error.
		// Never blindly retry a failed mutation and assume ownership.
		current, readErr := m.readServicesLease(ctx)
		if readErr != nil {
			return errors.Join(err, readErr)
		}
		if current == nil || current.Metadata.ResourceVersion == previousVersion {
			return err
		}
		if current.Spec.HolderIdentity == holder {
			return nil
		} // server committed but response was lost
	}
}

func (m *Manager) renewServicesLease(ctx context.Context, holder string) error {
	lease, err := m.readServicesLease(ctx)
	if err != nil {
		return err
	}
	if lease == nil || lease.Spec.HolderIdentity != holder {
		return errors.New("service reconciliation lease ownership lost")
	}
	now := time.Now().UTC()
	expired, err := leaseExpired(lease, now)
	if err != nil {
		return err
	}
	if expired {
		return errors.New("service reconciliation lease expired before renewal")
	}
	lease.Spec.RenewTime = &leaseTime{now}
	return m.writeServicesLease(ctx, lease, false)
}

func (m *Manager) releaseServicesLease(holder string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	lease, err := m.readServicesLease(ctx)
	if err != nil {
		return err
	}
	if lease == nil || lease.Spec.HolderIdentity != holder {
		return nil
	}
	lease.Spec.HolderIdentity = ""
	now := time.Now().UTC()
	lease.Spec.RenewTime = &leaseTime{now}
	return m.writeServicesLease(ctx, lease, false)
}

func (m *Manager) withServicesLease(ctx context.Context, apply func(context.Context) error) error {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	holder := m.Config.Name + "-" + hex.EncodeToString(random[:])
	acquire, cancelAcquire := context.WithTimeout(ctx, 2*time.Minute)
	err := m.acquireServicesLease(acquire, holder)
	cancelAcquire()
	if err != nil {
		return fmt.Errorf("acquire service reconciliation lease: %w", err)
	}
	held, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		tick := time.NewTicker(serviceLeaseDuration / 6)
		defer tick.Stop()
		for {
			select {
			case <-held.Done():
				done <- nil
				return
			case <-tick.C:
				bounded, stop := context.WithTimeout(held, serviceLeaseDuration/3)
				err := m.renewServicesLease(bounded, holder)
				stop()
				if err != nil {
					cancel()
					done <- fmt.Errorf("renew service reconciliation lease: %w", err)
					return
				}
			}
		}
	}()
	err = apply(held)
	cancel()
	renewErr := <-done
	releaseErr := m.releaseServicesLease(holder)
	return errors.Join(err, renewErr, releaseErr)
}
