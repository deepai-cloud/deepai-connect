package cluster

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWaitReadyRequiresServiceStartupDespiteRegisteredNode(t *testing.T) {
	c := config(t)
	c.Role, c.Voter, c.FirstHub = "worker", false, false
	c.ServerURL, c.JoinToken = "https://100.64.0.2:6443", secureJoin()
	checks := 0
	starting := make(chan struct{})
	f := &fakeRunner{run: func(_ []byte, command string, args []string) ([]byte, error) {
		if command == "systemctl" {
			if strings.Join(args, " ") != "is-active --quiet "+UnitName {
				t.Errorf("unexpected service probe: %v", args)
			}
			checks++
			if checks == 1 {
				close(starting)
				return nil, errors.New("activating")
			}
			return nil, nil
		}
		return readyNode(c.OverlayIP), nil
	}}
	m := newManager(t, c, f)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.WaitReady(ctx) }()
	<-starting
	select {
	case err := <-done:
		t.Fatalf("Ready node bypassed pending service startup: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if checks < 2 {
		t.Fatal("service startup was not rechecked")
	}
}

func TestWaitReadyHonorsCallerDeadlineWhileServiceActivates(t *testing.T) {
	f := &fakeRunner{run: func(_ []byte, command string, _ []string) ([]byte, error) {
		if command != "systemctl" {
			t.Error("queried stale Node status before service startup")
		}
		return nil, errors.New("activating")
	}}
	m := newManager(t, config(t), f)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.WaitReady(ctx); !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "service has not completed startup") {
		t.Fatalf("startup wait lost caller deadline or diagnostic: %v", err)
	}
}

func TestHasJoinedStillProtectsIdentityWhileServiceActivates(t *testing.T) {
	c := config(t)
	c.Role, c.Voter, c.FirstHub = "worker", false, false
	c.ServerURL, c.JoinToken = "https://100.64.0.2:6443", secureJoin()
	f := &fakeRunner{run: func(_ []byte, command string, _ []string) ([]byte, error) {
		if command == "systemctl" {
			t.Error("registration protection depends on service startup")
			return nil, errors.New("activating")
		}
		return readyNode(c.OverlayIP), nil
	}}
	m := newManager(t, c, f)
	joined, err := m.HasJoined(context.Background())
	if err != nil || !joined || !m.Joined {
		t.Fatalf("registered worker lost credential-rotation protection: joined=%v err=%v", joined, err)
	}
}
