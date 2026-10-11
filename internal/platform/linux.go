//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"

	"golang.org/x/sys/unix"
)

func dockerPaths() []string { return []string{"/usr/bin/docker"} }
func hostEligible() error {
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil && strings.Contains(strings.ToLower(string(b)), "microsoft") {
		return errors.New("run deepai-connect on a native Linux VPS; DeepAI Connect does not run inside WSL")
	}
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return err
	}
	// A nominal 2 GiB VM reports less usable RAM after kernel reservations.
	if uint64(info.Totalram)*uint64(info.Unit) < 1536<<20 {
		return errors.New("at least 2 GiB installed RAM (1.5 GiB usable by Linux) is required")
	}
	return nil
}

func privileged(ctx context.Context, command string, args ...string) error {
	if os.Geteuid() == 0 {
		return run(ctx, command, args...)
	}
	return run(ctx, "sudo", append([]string{command}, args...)...)
}

func startDocker(ctx context.Context) error {
	if err := privileged(ctx, "systemctl", "start", "docker"); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		if err := dockerReady(ctx); err != nil {
			return errors.New("Docker is running but this account cannot access it; have an administrator grant Docker access, then sign out and back in and rerun deepai-connect")
		}
	}
	return nil
}

func installDocker(ctx context.Context) error {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			fields[key] = strings.Trim(value, "\"'")
		}
	}
	if fields["ID"] != "ubuntu" || (fields["VERSION_ID"] != "24.04" && fields["VERSION_ID"] != "26.04") {
		return errors.New("automatic Docker installation supports Ubuntu 24.04/26.04; install a rootful Docker Engine on this distribution, then rerun")
	}
	for _, pkg := range []string{"docker-ce", "moby-engine", "podman-docker"} {
		status, _ := output(ctx, "dpkg-query", "-W", "-f=${Status}", pkg)
		if status == "install ok installed" {
			return fmt.Errorf("%s is installed but Docker CLI was not found; repair it first", pkg)
		}
	}
	if err = privileged(ctx, "apt-get", "update"); err != nil {
		return err
	}
	if err = privileged(ctx, "apt-get", "install", "-y", "docker.io"); err != nil {
		return err
	}
	if err = privileged(ctx, "systemctl", "enable", "--now", "docker"); err != nil {
		return err
	}
	if os.Geteuid() != 0 && dockerReady(ctx) != nil {
		account, err := user.Current()
		if err != nil {
			return err
		}
		if err = privileged(ctx, "usermod", "-aG", "docker", account.Username); err != nil {
			return err
		}
		return errors.New("Docker was installed and your account was added to the docker group; sign out and back in, then rerun deepai-connect to resume")
	}
	return nil
}
