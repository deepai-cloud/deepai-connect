package cluster

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

// StartupEnabled reads the explicit machine-boot preference independently from
// enrollment and cluster credentials. Older installations retain automatic boot.
func StartupEnabled(dir string) (bool, error) {
	data, err := platform.ReadFile(filepath.Join(dir, "host-startup.json"))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	var preference struct {
		Version int   `json:"version"`
		Enabled *bool `json:"enabled"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&preference); err != nil || preference.Version != 1 || preference.Enabled == nil {
		return false, errors.New("invalid host startup preference; restore host-startup.json before continuing")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return false, errors.New("invalid trailing host startup preference data")
	}
	return *preference.Enabled, nil
}

// SetStartupEnabled records intent before systemd changes. If a systemctl call
// fails, the next explicit startup command or resume can reconcile that intent.
func SetStartupEnabled(dir string, enabled bool) error {
	data, err := json.Marshal(struct {
		Version int  `json:"version"`
		Enabled bool `json:"enabled"`
	}{1, enabled})
	if err != nil {
		return err
	}
	return platform.WriteFile(filepath.Join(dir, "host-startup.json"), append(data, '\n'), false)
}
