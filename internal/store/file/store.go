package file

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"flexconnect/internal/types"
)

type Data struct {
	SchemaVersion    int               `json:"schema_version"`
	Profiles         []types.Profile   `json:"profiles"`
	CurrentProfileID string            `json:"current_profile_id"`
	SelectedProfiles map[string]string `json:"selected_profiles"`
	ControlMode      string            `json:"control_mode"`
	MachineProfileID string            `json:"machine_profile_id,omitempty"`
	Intent           *Intent           `json:"intent,omitempty"`
}

type Intent struct {
	Version      int            `json:"version"`
	Kind         string         `json:"kind"`
	ProfileID    string         `json:"profile_id"`
	NewProfile   *types.Profile `json:"new_profile,omitempty"`
	OldSecretRef string         `json:"old_secret_ref,omitempty"`
	NewSecretRef string         `json:"new_secret_ref,omitempty"`
}

// storedProfile is the state-file representation. SecretRef and OwnerID are
// intentionally excluded from types.Profile's JSON representation so they can
// never leak through the Local API; only this persistence boundary serializes
// them.
type storedProfile struct {
	types.Profile
	SecretRef string `json:"secret_ref"`
	OwnerID   string `json:"owner_id"`
}

type storedIntent struct {
	Version      int            `json:"version"`
	Kind         string         `json:"kind"`
	ProfileID    string         `json:"profile_id"`
	NewProfile   *storedProfile `json:"new_profile,omitempty"`
	OldSecretRef string         `json:"old_secret_ref,omitempty"`
	NewSecretRef string         `json:"new_secret_ref,omitempty"`
}

type storedData struct {
	SchemaVersion    int               `json:"schema_version"`
	Profiles         []storedProfile   `json:"profiles"`
	CurrentProfileID string            `json:"current_profile_id"`
	SelectedProfiles map[string]string `json:"selected_profiles"`
	ControlMode      string            `json:"control_mode"`
	MachineProfileID string            `json:"machine_profile_id,omitempty"`
	Intent           *storedIntent     `json:"intent,omitempty"`
}

const CurrentSchemaVersion = 3

type Store struct {
	path string
	mu   sync.Mutex
}

func New(path string) *Store {
	return &Store{path: path}
}

func (s *Store) Load() (Data, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var disk storedData
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Data{SchemaVersion: CurrentSchemaVersion, SelectedProfiles: map[string]string{}, ControlMode: "user"}, nil
	}
	if err != nil {
		return Data{}, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return Data{}, fmt.Errorf("state file %s is empty", s.path)
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&disk); err != nil {
		return Data{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return Data{}, errors.New("state file contains multiple JSON values")
		}
		return Data{}, fmt.Errorf("state file contains trailing data: %w", err)
	}
	return fromStoredData(disk), nil
}

func (s *Store) Save(data Data) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(toStoredData(data), "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".flexconnect-state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceFile(tmpPath, s.path); err != nil {
		return err
	}
	if err := secureFile(s.path); err != nil {
		return fmt.Errorf("secure state file: %w", err)
	}
	if err := syncParentDir(filepath.Dir(s.path)); err != nil {
		return err
	}
	committed = true
	return nil
}

func toStoredProfile(profile types.Profile) storedProfile {
	return storedProfile{Profile: profile, SecretRef: profile.SecretRef, OwnerID: profile.OwnerID}
}

func fromStoredProfile(profile storedProfile) types.Profile {
	result := profile.Profile
	result.SecretRef = profile.SecretRef
	result.OwnerID = profile.OwnerID
	return result
}

func toStoredData(data Data) storedData {
	disk := storedData{
		SchemaVersion: data.SchemaVersion, CurrentProfileID: data.CurrentProfileID,
		SelectedProfiles: data.SelectedProfiles, ControlMode: data.ControlMode,
		MachineProfileID: data.MachineProfileID,
	}
	disk.Profiles = make([]storedProfile, len(data.Profiles))
	for i := range data.Profiles {
		disk.Profiles[i] = toStoredProfile(data.Profiles[i])
	}
	if data.Intent != nil {
		disk.Intent = &storedIntent{
			Version: data.Intent.Version, Kind: data.Intent.Kind, ProfileID: data.Intent.ProfileID,
			OldSecretRef: data.Intent.OldSecretRef, NewSecretRef: data.Intent.NewSecretRef,
		}
		if data.Intent.NewProfile != nil {
			profile := toStoredProfile(*data.Intent.NewProfile)
			disk.Intent.NewProfile = &profile
		}
	}
	return disk
}

func fromStoredData(disk storedData) Data {
	data := Data{
		SchemaVersion: disk.SchemaVersion, CurrentProfileID: disk.CurrentProfileID,
		SelectedProfiles: disk.SelectedProfiles, ControlMode: disk.ControlMode,
		MachineProfileID: disk.MachineProfileID,
	}
	data.Profiles = make([]types.Profile, len(disk.Profiles))
	for i := range disk.Profiles {
		data.Profiles[i] = fromStoredProfile(disk.Profiles[i])
	}
	if disk.Intent != nil {
		data.Intent = &Intent{
			Version: disk.Intent.Version, Kind: disk.Intent.Kind, ProfileID: disk.Intent.ProfileID,
			OldSecretRef: disk.Intent.OldSecretRef, NewSecretRef: disk.Intent.NewSecretRef,
		}
		if disk.Intent.NewProfile != nil {
			profile := fromStoredProfile(*disk.Intent.NewProfile)
			data.Intent.NewProfile = &profile
		}
	}
	return data
}
