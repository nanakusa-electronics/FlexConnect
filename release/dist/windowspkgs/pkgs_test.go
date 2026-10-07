package windowspkgs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"flexconnect/release/dist"
)

func TestWindowsFilenames(t *testing.T) {
	if got := zipFilename("1.2.3", "amd64"); got != "flexconnect_1.2.3_windows_amd64.zip" {
		t.Fatalf("unexpected zip filename %q", got)
	}
	if got := msiFilename("1.2.3", "amd64"); got != "flexconnect_1.2.3_windows_amd64.msi" {
		t.Fatalf("unexpected msi filename %q", got)
	}
	if got := windowsMSIVersion("1.2"); got != "1.2.0" {
		t.Fatalf("unexpected msi version %q", got)
	}
	if got := windowsMSIVersion("2.0.0-beta.1"); got != "2.0.0" {
		t.Fatalf("beta MSI product version = %q", got)
	}
}

func TestUpgradeCode(t *testing.T) {
	if got := upgradeCode(&dist.Build{}); got != defaultUpgradeCode {
		t.Fatalf("default upgrade code = %q", got)
	}
	if got := upgradeCode(&dist.Build{WindowsUpgradeCode: "custom"}); got != "custom" {
		t.Fatalf("custom upgrade code = %q", got)
	}
}

func TestCollectWindowsOutputs(t *testing.T) {
	workDir := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir out: %v", err)
	}

	for name := range map[string]bool{
		"flexconnect_1.0.1_windows_amd64.msi":    true,
		"cab1.cab":                               false,
		"flexconnect_1.0.1_windows_amd64.wixpdb": false,
		"flexconnect.wxs":                        false,
	} {
		if err := os.WriteFile(filepath.Join(workDir, name), []byte(name), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	got, err := collectWindowsOutputs(workDir, outDir, "flexconnect_1.0.1_windows_amd64.msi")
	if err != nil {
		t.Fatalf("collectWindowsOutputs error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 distributable output, got %d (%v)", len(got), got)
	}
	for _, path := range got {
		if filepath.Ext(path) == ".wixpdb" {
			t.Fatalf("unexpected wixpdb output %q", path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected copied file %q: %v", path, err)
		}
	}
}

func TestRenderWXSUsesCustomUpgradeCode(t *testing.T) {
	repo := t.TempDir()
	tmplDir := filepath.Join(repo, "release", "dist", "windowspkgs", "files")
	if err := os.MkdirAll(tmplDir, 0o755); err != nil {
		t.Fatalf("mkdir template dir: %v", err)
	}
	templateBody := `UpgradeCode={{ .UpgradeCode }}|Version={{ .Version }}`
	if err := os.WriteFile(filepath.Join(tmplDir, "flexconnect.wxs.tmpl"), []byte(templateBody), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	build := &dist.Build{
		Repo:               repo,
		Version:            "1.2.3",
		WindowsUpgradeCode: "11111111-2222-3333-4444-555555555555",
	}
	artifacts := dist.CommonArtifacts{}
	got, err := renderWXS(build, artifacts)
	if err != nil {
		t.Fatalf("renderWXS error: %v", err)
	}
	if !bytes.Contains(got, []byte("UpgradeCode=11111111-2222-3333-4444-555555555555")) {
		t.Fatalf("expected custom upgrade code in template output, got %q", string(got))
	}
	if !bytes.Contains(got, []byte("Version=1.2.3")) {
		t.Fatalf("expected version in template output, got %q", string(got))
	}
}

func TestRenderWXSIncludesStartMenuShortcut(t *testing.T) {
	repo := t.TempDir()
	tmplDir := filepath.Join(repo, "release", "dist", "windowspkgs", "files")
	if err := os.MkdirAll(tmplDir, 0o755); err != nil {
		t.Fatalf("mkdir template dir: %v", err)
	}
	templateBody := `
ShortcutTarget=[#filFlexTray]
ProgramsFolder=ApplicationProgramsFolder
RegistryKey=Software\FlexConnect
`
	if err := os.WriteFile(filepath.Join(tmplDir, "flexconnect.wxs.tmpl"), []byte(templateBody), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	build := &dist.Build{Repo: repo, Version: "1.2.3"}
	got, err := renderWXS(build, dist.CommonArtifacts{})
	if err != nil {
		t.Fatalf("renderWXS error: %v", err)
	}
	if !bytes.Contains(got, []byte("[#filFlexTray]")) {
		t.Fatalf("expected start menu shortcut target in template output, got %q", string(got))
	}
	if !bytes.Contains(got, []byte("ApplicationProgramsFolder")) {
		t.Fatalf("expected program menu folder in template output, got %q", string(got))
	}
}

func TestRenderWXSIncludesPathEnvironment(t *testing.T) {
	repo := t.TempDir()
	tmplDir := filepath.Join(repo, "release", "dist", "windowspkgs", "files")
	if err := os.MkdirAll(tmplDir, 0o755); err != nil {
		t.Fatalf("mkdir template dir: %v", err)
	}
	templateBody := `
EnvName=PATH
EnvValue=[INSTALLDIR]
EnvSystem=yes
EnvPart=last
`
	if err := os.WriteFile(filepath.Join(tmplDir, "flexconnect.wxs.tmpl"), []byte(templateBody), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	build := &dist.Build{Repo: repo, Version: "1.2.3"}
	got, err := renderWXS(build, dist.CommonArtifacts{})
	if err != nil {
		t.Fatalf("renderWXS error: %v", err)
	}
	if !bytes.Contains(got, []byte("EnvName=PATH")) {
		t.Fatalf("expected PATH environment entry in template output, got %q", string(got))
	}
	if !bytes.Contains(got, []byte("EnvValue=[INSTALLDIR]")) {
		t.Fatalf("expected INSTALLDIR environment value in template output, got %q", string(got))
	}
}
