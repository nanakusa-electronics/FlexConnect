package windowspkgs

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"flexconnect/release/dist"
)

const defaultUpgradeCode = "8F4A7D5B-4021-4A65-9F08-53B0E2A1C4B7"

type zipTarget struct{ goarch string }

func (t *zipTarget) String() string { return fmt.Sprintf("windows/%s/zip", t.goarch) }

func (t *zipTarget) Build(b *dist.Build) ([]string, error) {
	artifacts, err := b.BuildCommonArtifacts("windows", t.goarch)
	if err != nil {
		return nil, err
	}
	filename := zipFilename(b.Version, t.goarch)
	outPath := filepath.Join(b.Out, filename)
	f, err := os.Create(outPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()

	root := strings.TrimSuffix(filename, ".zip")
	if err := addZipFile(zw, artifacts.FlexConnect, filepath.Join(root, filepath.Base(artifacts.FlexConnect))); err != nil {
		return nil, err
	}
	if err := addZipFile(zw, artifacts.FlexConnectD, filepath.Join(root, filepath.Base(artifacts.FlexConnectD))); err != nil {
		return nil, err
	}
	if err := addZipFile(zw, artifacts.FlexTray, filepath.Join(root, filepath.Base(artifacts.FlexTray))); err != nil {
		return nil, err
	}
	if err := addZipFile(zw, artifacts.WintunDLL, filepath.Join(root, "wintun.dll")); err != nil {
		return nil, err
	}
	return []string{outPath}, nil
}

type msiTarget struct{ goarch string }

func (t *msiTarget) String() string { return fmt.Sprintf("windows/%s/msi", t.goarch) }

func (t *msiTarget) Build(b *dist.Build) ([]string, error) {
	if _, err := b.LookPath("wix"); err != nil {
		return nil, fmt.Errorf("wix CLI not found in PATH")
	}
	artifacts, err := b.BuildCommonArtifacts("windows", t.goarch)
	if err != nil {
		return nil, err
	}
	workDir, err := b.TmpDir("windows-msi-*")
	if err != nil {
		return nil, err
	}
	wxsPath := filepath.Join(workDir, "flexconnect.wxs")
	msiName := msiFilename(b.Version, t.goarch)
	msiPath := filepath.Join(workDir, msiName)

	wxs, err := renderWXS(b, artifacts)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(wxsPath, wxs, 0o644); err != nil {
		return nil, err
	}

	cmd := exec.Command("wix", "build", "-arch", "x64", wxsPath, "-o", msiPath)
	cmd.Dir = workDir
	if b.Verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return collectWindowsOutputs(workDir, b.Out, msiName)
}

type wxsTemplateData struct {
	Version      string
	UpgradeCode  string
	IconPath     string
	FlexConnect  string
	FlexConnectD string
	FlexTray     string
	WintunDLL    string
}

func renderWXS(b *dist.Build, artifacts dist.CommonArtifacts) ([]byte, error) {
	tmplBytes, err := os.ReadFile(b.RepoPath("release", "dist", "windowspkgs", "files", "flexconnect.wxs.tmpl"))
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("wxs").Parse(string(tmplBytes))
	if err != nil {
		return nil, err
	}
	data := wxsTemplateData{
		Version:      windowsMSIVersion(b.Version),
		UpgradeCode:  upgradeCode(b),
		IconPath:     b.RepoPath("assets", "windows", "flextray.ico"),
		FlexConnect:  artifacts.FlexConnect,
		FlexConnectD: artifacts.FlexConnectD,
		FlexTray:     artifacts.FlexTray,
		WintunDLL:    artifacts.WintunDLL,
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func upgradeCode(b *dist.Build) string {
	if b.WindowsUpgradeCode != "" {
		return b.WindowsUpgradeCode
	}
	return defaultUpgradeCode
}

func windowsMSIVersion(version string) string {
	version, _, _ = strings.Cut(version, "-")
	version, _, _ = strings.Cut(version, "+")
	parts := strings.Split(version, ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	return strings.Join(parts[:3], ".")
}

func zipFilename(version, arch string) string {
	return fmt.Sprintf("flexconnect_%s_windows_%s.zip", version, arch)
}

func msiFilename(version, arch string) string {
	return fmt.Sprintf("flexconnect_%s_windows_%s.msi", version, arch)
}

func addZipFile(zw *zip.Writer, src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	w, err := zw.Create(filepath.ToSlash(dst))
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func collectWindowsOutputs(workDir, outDir, msiName string) ([]string, error) {
	entries, err := os.ReadDir(workDir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name != msiName {
			continue
		}
		src := filepath.Join(workDir, name)
		dst := filepath.Join(outDir, name)
		if err := copyFile(src, dst); err != nil {
			return nil, err
		}
		out = append(out, dst)
	}
	sort.Strings(out)
	return out, nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}
