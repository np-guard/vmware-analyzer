package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSegmentNamespaceMapCSV(t *testing.T) {
	m, err := ParseSegmentNamespaceMapCSV("Seg-Web=tom-testing,Seg-Database=tom-testing")
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"Seg-Web":      "tom-testing",
		"Seg-Database": "tom-testing",
	}, m)
}

func TestParseSegmentNamespaceMapCSVInvalid(t *testing.T) {
	_, err := ParseSegmentNamespaceMapCSV("Seg-Web")
	require.Error(t, err)
}

func TestLoadSegmentNamespaceMapFileYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "map.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
Seg-Web: tom-testing
Seg-Database: tom-testing
`), 0o600))
	m, err := LoadSegmentNamespaceMapFile(path)
	require.NoError(t, err)
	require.Equal(t, "tom-testing", m["Seg-Web"])
	require.Equal(t, "tom-testing", m["Seg-Database"])
}

func TestLoadSegmentNamespaceMapFileJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "map.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"Seg-Web":"tom-testing"}`), 0o600))
	m, err := LoadSegmentNamespaceMapFile(path)
	require.NoError(t, err)
	require.Equal(t, "tom-testing", m["Seg-Web"])
}

func TestMergeSegmentNamespaceMaps(t *testing.T) {
	merged := MergeSegmentNamespaceMaps(
		map[string]string{"Seg-Web": "from-file", "Seg-Database": "from-file"},
		map[string]string{"Seg-Web": "from-flag"},
	)
	require.Equal(t, "from-flag", merged["Seg-Web"])
	require.Equal(t, "from-file", merged["Seg-Database"])
}
