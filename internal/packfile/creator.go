package packfile

import (
	"github.com/NahomAnteneh/vec-server/core"
)

// CreateFromObjects creates a packfile from object hashes
func CreateFromObjects(repo *core.Repository, objects []string, useDelta bool, outputPath string, hashLength ...int) error {
	p := NewPackfile(repo, hashLength...)
	return p.Create(objects, useDelta, outputPath)
}
