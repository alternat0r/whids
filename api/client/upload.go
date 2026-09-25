package client

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/whids/utils"
)

const ()

var (
	// Anchored regular expressions: the entire field must match, so none of
	// them can carry a path separator (and therefore no path traversal) into
	// the components used to build the dump destination path.
	guidRe      = regexp.MustCompile(`(?i:\A\{[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}\}\z)`)
	eventHashRe = regexp.MustCompile(`(?i:\A[a-f0-9]{32,}\z)`) // at least md5
	filenameRe  = regexp.MustCompile(`\A[\w\s\.-]+\z`)

	UploadShrinkerBufferSize = int64(3 * utils.Mega)
)

type UploadShrinker struct {
	name  string
	f     *os.File
	fu    *FileUpload
	buff  []byte
	chunk int
	total int
	size  int64
	err   error
}

// NewUploadShrinker creates a new object to shrink files to be uploaded to the manager
func NewUploadShrinker(path, guid, ehash string) (it *UploadShrinker, err error) {
	var fd *os.File
	var stat fs.FileInfo

	if fd, err = os.Open(path); err != nil {
		return
	}

	if stat, err = fd.Stat(); err != nil {
		return
	}

	size := stat.Size()
	total := int(size/UploadShrinkerBufferSize) + 1

	it = &UploadShrinker{
		name: filepath.Base(path),
		f:    fd,
		fu: &FileUpload{
			Name:      filepath.Base(path),
			GUID:      guid,
			EventHash: ehash,
			Total:     total,
		},
		buff:  make([]byte, UploadShrinkerBufferSize),
		chunk: 1,
		total: total,
		size:  size,
	}

	return
}

// Size returns the size of the file to be shrinked
func (i *UploadShrinker) Size() int64 {
	return i.size
}

// Next returns the next FileUpload or nil if finished
func (i *UploadShrinker) Next() *FileUpload {
	var n int
	var err error

	if i.Done() {
		return nil
	}

	if n, err = i.f.Read(i.buff); err != nil && err != io.EOF {
		i.err = err
		return nil
	}

	i.fu.Chunk = i.chunk
	i.fu.Content = i.buff[:n]
	i.chunk++

	return i.fu
}

// Done returns true when all files have been sent
func (i *UploadShrinker) Done() bool {
	return i.chunk > i.total
}

// Err report any error encountered while iterating over Next
func (i *UploadShrinker) Err() error {
	return i.err
}

// Close closes the underlying file
func (i *UploadShrinker) Close() error {
	return i.f.Close()
}

//////////////////////// FileUpload

// FileUpload structure used to forward files from the client to the manager
type FileUpload struct {
	Name      string `json:"filename"`
	GUID      string `json:"guid"`
	EventHash string `json:"event-hash"`
	Content   []byte `json:"content"`
	Chunk     int    `json:"chunk"` // identify the chunk number
	Total     int    `json:"total"` // total number of chunks needed to reconstruct the file
}

// Validate that the file upload follows the expected format
func (f *FileUpload) Validate() error {
	if !filenameRe.MatchString(f.Name) {
		return fmt.Errorf("bad filename")
	}
	if !guidRe.MatchString(f.GUID) {
		return fmt.Errorf("bad guid")
	}
	if !eventHashRe.MatchString(f.EventHash) {
		return fmt.Errorf("bad event hash")
	}
	// The regexes above are anchored so they cannot contain separators, but we
	// reject path separators outright as defense in depth: the components are
	// joined into a filesystem path, so any of them carrying a separator (or
	// the ".." component) could escape the dump directory.
	if hasPathComponent(f.Name) || hasPathComponent(f.GUID) || hasPathComponent(f.EventHash) {
		return fmt.Errorf("invalid path component")
	}
	return nil
}

// hasPathComponent reports whether s contains a path separator or a ".."
// component, i.e. anything that could be used to traverse out of a directory.
func hasPathComponent(s string) bool {
	if strings.ContainsAny(s, `/\`) {
		return true
	}
	return strings.Contains(s, "..")
}

// Implode returns the full path of the FileUpload
func (f *FileUpload) Implode() string {
	return filepath.Join(f.GUID, f.EventHash, f.Name)
}

// Dump dumps the FileUpload into the given root directory dir
func (f *FileUpload) Dump(root string) (err error) {
	// Return error if cannot dump file
	if err = f.Validate(); err != nil {
		return
	}

	// Defense in depth: make sure the computed destination stays inside root,
	// no matter what the components are (e.g. ".." or absolute paths).
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return
	}
	destDir := filepath.Join(rootAbs, f.GUID, f.EventHash)
	if !isSubPath(rootAbs, destDir) {
		return fmt.Errorf("dump destination escapes root directory")
	}

	dirpath := filepath.Join(root, f.GUID, f.EventHash)

	// Create directory if doesn't exist
	if !fsutil.IsDir(dirpath) {
		if err = os.MkdirAll(dirpath, utils.DefaultFilePerm); err != nil {
			return
		}
	}

	return f.write(root)
}

// isSubPath reports whether sub is p itself or located inside p.
func isSubPath(p, sub string) bool {
	rel, err := filepath.Rel(p, sub)
	if err != nil {
		return false
	}
	// rel is always a relative path; reject escaping via "..".
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func (f *FileUpload) write(root string) (err error) {
	var out *os.File
	var content []byte

	path := filepath.Join(root, f.Implode())
	if f.Chunk < f.Total {
		return utils.HidsWriteData(fmt.Sprintf("%s.%d", path, f.Chunk), f.Content)
	} else {
		// special case where we have only one chunk
		if f.Total == 1 {
			return utils.HidsWriteData(path, f.Content)
		}

		// we reassemble chunks
		if out, err = utils.HidsCreateFile(path); err != nil {
			return
		}

		for i := 1; i < f.Total; i++ {
			chunkPath := fmt.Sprintf("%s.%d", path, i)
			if content, err = os.ReadFile(chunkPath); err != nil {
				return
			}

			if _, err = out.Write(content); err != nil {
				return
			}

			os.Remove(chunkPath)
		}

		if _, err = out.Write(f.Content); err != nil {
			return
		}

		return out.Close()
	}
}
