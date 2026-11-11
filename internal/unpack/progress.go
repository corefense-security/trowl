package unpack

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Progress receives what Unpack is doing, to show it. Unpack reports each stage by name with the
// bytes it will take (0 when unknown), then the bytes done as they go. status.Step implements it.
// Unpack works without one.
type Progress interface {
	Stage(name string, size int64)
	Add(n int64)
}

type noProgress struct{}

func (noProgress) Stage(string, int64) {}
func (noProgress) Add(int64)           {}

// partProgress names the partition of a disk image a stage is about, as in "partition 2: extracting ext".
type partProgress struct {
	Progress
	prefix string
}

func (p partProgress) Stage(name string, size int64) { p.Progress.Stage(p.prefix+name, size) }

// counting passes reads through and counts them as progress. These are compressed bytes for a
// stream being decompressed, or archive bytes for a tarball.
type counting struct {
	r io.Reader
	p Progress
}

func (c counting) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.p.Add(int64(n))
	return n, err
}

// pollInterval is how often watchDir measures what an extractor has written so far.
const pollInterval = 300 * time.Millisecond

// watchDir counts the bytes of regular files appearing under dir as progress, for an external
// extractor (debugfs, unsquashfs) that reports none of its own. It returns a function that stops
// watching and waits for the watcher to finish.
func watchDir(dir string, p Progress) (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var counted int64
		for {
			select {
			case <-done:
				return
			case <-time.After(pollInterval):
			}
			n := treeBytes(dir)
			if n > counted {
				p.Add(n - counted)
				counted = n
			}
		}
	}()
	return func() {
		close(done)
		wg.Wait()
	}
}

// treeBytes adds up the sizes of the regular files under dir, skipping what it can't read.
func treeBytes(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			n += info.Size()
		}
		return nil
	})
	return n
}

// fileSize is a file's size, or 0 when it can't be read (the stage then shows no percentage).
func fileSize(path string) int64 {
	if info, err := os.Stat(path); err == nil {
		return info.Size()
	}
	return 0
}
