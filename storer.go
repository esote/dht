package dht

import (
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/esote/dht/util"
	"github.com/esote/util/splay"
)

// Storer stores key-value pairs. Storer is safe for concurrent use.
type Storer interface {
	// Load a value. Returns the value and its length.
	//
	// If the value does not exist, Load returns ErrStorerNotExist.
	Load(key []byte) (value io.ReadCloser, length uint64, err error)

	// Store a value. If value is nil, Store is used only to check if the
	// value could be stored.
	//
	// If the value is too large to be supported, or the total storage
	// capacity has been reached, Store returns ErrStorerLarge. If the
	// storer's quota of key-value pairs has been reached, Storer returns
	// ErrStorerQuota. If the value is already stored, Store returns
	// ErrStorerExist.
	Store(key []byte, length uint64, value io.Reader) error

	// Delete a value. If the value does not exist, Delete returns
	// ErrStorerNotExist.
	Delete(key []byte) error

	io.Closer
}

// Errors which may be returned by a Storer.
var (
	ErrStorerLarge    = errors.New("storer: value too large")
	ErrStorerQuota    = errors.New("storer: quota exceeded")
	ErrStorerExist    = errors.New("storer: value already exists")
	ErrStorerNotExist = errors.New("storer: value does not exist")
)

type fileStorer struct {
	s         *splay.Splay
	dir       string
	maxLength uint64
	maxCount  uint64

	// Mutex instead of atomic because we need to compare and increment
	// atomically.
	mu    sync.Mutex
	count uint64
}

// NewFileStorer returns a storer backed by files. Individual files may be at
// most maxLength bytes, the storer may contain at most maxCount files.
func NewFileStorer(dir string, maxLength, maxCount uint64) (Storer, error) {
	dir = filepath.Clean(dir)
	s, err := splay.NewSplay(dir, 4)
	if err != nil {
		return nil, err
	}
	storer := &fileStorer{
		s:         s,
		dir:       dir,
		maxLength: maxLength,
		maxCount:  maxCount,
	}
	err = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			storer.count++
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return storer, nil
}

func (s *fileStorer) Load(key []byte) (io.ReadCloser, uint64, error) {
	file, err := s.s.Open(encodeKey(key))
	if err == os.ErrNotExist {
		err = ErrStorerNotExist
	}
	if err != nil {
		return nil, 0, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, err
	}
	return file, uint64(info.Size()), nil
}

func (s *fileStorer) Store(key []byte, length uint64, value io.Reader) error {
	s.mu.Lock()
	if s.count >= s.maxCount {
		s.mu.Unlock()
		return ErrStorerQuota
	}
	// Reserve spot for file
	if value != nil {
		s.count++
	}
	s.mu.Unlock()
	err := s.store(key, length, value)
	if value != nil && err != nil {
		s.mu.Lock()
		s.count--
		s.mu.Unlock()
	}
	return err
}

func (s *fileStorer) store(key []byte, length uint64, value io.Reader) (err error) {
	if length > s.maxLength {
		return ErrStorerLarge
	}
	if value == nil {
		_, err = s.s.Stat(encodeKey(key))
		switch {
		case err == nil:
			return ErrStorerExist
		case os.IsNotExist(err):
			return nil
		default:
			return err
		}
	}
	file, err := s.s.OpenFile(encodeKey(key),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == os.ErrExist {
		err = ErrStorerExist
	} else if isEDQUOT(err) {
		err = ErrStorerLarge
	}
	if err != nil {
		return err
	}
	defer func() {
		if err2 := file.Close(); err == nil {
			err = err2
		}
	}()
	_, err = util.CopyN(file, value, length)
	if isEDQUOT(err) {
		err = ErrStorerLarge
	}
	if err != nil {
		return err
	}
	return nil
}

func (s *fileStorer) Delete(key []byte) error {
	switch err := s.s.Remove(encodeKey(key)); err {
	case nil:
		s.mu.Lock()
		s.count--
		s.mu.Unlock()
		return nil
	case os.ErrNotExist:
		return ErrStorerNotExist
	default:
		return err
	}
}

func (s *fileStorer) Close() error {
	return nil
}

func isEDQUOT(err error) bool {
	if err == nil {
		return false
	}
	e, ok := err.(*os.PathError)
	return ok && e.Err == syscall.EDQUOT
}

func encodeKey(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}
