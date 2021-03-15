// Package storer implements an abstract key-value storage interface.
package storer

import (
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/esote/util/atomic2"
	"github.com/esote/util/io64"
)

// Errors which may be returned by a Storer.
var (
	ErrStorerExist    = errors.New("storer: value already exists")
	ErrStorerNotExist = errors.New("storer: value does not exist")
)

// Storer stores key-value pairs. Storer is safe for concurrent use. Keys must
// be at least one byte in length.
type Storer interface {
	// Load a value. Returns the value and its length. If the value does not
	// exist, Load returns ErrStorerNotExist
	Load(key []byte) (value io.ReadCloser, length uint64, err error)

	// Store a value. If value is nil, Store only checks if the value could
	// be stored. If the value is already stored, Store returns
	// ErrStorerExist.
	Store(key []byte, length uint64, value io.Reader) error

	// Delete a value. If the value does not exist, Delete returns
	// ErrStorerNotExist.
	Delete(key []byte) error

	// Close the Storer.
	Close() error
}

type fileStorer struct {
	dir       string
	maxLength uint64
	maxCount  uint64

	count uint64

	closed *atomic2.Bool
}

var (
	errStorerLength = errors.New("storer: max value length exceeded")
	errStorerCount  = errors.New("storer: max key count exceeded")
	errStorerClosed = errors.New("storer: closed")
)

var _ Storer = &fileStorer{}

// NewFileStorer returns a Storer backed by the filesystem. Individual files may
// be at most maxLength bytes and the Storer may contain at most maxCount files.
func NewFileStorer(dir string, maxLength, maxCount uint64) (Storer, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	storer := &fileStorer{
		dir:       dir,
		maxLength: maxLength,
		maxCount:  maxCount,
		closed:    atomic2.NewBool(),
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
	if s.closed.IsSet() {
		return nil, 0, errStorerClosed
	}
	file, err := os.Open(s.filename(key))
	if err != nil {
		if os.IsNotExist(err) {
			err = ErrStorerNotExist
		}
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
	if s.closed.IsSet() {
		return errStorerClosed
	}
	if length > s.maxLength {
		return errStorerLength
	}
	if atomic.LoadUint64(&s.count) >= s.maxCount {
		return errStorerCount
	}
	if value == nil {
		_, err := os.Stat(s.filename(key))
		switch {
		case err == nil:
			return ErrStorerExist
		case os.IsNotExist(err):
			return nil
		default:
			return err
		}
	}
	// Reserve spot for file
	if value != nil {
		atomic.AddUint64(&s.count, 1)
	}
	err := s.store(key, length, value)
	if value != nil && err != nil {
		// Free reserved spot.
		atomic.AddUint64(&s.count, ^uint64(0))
	}
	return err
}

func (s *fileStorer) store(key []byte, length uint64, value io.Reader) (err error) {
	file, err := os.OpenFile(s.filename(key),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			err = ErrStorerExist
		}
		return err
	}
	defer func() {
		if err2 := file.Close(); err == nil {
			err = err2
		}
	}()
	_, err = io64.CopyN(file, value, length)
	return err
}

func (s *fileStorer) Delete(key []byte) error {
	if s.closed.IsSet() {
		return errStorerClosed
	}
	err := os.Remove(s.filename(key))
	if err != nil {
		if os.IsNotExist(err) {
			err = ErrStorerNotExist
		}
		return err
	}
	atomic.AddUint64(&s.count, ^uint64(0))
	return nil
}

func (s *fileStorer) Close() error {
	if !s.closed.Set() {
		return errStorerClosed
	}
	return nil
}

func (s *fileStorer) filename(key []byte) string {
	return filepath.Join(s.dir, base64.RawURLEncoding.EncodeToString(key))
}
