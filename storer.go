package dht

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/esote/dht/util"
	"github.com/esote/util/splay"
)

// Storer stores key-value pairs. Storer is safe for concurrent use.
type Storer interface {
	// Load a value. Returns the value and its length.
	//
	// If the value does not exist, Load returns ErrStorerNotExist.
	Load(key KeyID) (value io.ReadCloser, length uint64, err error)

	// Store a value. If value is nil, Store is used only to check if the
	// value could be stored.
	//
	// If the value is too large to be supported, or the total storage
	// capacity has been reached, Store returns ErrStorerLarge. If the
	// storer's quota of key-value pairs has been reached, Storer returns
	// ErrStorerQuota. If the value is already stored, Store returns
	// ErrStorerExist.
	Store(key KeyID, length uint64, value io.Reader) error

	// Delete a value. If the value does not exist, Delete returns
	// ErrStorerNotExist.
	Delete(key KeyID) error

	io.Closer
}

// Errors which may be returned by a Storer.
var (
	ErrStorerLarge    = errors.New("storer: value too large")      // EFBIG
	ErrStorerQuota    = errors.New("storer: quota exceeded")       // EDQUOT
	ErrStorerExist    = errors.New("storer: value already exists") // EEXIST
	ErrStorerNotExist = errors.New("storer: value does not exist") // ENOENT
)

type fileStorer struct {
	s            *splay.Splay
	dir          string
	maxLength    uint64
	maxTotalSize uint64
}

func NewFileStorer(dir string, maxLength, maxTotalSize uint64) (Storer, error) {
	dir = filepath.Clean(dir)
	s, err := splay.NewSplay(dir, 4)
	if err != nil {
		return nil, err
	}
	return &fileStorer{
		s:            s,
		dir:          dir,
		maxLength:    maxLength,
		maxTotalSize: maxTotalSize,
	}, nil
}

func (s *fileStorer) Load(key KeyID) (io.ReadCloser, uint64, error) {
	file, err := s.s.Open(string(key))
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

func (s *fileStorer) Store(key KeyID, length uint64, value io.Reader) error {
	if length > s.maxLength {
		return ErrStorerLarge
	}
	size, err := s.size()
	if err != nil {
		return err
	}
	if uint64(size)+length > s.maxTotalSize {
		return ErrStorerLarge
	}
	if value == nil {
		_, err = s.s.Stat(string(key))
		switch {
		case err == nil:
			return ErrStorerExist
		case os.IsNotExist(err):
			return nil
		default:
			return err
		}
	}
	file, err := s.s.OpenFile(string(key),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	// TODO: check EDQUOT
	if err == os.ErrExist {
		err = ErrStorerExist
	}
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = util.CopyN(file, value, length)
	// TODO: check EDQUOT
	return err
}

func (s *fileStorer) Delete(key KeyID) error {
	err := s.s.Remove(string(key))
	if err == os.ErrNotExist {
		err = ErrStorerNotExist
	}
	return err
}

func (s *fileStorer) Close() error {
	return nil
}

func (s *fileStorer) size() (uint64, error) {
	var size uint64
	err := filepath.Walk(s.dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			size += uint64(info.Size())
		}
		return err
	})
	return size, err
}
