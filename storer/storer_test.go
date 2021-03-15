package storer

import (
	"bytes"
	"io/ioutil"
	"os"
	"sync"
	"testing"
)

func TestFileStorer(t *testing.T) {
	dir, err := ioutil.TempDir("", "storertest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	s, err := NewFileStorer(dir, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{0, 1, 2}
	length := uint64(len(data))
	key := []byte{0}
	if _, _, err := s.Load(key); err != ErrStorerNotExist {
		t.Fatalf("expected ErrStorerNotExist, got %s", err)
	}
	if err = s.Delete(key); err != ErrStorerNotExist {
		t.Fatalf("expected ErrStorerNotExist, got %s", err)
	}
	if err = s.Store(key, length, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if err = s.Store(key, length, nil); err != ErrStorerExist {
		t.Fatalf("expected ErrStorerExist, got %s", err)
	}
	if err = s.Delete(key); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
}

// Concurrently store, load, and delete the same 5 key-value pairs.
func TestFileStorerConcurrent(t *testing.T) {
	dir, err := ioutil.TempDir("", "storertest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	s, err := NewFileStorer(dir, 1, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	const loop = 400
	value := []byte{0}
	keys := [][]byte{
		{0}, {1}, {2}, {3}, {4}, {5},
	}
	store := func(wg *sync.WaitGroup) {
		defer wg.Done()
		for i := uint64(0); i < loop; i++ {
			for j := 0; j < len(keys); j++ {
				err := s.Store(keys[j], 1, bytes.NewReader(value))
				if err != nil && err != ErrStorerExist {
					t.Fatal(err)
				}
			}
		}
	}
	load := func(wg *sync.WaitGroup) {
		defer wg.Done()
		for i := uint64(0); i < loop; i++ {
			for j := 0; j < len(keys); j++ {
				v, _, err := s.Load(keys[j])
				if err != nil {
					if err == ErrStorerNotExist {
						continue
					}
					t.Fatal(err)
				}
				if err = v.Close(); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	del := func(wg *sync.WaitGroup) {
		defer wg.Done()
		for i := uint64(0); i < loop; i++ {
			for j := 0; j < len(keys); j++ {
				err := s.Delete(keys[j])
				if err != nil && err != ErrStorerNotExist {
					t.Fatal(err)
				}
			}
		}
	}
	const c = 8
	var wg sync.WaitGroup
	wg.Add(c * 3)
	for i := 0; i < c; i++ {
		go store(&wg)
		go load(&wg)
		go del(&wg)
	}
	wg.Wait()
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
}
