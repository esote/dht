package main

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/esote/dht"
)

func usage() {
	fmt.Println(`Usage: ./dht <flags> <filename>
Flags:`)
	flag.PrintDefaults()
}

func main() {
	var (
		dir   string
		port  int
		nocli bool
	)
	flag.Usage = usage

	flag.IntVar(&port, "p", 16789, "listening port")
	flag.BoolVar(&nocli, "c", false, "disable CLI input")
	flag.Parse()

	if flag.NArg() == 0 {
		log.Fatal("no working directory specified")
	}

	dir = flag.Args()[0]

	in := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter password: ")
	var password []byte
	if !in.Scan() {
		log.Fatal("scan failed:", in.Err())
	} else {
		password = in.Bytes()
	}
	if len(password) == 0 {
		log.Fatal("password required to encrypt node private key")
	}
	const (
		maxSingleValueSize = 64 * 1024      // 64 mb
		maxTotalSize       = 64 * 1024 * 64 // 4096 mb
	)

	storer, err := dht.NewFileStorer(filepath.Join(dir, "storer"),
		maxSingleValueSize, maxTotalSize)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := storer.Close(); err != nil {
			log.Println(err)
		}
	}()

	config := &dht.DHTConfig{
		NetworkID:     []byte{1, 2, 3, 4},
		Dir:           dir,
		Password:      password,
		Storer:        storer,
		Logger:        dht.NewConsoleLogger(dht.LogDebug),
		IP:            net.IPv4(127, 0, 0, 1),
		Port:          uint16(port),
		FixedTimeout:  time.Second,
		StreamTimeout: time.Minute,
	}

	d, err := dht.NewDHT(config)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := d.Close(); err != nil {
			log.Println(err)
		}
	}()

	if nocli {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
	}
cliloop:
	for !nocli && in.Scan() {
		line := in.Text()
		split := strings.Split(line, " ")
		if len(split) == 0 {
			log.Println("cmd invalid")
			continue
		}
		switch split[0] {
		case "store":
			if len(split) < 2 {
				log.Println("missing store arguments")
				continue
			}
			file, err := filepath.Abs(split[1])
			if err != nil {
				log.Println(err)
				continue
			}
			if err = store(d, file); err != nil {
				log.Println(err)
			}
		case "load":
			if len(split) < 3 {
				log.Println("missing load arguments")
				continue
			}
			key, err := base64.RawURLEncoding.DecodeString(split[1])
			if err != nil {
				log.Println(err)
				continue
			}
			output := split[2]
			if _, err := os.Stat(output); err == nil || os.IsExist(err) {
				log.Println("output already exists")
				continue
			}
			if err = load(d, key, output); err != nil {
				log.Println(err)
			}
		case "bootstrap":
			if len(split) < 4 {
				log.Println("missing bootstrap arguments")
			}
			publ, err := base64.RawURLEncoding.DecodeString(split[1])
			if err != nil {
				log.Println(err)
				continue
			}
			// TODO: shouldn't need to do To16()
			ip := net.ParseIP(split[2]).To16()
			if ip == nil {
				log.Println("ip invalid")
				continue
			}
			port, err := strconv.ParseUint(split[3], 10, 16)
			if err != nil {
				log.Println(err)
				continue
			}
			if err = bootstrap(d, publ, ip, uint16(port)); err != nil {
				log.Println(err)
			}
		case "exit":
			break cliloop
		default:
			log.Printf("cmd '%s' invalid", split[0])
			continue
		}
	}
	if err = in.Err(); err != nil {
		log.Println(err)
	}
}

type rereader struct {
	file string
}

func (r *rereader) Next() (io.ReadCloser, error) {
	return os.Open(r.file)
}

func store(d *dht.DHT, file string) (err error) {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer func() {
		if err2 := f.Close(); err == nil {
			err = err2
		}
	}()
	h := sha512.New()
	if _, err = io.Copy(h, f); err != nil {
		return err
	}
	sum := h.Sum(nil)
	// TODO: move to dht DEBUG?
	fmt.Println("file", file, "key", base64.RawURLEncoding.EncodeToString(sum))

	info, err := os.Stat(file)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("path isn't a regular file")
	}
	length := uint64(info.Size())

	return d.Store(sum, length, &rereader{file})
}

func load(d *dht.DHT, key []byte, output string) (err error) {
	value, _, err := d.Load(key)
	if err != nil {
		return err
	}
	defer func() {
		if err2 := value.Close(); err == nil {
			err = err2
		}
	}()
	h := sha512.New()
	out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err2 := out.Close(); err == nil {
			err = err2
		}
	}()
	w := io.MultiWriter(out, h)
	if _, err = io.Copy(w, value); err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), key) {
		return errors.New("value hash mismatch")
	}
	return nil
}

func bootstrap(d *dht.DHT, publ []byte, ip net.IP, port uint16) error {
	if ip = ip.To16(); ip == nil {
		return errors.New("ip invalid")
	}
	return d.Bootstrap(publ, ip, port)
}
