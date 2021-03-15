package main

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/esote/dht"
	"github.com/esote/dht/storer"
)

const usage = `usage: dht directory command options...

directory:
	Working directory of DHT

command:
	start           begin DHT node operation
	stop            stop DHT node
	bootstrap, bs   learn about another node
	store           store file on network
	load            load file from network

Use "dht help [command]" for usage details of a command.`

const startUsage = `usage: dht directory start [-p] port

arguments:
	-p file
		Password file, if not specified the password is read from stdin
	port
		Network port to listen on`

const stopUsage = `usage: dht directory stop`

const bootstrapUsage = `usage: dht directory bootstrap id ip:port

arguments:
	id
		Base64 node ID
	ip
		IPv4 or IPv6 node address
	port
		Node network port`

const storeUsage = `usage: dht directory store file

arguments:
	file
		File to store`

const loadUsage = `usage: dht directory load key output

arguments:
	key
		Base64 file key
	output
		Output file location`

func main() {
	usageMap := map[string]string{
		"start":     startUsage,
		"stop":      stopUsage,
		"bootstrap": bootstrapUsage,
		"store":     storeUsage,
		"load":      loadUsage,
	}

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "missing working directory path")
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(1)
	}
	if len(os.Args) == 2 || os.Args[1] == "help" {
		if os.Args[1] == "help" {
			if len(os.Args) >= 3 {
				u, ok := usageMap[os.Args[2]]
				if ok {
					fmt.Fprintln(os.Stderr, u)
				}
			} else {
				fmt.Fprintln(os.Stderr, usage)
			}
		} else {
			fmt.Fprintln(os.Stderr, "missing command")
		}
		os.Exit(0)
	}
	dir, err := filepath.Abs(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch os.Args[2] {
	case "start":
		err = start(dir)
	case "stop":
		err = sendSignal(dir, sigStop, nil)
	case "bootstrap":
		id, err := base64.RawURLEncoding.Strict().DecodeString(os.Args[3])
		if err != nil {
			break
		}
		host, strport, err := net.SplitHostPort(os.Args[4])
		if err != nil {
			break
		}
		ip := net.ParseIP(host)
		if ip == nil {
			err = errors.New("bootstrap IP invalid")
			break
		}
		port, err := strconv.ParseUint(strport, 10, 16)
		if err != nil {
			break
		}
		bootstrap := &bootstrapArgs{
			ID:   id,
			IP:   ip,
			Port: uint16(port),
		}
		err = sendSignal(dir, sigBootstrap, bootstrap)
	case "store":
		file, err := filepath.Abs(os.Args[3])
		if err != nil {
			break
		}
		store := &storeArgs{
			File: file,
		}
		f, err := os.Open(file)
		if err != nil {
			break
		}
		defer func() {
			if err2 := f.Close(); err == nil {
				err = err2
			}
		}()
		h := sha512.New()
		if _, err = io.Copy(h, f); err != nil {
			break
		}
		sum := h.Sum(nil)
		fmt.Println("key", base64.RawURLEncoding.EncodeToString(sum))
		err = sendSignal(dir, sigStore, store)
	case "load":
		key, err := base64.RawURLEncoding.Strict().DecodeString(os.Args[3])
		if err != nil {
			break
		}
		output, err := filepath.Abs(os.Args[4])
		if err != nil {
			break
		}
		load := &loadArgs{
			Key:    key,
			Output: output,
		}
		err = sendSignal(dir, sigLoad, load)
	default:
		fmt.Fprintf(os.Stderr, "unexpected command '%s'\n", os.Args[2])
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func start(dir string) (err error) {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	var passfile string
	fs.Usage = func() { fmt.Fprintln(os.Stderr, startUsage) }
	fs.StringVar(&passfile, "p", "", "password file")
	fs.Parse(os.Args[3:])

	if fs.NArg() == 0 {
		fs.Usage()
		os.Exit(2)
	}

	if passfile == "-" {
		passfile = ""
	}

	port, err := strconv.ParseUint(fs.Args()[0], 10, 16)
	if err != nil {
		return err
	}

	var password []byte
	if passfile == "" {
		in := bufio.NewScanner(os.Stdin)
		fmt.Print("Enter password: ")
		if !in.Scan() {
			return in.Err()
		}
		password = in.Bytes()
	} else {
		info, err := os.Stat(passfile)
		if err != nil {
			return err
		}
		if info.Mode().Perm() != 0600 {
			return errors.New("password file permissions must be 0600")
		}
		password, err = ioutil.ReadFile(passfile)
		if err != nil {
			return err
		}
	}
	if len(password) == 0 {
		return errors.New("password required")
	}

	const (
		maxSingleValueSize = 64 * 1024      // 64 mb
		maxTotalSize       = 64 * 1024 * 64 // 4096 mb
	)
	if err = os.Mkdir(filepath.Join(dir, "storer"), 0700); err != nil {
		if !os.IsExist(err) {
			return err
		}
		err = nil
	}
	storer, err := storer.NewFileStorer(filepath.Join(dir, "storer"),
		maxSingleValueSize, maxTotalSize)
	if err != nil {
		return err
	}
	defer func() {
		if err2 := storer.Close(); err == nil {
			err = err2
		}
	}()

	logger := dht.NewConsoleLogger(dht.LogDebug)

	config := &dht.DHTConfig{
		NetworkID:     []byte{1, 2, 3, 4},
		Dir:           dir,
		Password:      password,
		Storer:        storer,
		Logger:        logger,
		IP:            net.IPv4(127, 0, 0, 1),
		Port:          uint16(port),
		FixedTimeout:  time.Second,
		StreamTimeout: time.Minute,
	}

	d, err := dht.NewDHT(config)
	if err != nil {
		return err
	}
	return listenSignals(dir, logger, d)
}

const (
	sigStop byte = iota
	sigBootstrap
	sigStore
	sigLoad
)

type bootstrapArgs struct {
	ID   []byte
	IP   net.IP
	Port uint16
}

type storeArgs struct {
	File string
}

type loadArgs struct {
	Key    []byte
	Output string
}

const netTimeout = 100 * time.Millisecond

func listenSignals(dir string, logger dht.Logger, d *dht.DHT) (err error) {
	_ = os.Remove(filepath.Join(dir, "sig"))
	l, err := net.Listen("unix", filepath.Join(dir, "sig"))
	if err != nil {
		return err
	}
	defer func() {
		if err2 := l.Close(); err2 != nil {
			logger.Log(dht.LogDebug, err2)
		}
	}()
	for {
		var c bool
		err, c = acceptSignal(d, l)
		if err != nil {
			logger.Log(dht.LogDebug, err)
		}
		if c {
			return
		}
	}
}

type rereader struct {
	file string
}

func (r *rereader) Next() (io.ReadCloser, error) {
	return os.Open(r.file)
}

func acceptSignal(d *dht.DHT, l net.Listener) (err error, c bool) {
	b := make([]byte, 1)
	conn, err := l.Accept()
	if err != nil {
		return
	}
	defer func() {
		if err2 := conn.Close(); err == nil {
			err = err2
		}
	}()
	if err = conn.SetDeadline(time.Now().Add(netTimeout)); err != nil {
		return
	}
	if _, err = conn.Read(b); err != nil {
		return
	}
	de := gob.NewDecoder(conn)
	switch b[0] {
	case sigStop:
		return d.Close(), true
	case sigBootstrap:
		var args bootstrapArgs
		if err = de.Decode(&args); err != nil {
			return
		}
		err = d.Bootstrap(args.ID, args.IP, args.Port)
		return
	case sigStore:
		var args storeArgs
		if err = de.Decode(&args); err != nil {
			return
		}
		var f *os.File
		f, err = os.Open(args.File)
		if err != nil {
			return
		}
		defer func() {
			if err2 := f.Close(); err == nil {
				err = err2
			}
		}()
		h := sha512.New()
		if _, err = io.Copy(h, f); err != nil {
			return
		}
		sum := h.Sum(nil)
		var info os.FileInfo
		info, err = os.Stat(args.File)
		if err != nil {
			return
		}
		if !info.Mode().IsRegular() {
			return errors.New("path isn't a regular file"), false
		}
		length := uint64(info.Size())
		err = d.Store(sum, length, &rereader{args.File})
		return
	case sigLoad:
		var args loadArgs
		if err = de.Decode(&args); err != nil {
			return
		}
		var value io.ReadCloser
		value, _, err = d.Load(args.Key)
		if err != nil {
			return
		}
		defer func() {
			if err2 := value.Close(); err == nil {
				err = err2
			}
		}()
		h := sha512.New()
		var out *os.File
		out, err = os.OpenFile(args.Output,
			os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return
		}
		defer func() {
			if err2 := out.Close(); err == nil {
				err = err2
			}
		}()
		w := io.MultiWriter(out, h)
		if _, err = io.Copy(w, value); err != nil {
			return
		}
		if !bytes.Equal(h.Sum(nil), args.Key) {
			return errors.New("value hash mismatch"), false
		}
		return
	}
	return nil, false
}

func sendSignal(dir string, sig byte, args interface{}) (err error) {
	conn, err := net.Dial("unix", filepath.Join(dir, "sig"))
	if err != nil {
		return
	}
	defer func() {
		if err2 := conn.Close(); err == nil {
			err = err2
		}
	}()
	b := []byte{sig}
	if _, err = conn.Write(b); err != nil {
		return
	}
	if args == nil {
		return
	}
	en := gob.NewEncoder(conn)
	return en.Encode(args)
}
