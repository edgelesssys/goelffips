// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// EDG: This is https://github.com/golang/go/blob/36bca3166e18db52687a4d91ead3f98ffe6d00b8/src/cmd/link/internal/ld/fips140.go with unused code removed.

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
)

const (
	fipsMagicLen = 16
	fipsSumLen   = 32
)

// fipsObj calculates the fips object hash and optionally writes
// the hashed content to a file for debugging.
type fipsObj struct {
	r   io.ReaderAt
	w   io.Writer
	wf  *os.File
	h   hash.Hash
	tmp [8]byte
}

// newFipsObj creates a fipsObj reading from r and writing to fipso
// (unless fipso is the empty string, in which case it writes nowhere
// and only computes the hash).
func newFipsObj(r io.ReaderAt, fipso string) (*fipsObj, error) {
	f := &fipsObj{r: r}
	f.h = hmac.New(sha256.New, make([]byte, 32))
	f.w = f.h
	if fipso != "" {
		wf, err := os.Create(fipso)
		if err != nil {
			return nil, err
		}
		f.wf = wf
		f.w = io.MultiWriter(f.h, wf)
	}

	if _, err := f.w.Write([]byte("go fips object v1\n")); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// addSection adds the section of r (passed to newFipsObj)
// starting at byte offset start and ending before byte offset end
// to the fips object file.
func (f *fipsObj) addSection(start, end int64) error {
	n := end - start
	binary.BigEndian.PutUint64(f.tmp[:], uint64(n))
	f.w.Write(f.tmp[:])
	_, err := io.Copy(f.w, io.NewSectionReader(f.r, start, n))
	return err
}

// sum returns the hash of the fips object file.
func (f *fipsObj) sum() []byte {
	return f.h.Sum(nil)
}

// Close closes the fipsObj. In particular it closes the output
// object file specified by fipso in the call to [newFipsObj].
func (f *fipsObj) Close() error {
	if f.wf != nil {
		return f.wf.Close()
	}
	return nil
}

// elffips updates go:fipsinfo after external linking
// on systems using ELF (most Unix systems).
func elffips(ctxt *Link, exe, fipso string) error {
	// Open executable both for reading ELF and for the fipsObj.
	ef, err := elf.Open(exe)
	if err != nil {
		return err
	}
	defer ef.Close()

	wf, err := os.OpenFile(exe, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer wf.Close()

	f, err := newFipsObj(wf, fipso)
	if err != nil {
		return err
	}
	defer f.Close()

	// Find the go:fipsinfo symbol.
	sect := ef.Section(".go.fipsinfo")
	if sect == nil {
		return fmt.Errorf("cannot find .go.fipsinfo")
	}

	data, err := sect.Data()
	if err != nil {
		return err
	}

	uptr := ctxt.Arch.ByteOrder.Uint64
	if ctxt.Arch.PtrSize == 4 {
		uptr = func(x []byte) uint64 {
			return uint64(ctxt.Arch.ByteOrder.Uint32(x))
		}
	}

	// Add the sections listed in go:fipsinfo to the FIPS object.
	// We expect R_zzz_RELATIVE relocations where the zero-based
	// values are already stored in the data. That is, the addend
	// is in the data itself in addition to being in the relocation tables.
	// So no need to parse the relocation tables unless we find a
	// toolchain that doesn't initialize the data this way.
	// For non-pie builds, there are no relocations at all:
	// the data holds the actual pointers.
	// This code handles both pie and non-pie binaries.
	data = data[fipsMagicLen+fipsSumLen:]
	data = data[ctxt.Arch.PtrSize:]

Addrs:
	for i := 0; i < 4; i++ {
		start := uptr(data[0:])
		end := uptr(data[ctxt.Arch.PtrSize:])
		data = data[2*ctxt.Arch.PtrSize:]
		for _, prog := range ef.Progs {
			if prog.Type == elf.PT_LOAD && prog.Vaddr <= start && start <= end && end <= prog.Vaddr+prog.Filesz {
				if err := f.addSection(int64(start+prog.Off-prog.Vaddr), int64(end+prog.Off-prog.Vaddr)); err != nil {
					return err
				}
				continue Addrs
			}
		}
		return fmt.Errorf("invalid pointers found in .go.fipsinfo")
	}

	// Overwrite the go:fipsinfo sum field with the calculated sum.
	if _, err := wf.WriteAt(f.sum(), int64(sect.Offset)+fipsMagicLen); err != nil {
		return err
	}
	if err := wf.Close(); err != nil {
		return err
	}
	return f.Close()
}
