// Copyright 2025 Edgeless Systems GmbH. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"os"
)

type Link struct {
	Arch
}

type Arch struct {
	ByteOrder binary.ByteOrder
	PtrSize   int
}

func main() {
	if err := elffips(&Link{Arch: Arch{ByteOrder: binary.LittleEndian, PtrSize: 8}}, os.Args[1], ""); err != nil {
		panic(err)
	}
}
