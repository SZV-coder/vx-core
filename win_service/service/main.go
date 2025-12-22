// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

// Example service program that beeps.
//
// The program demonstrates how to create Windows service and
// install / remove it on a computer. It also shows how to
// stop / start / pause / continue any service, and how to
// write to event log. It also shows how to use debug
// facilities available in debug package.
package main

import (
	"fmt"
	"log"
	"os"
	"strings"
)

func usage(errmsg string) {
	fmt.Fprintf(os.Stderr,
		"%s\n\n"+
			"usage: %s <command>\n"+
			"       where <command> is one of\n"+
			"       install, remove, debug, start, stop, pause or continue.\n",
		errmsg, os.Args[0])
	os.Exit(2)
}

var svcName = "vx"

func main() {
	// flag.StringVar(&svcName, "name", svcName, "name of the service")
	// flag.Parse()

	if len(os.Args) < 2 {
		usage("no enough command specified")
	}

	var err error
	cmd := strings.ToLower(os.Args[1])
	switch cmd {
	case "install":
		// if len(os.Args) < 3 {
		// 	usage("no enough commands specified")
		// }
		err = installService(svcName, "vx service")
	case "remove":
		err = removeService(svcName)
	// case "start":
	// 	err = startService(svcName)
	// case "stop":
	// 	err = controlService(svcName, svc.Stop, svc.Stopped)
	// case "pause":
	// 	err = controlService(svcName, svc.Pause, svc.Paused)
	// case "continue":
	// 	err = controlService(svcName, svc.Continue, svc.Running)
	default:
		usage(fmt.Sprintf("invalid command %s", cmd))
	}
	if err != nil {
		log.Fatalf("failed to %s %s: %v", cmd, svcName, err)
	}
}
