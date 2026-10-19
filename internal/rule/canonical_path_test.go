package rule

import (
	"strconv"
	"strings"
	"testing"
)

func TestCanonicalPath(t *testing.T) {
	cases := map[string]string{
		"":                                         "",
		"numbat.ts":                                "numbat.ts",
		"/etc/sudoers.d/agent":                     "/etc/sudoers.d/agent",
		"/etc/sudoers.d/./agent":                   "/etc/sudoers.d/agent",
		"/etc//sudoers.d/agent":                    "/etc/sudoers.d/agent",
		"/etc/sudoers.d/x/../agent":                "/etc/sudoers.d/agent",
		"/etc/sudoers.d/../sudoers":                "/etc/sudoers",
		"/../etc/sudoers":                          "/etc/sudoers",
		"/proc/self/root/etc/sudoers":              "/etc/sudoers",
		"/proc/4321/task/8765/root/etc/sudoers":    "/etc/sudoers",
		"/proc/thread-self/root":                   "/",
		"/proc/self/root":                          "/",
		"/proc/self/root/":                         "/",
		"/proc/self/root/proc/1/root":              "/",
		"/proc/self/root/proc/1/root/":             "/",
		"/proc/self/root//proc/1/root/etc/sudoers": "/etc/sudoers",
		"/proc/self/rootfs/etc/sudoers":            "/proc/self/rootfs/etc/sudoers",
		"~/.ssh/./authorized_keys":                 "~/.ssh/authorized_keys",
		"~//.ssh//authorized_keys":                 "~/.ssh/authorized_keys",
		"$HOME//.ssh/authorized_keys":              "$HOME/.ssh/authorized_keys",
		"$HOME/x/../.ssh/authorized_keys":          "$HOME/.ssh/authorized_keys",
		"~/../~/.ssh/authorized_keys":              "~/../~/.ssh/authorized_keys",
		"x/../~/.ssh/authorized_keys":              "x/../~/.ssh/authorized_keys",
		"C:/Users/dev/x/../.ssh/authorized_keys":   "C:/Users/dev/.ssh/authorized_keys",
		"C:/../C:/Users/dev/.ssh/authorized_keys":  "C:/../C:/Users/dev/.ssh/authorized_keys",
		"-f=/etc/sudoers.d/../sudoers":             "-f=/etc/sudoers",
		"-f=/../etc/sudoers":                       "-f=/etc/sudoers",
		"--file=/proc/self/root/etc/sudoers":       "--file=/etc/sudoers",
		"--file=/proc/self/root/":                  "--file=/",
		"/proc/self/root/proc/1/root/etc/sudoers":  "/etc/sudoers",
		"FILE=~//.ssh/authorized_keys":             "FILE=~/.ssh/authorized_keys",
		"/proc//self/root/etc/sudoers":             "/etc/sudoers",
		"/proc/./self/root/etc/sudoers":            "/etc/sudoers",
		"/etc/../proc/self/root/etc/sudoers":       "/etc/sudoers",
		"/proc/4321/task/./8765/root/etc/sudoers":  "/etc/sudoers",
		"/proc/self/root/../etc/sudoers":           "/etc/sudoers",
		"-f=/proc//self/root/etc/sudoers":          "-f=/etc/sudoers",
		"/etc/$PART/../sudoers":                    "/etc/$PART/../sudoers",
		"/home/$OTHER/../dev/.ssh/authorized_keys": "/home/$OTHER/../dev/.ssh/authorized_keys",
		"$HOME/$OTHER/../.ssh/authorized_keys":     "$HOME/$OTHER/../.ssh/authorized_keys",
		"/etc/`id`/../sudoers":                     "/etc/`id`/../sudoers",
	}
	for in, want := range cases {
		if got := canonicalPath(in); got != want {
			t.Errorf("canonicalPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalPathRepeatedRoots(t *testing.T) {
	value := strings.Repeat("/proc/self/root", 4096) + "/tmp/target"
	if got := canonicalPath(value); got != "/tmp/target" {
		t.Fatalf("canonicalPath with repeated roots = %q, want /tmp/target", got)
	}
}

func BenchmarkCanonicalPathRepeatedRoots(b *testing.B) {
	for _, count := range []int{256, 1024, 4096} {
		value := strings.Repeat("/proc/self/root", count) + "/tmp/target"
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(value)))
			for range b.N {
				if got := canonicalPath(value); got != "/tmp/target" {
					b.Fatalf("canonicalPath = %q, want /tmp/target", got)
				}
			}
		})
	}
}
