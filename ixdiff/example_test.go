package ixdiff_test

import (
	"fmt"
	"log"

	"github.com/loov/ixdiff/ixdiff"
)

// Example compares two builds of a program and prints which functions
// changed and by how much.
func Example() {
	old, err := ixdiff.Open("app.v1")
	if err != nil {
		log.Fatal(err)
	}
	defer old.Close()
	new, err := ixdiff.Open("app.v2")
	if err != nil {
		log.Fatal(err)
	}
	defer new.Close()

	diff, err := ixdiff.Compare(old, new, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("total text size delta: %+d bytes\n", diff.SizeDelta())
	for _, p := range diff.Pairs() {
		if p.State != ixdiff.Changed {
			continue
		}
		fmt.Printf("%s: %+d bytes, %+d instructions\n", p.Name, p.SizeDelta, p.InstDelta)
		lines, err := diff.Lines(p)
		if err != nil {
			log.Fatal(err)
		}
		for _, l := range lines {
			fmt.Printf("%c %s\n", " -+"[l.Op], l.Text)
		}
	}
}
