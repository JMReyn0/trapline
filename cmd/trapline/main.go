// Command trapline runs the sensor and prints alerts as newline-delimited
// JSON on stdout. Requires root (or CAP_BPF+CAP_PERFMON) to load BPF
// programs.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/justinmreynolds93-afk/trapline/internal/alert"
	"github.com/justinmreynolds93-afk/trapline/internal/event"
	"github.com/justinmreynolds93-afk/trapline/internal/rules"
	"github.com/justinmreynolds93-afk/trapline/internal/sensor"
)

func main() {
	rulesPath := flag.String("rules", "rules/default.yaml", "path to the YAML detection rules file")
	verbose := flag.Bool("verbose", false, "also print every observed event (to stderr), not just alerts")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("trapline needs root (or CAP_BPF+CAP_PERFMON) to load BPF programs")
	}

	loadedRules, err := rules.Load(*rulesPath)
	if err != nil {
		log.Fatalf("loading rules: %v", err)
	}
	engine := rules.NewEngine(loadedRules)
	log.Printf("loaded %d detection rules from %s", len(loadedRules), *rulesPath)

	sen, err := sensor.Open()
	if err != nil {
		log.Fatalf("opening sensor: %v", err)
	}
	defer sen.Close()
	log.Println("sensor attached: exec, connect, open")

	events := make(chan event.Event, 256)
	go func() {
		if err := sen.Run(events); err != nil {
			log.Printf("sensor run loop ended: %v", err)
		}
	}()

	alertWriter := alert.NewWriter(os.Stdout)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case e := <-events:
			if *verbose {
				fmt.Fprintln(os.Stderr, e.String())
			}
			for _, r := range engine.Evaluate(e) {
				if err := alertWriter.Write(alert.New(r, e)); err != nil {
					log.Printf("write alert: %v", err)
				}
			}
		case <-sigs:
			return
		}
	}
}
