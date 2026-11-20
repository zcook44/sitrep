package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "time/tzdata"

	"github.com/zcook44/sitrep/internal/demo"
	"github.com/zcook44/sitrep/internal/posture"
	"github.com/zcook44/sitrep/internal/session"
	"github.com/zcook44/sitrep/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "demo-data" {
		out := ""
		args := os.Args[2:]
		for i := 0; i < len(args); i++ {
			if args[i] == "--out" && i+1 < len(args) {
				i++
				out = args[i]
			}
		}
		if out == "" {
			fmt.Fprintln(os.Stderr, "usage: sitrep demo-data --out DIR")
			os.Exit(1)
		}
		if err := demo.Write(out); err != nil {
			fmt.Fprintf(os.Stderr, "sitrep: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("wrote checklist tree at %s\n", out)
		return
	}

	useHostZone()
	root := os.Getenv("CHECKLIST_ROOT")
	if root == "" {
		root = "/data"
	}
	port := 8780
	if raw := os.Getenv("PORT"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 65535 {
			fmt.Fprintf(os.Stderr, "sitrep: invalid PORT %q\n", raw)
			os.Exit(1)
		}
		port = parsed
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/posture", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Not found\n", http.StatusNotFound)
			return
		}
		body, err := posture.Collect(root)
		if err != nil {
			log.Printf("posture: %v", err)
			http.Error(w, "The checklist tree could not be read.\n", http.StatusInternalServerError)
			return
		}
		writeJSON(w, body)
	})
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, session.For(r.Header))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.Error(w, "Not found\n", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(web.IndexHTML)
	})
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	log.Printf("sitrep reading %s on %d", root, port)
	server := &http.Server{Addr: addr, Handler: mux}
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "sitrep: %v\n", err)
		os.Exit(1)
	}
}

func writeJSON(w http.ResponseWriter, body any) {
	raw, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "The checklist tree could not be read.\n", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(raw)
}

func useHostZone() {
	if os.Getenv("TZ") != "" {
		if loc, err := time.LoadLocation(os.Getenv("TZ")); err == nil {
			time.Local = loc
		}
		return
	}
	for _, path := range []string{"/etc/localtime", "/host/localtime"} {
		target, err := os.Readlink(path)
		if err == nil {
			const marker = "zoneinfo/"
			if i := strings.Index(target, marker); i >= 0 {
				if loc, err := time.LoadLocation(target[i+len(marker):]); err == nil {
					time.Local = loc
					return
				}
			}
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) < 4 || string(data[:4]) != "TZif" {
			continue
		}
		loc, err := time.LoadLocationFromTZData("Local", data)
		if err == nil {
			time.Local = loc
			return
		}
	}
}
