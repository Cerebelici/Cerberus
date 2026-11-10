package main

import (
	"context"
	"embed"
	"io"
	"log"
	"os"
	"time"

	"github.com/gr0gu/cerberus/internal/app"
	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/logstream"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

// logHistory is how many daemon log lines the Debug page can show.
const logHistory = 2000

func main() {
	// Keep the daemon log in memory for the Debug page, and still write it to stderr.
	logs := logstream.New(logHistory)
	log.SetOutput(io.MultiWriter(os.Stderr, logs))

	cfg := config.Load()
	if cfg.DBPath == "cerberus.db" {
		cfg.DBPath = config.OSDataDir("cerberus", "cerberus.db")
	}
	// Desktop talks to the daemon over Wails IPC. The only HTTP listener is the loopback
	// agent ingest endpoint, which stays on 127.0.0.1 unless explicitly disabled.

	d := app.New(cfg)
	d.SetLogs(logs)
	b := NewBridge(d)

	err := wails.Run(&options.App{
		Title:  "Cerberus Sentinel",
		Width:  1280,
		Height: 820,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "io.github.gr0gu.cerberus",
			OnSecondInstanceLaunch: func(options.SecondInstanceData) {
				if b.ctx != nil {
					runtime.WindowShow(b.ctx)
				}
			},
		},
		OnStartup: func(ctx context.Context) {
			b.SetContext(ctx)
			logs.Subscribe(func(entry logstream.Entry) {
				runtime.EventsEmit(ctx, "cerberus:log", entry)
			})
			d.SetScanEventEmitter(func(event string, data any) {
				runtime.EventsEmit(ctx, event, data)
			})
			if err := d.Start(context.Background()); err != nil {
				runtime.MessageDialog(ctx, runtime.MessageDialogOptions{
					Type:    runtime.ErrorDialog,
					Title:   "Cerberus Failed to Start",
					Message: err.Error(),
				})
				runtime.Quit(ctx)
				return
			}
			go func() {
				for err := range d.Errors() {
					runtime.EventsEmit(ctx, "daemon:error", err.Error())
				}
			}()
		},
		OnShutdown: func(context.Context) {
			sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = d.Stop(sctx)
		},
		Bind: []interface{}{b},
	})
	if err != nil {
		log.Fatal(err)
	}
}
