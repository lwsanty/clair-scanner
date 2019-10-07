package server

import (
	"net/http"
	"time"

	"gopkg.in/src-d/go-log.v1"
)

const (
	HttpPort = "9279"
)

// HttpFileServer servers files from a specified folder
// TODO if port can't be opened is not handled
func HttpFileServer(path string) *http.Server {
	server := &http.Server{Addr: ":" + HttpPort}
	http.Handle("/", http.FileServer(http.Dir(path)))
	go func() {
		server.ListenAndServe()
	}()
	time.Sleep(100 * time.Millisecond) // It takes some time to open the port, just to be sure we wait a bit
	log.Infof("Server listening on port %s", HttpPort)
	return server
}
