package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/theredrad/certauthz/server/handler"
	"github.com/theredrad/certauthz/server/web"
)

var (
	primaryName = "primary"
	host        = "0.0.0.0"
	port        = 8585
	path        = "../credentials"
)

func init() {
	flag.StringVar(&primaryName, "primary-name", "primary", "primary name including ca certificate and public key")
	flag.StringVar(&host, "host", "0.0.0.0", "server host")
	flag.StringVar(&path, "path", "../credentials", "credentials path")
	flag.IntVar(&port, "port", 8585, "server port")
	flag.Parse()
}

func main() {
	h := handler.Handler{}

	certMiddleware, err := web.NewCertificateMiddleware(fmt.Sprintf("%s/%s/ca_certificate.crt", path, primaryName))
	if err != nil {
		log.Fatal(err)
	}

	jwtMiddleware, err := web.NewJWTokenMiddleware(fmt.Sprintf("%s/%s/public.pub", path, primaryName))
	if err != nil {
		log.Fatal(err)
	}

	// wrap the handler with JWT middleware
	clientWithTokenHandler := web.WrapMiddlewares([]web.Middlware{
		jwtMiddleware.Handle,
	}, h.Handle)

	// wrap the handler with certificate middleware
	clientWithCertHandler := web.WrapMiddlewares([]web.Middlware{
		certMiddleware.Handle,
	}, h.Handle)

	mux := http.NewServeMux()
	mux.HandleFunc("/token", clientWithTokenHandler)
	mux.HandleFunc("/cert", clientWithCertHandler)

	server := http.Server{
		Addr:    fmt.Sprintf("%s:%d", host, port),
		Handler: mux,
	}

	serverErr := make(chan error, 1)
	go func() {
		fmt.Printf("listening on %s:%d\n", host, port)
		serverErr <- server.ListenAndServe()
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case s := <-sig:
		log.Printf("received os signal: %s", s)
	case err = <-serverErr:
		log.Fatalf("server error: %s", err)
	}
}
