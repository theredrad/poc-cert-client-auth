package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	coreTLS "github.com/theredrad/certauthz/core/tls"
	"github.com/theredrad/certauthz/server/handler"
	"github.com/theredrad/certauthz/server/web"
)

var (
	primaryName      = "primary"
	serverClientName = "bob"
	host             = "0.0.0.0"
	port             = 8585
	path             = "../credentials"
	mtls             = false
)

func init() {
	flag.StringVar(&primaryName, "primary-name", "primary", "primary name including ca certificate and public key")
	flag.StringVar(&serverClientName, "server-client-name", "bob", "server directory including server certificate and private key")
	flag.StringVar(&host, "host", "0.0.0.0", "server host")
	flag.StringVar(&path, "path", "../credentials", "credentials path")
	flag.IntVar(&port, "port", 8585, "server port")
	flag.BoolVar(&mtls, "mtls", false, "enable mtls, custom authentication is disabled")
	flag.Parse()
}

func main() {
	h := handler.Handler{}

	mux := http.NewServeMux()

	var tlsConfig *tls.Config
	if !mtls {
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

		mux.HandleFunc("/token", clientWithTokenHandler)
		mux.HandleFunc("/cert", clientWithCertHandler)

		fmt.Println("TLS is disabled")
	} else {
		var err error
		tlsConfig, err = coreTLS.NewServerConfig(
			fmt.Sprintf("%s/%s/ca_certificate.crt", path, primaryName),
			fmt.Sprintf("%s/%s/certificate.crt", path, serverClientName),
			fmt.Sprintf("%s/%s/private.key", path, serverClientName),
			fmt.Sprintf("%s.", serverClientName), // the client certificate must have at least one scope with a "[ServerClientName]." prefix to handshake, e.g. bob.*
		)
		if err != nil {
			log.Fatal(err)
		}

		tlsMiddleware := web.NewTLSCertificateMiddleware()

		clientWithTLSHandler := web.WrapMiddlewares([]web.Middlware{
			tlsMiddleware.Handle,
		}, h.Handle)

		mux.HandleFunc("/", clientWithTLSHandler)

		fmt.Println("TLS is enabled")
	}

	server := http.Server{
		Addr:      fmt.Sprintf("%s:%d", host, port),
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	serverErr := make(chan error, 1)
	go func() {
		fmt.Printf("listening on %s:%d\n", host, port)

		if !mtls {
			serverErr <- server.ListenAndServe()
			return
		}

		serverErr <- server.ListenAndServeTLS("", "")
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case s := <-sig:
		log.Printf("received os signal: %s", s)
	case err := <-serverErr:
		log.Fatalf("server error: %s", err)
	}
}
