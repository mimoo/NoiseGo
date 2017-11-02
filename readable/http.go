package noise

//
// This is creating functions similar to http.ListenAndServeTLS but for Noise
// honestly this is complicated, a lot of code needs to be changed, probably
// best is to add some examples as to how to make a http server with the code?
// or come back to this once the conn API has been implemented properly

/*
import "net"

// ListenAndServeTLS acts identically to ListenAndServe, except that it
// expects HTTPS connections. Additionally, files containing a certificate and
// matching private key for the server must be provided. If the certificate
// is signed by a certificate authority, the certFile should be the concatenation
// of the server's certificate, any intermediates, and the CA's certificate.
//
// A trivial example server is:
//
//	import (
//		"log"
//		"net/http"
//	)
//
//	func handler(w http.ResponseWriter, req *http.Request) {
//		w.Header().Set("Content-Type", "text/plain")
//		w.Write([]byte("This is an example server.\n"))
//	}
//
//	func main() {
//		http.HandleFunc("/", handler)
//		log.Printf("About to listen on 10443. Go to https://127.0.0.1:10443/")
//		err := http.ListenAndServeTLS(":10443", "cert.pem", "key.pem", nil)
//		log.Fatal(err)
//	}
//
// One can use generate_cert.go in crypto/tls to generate cert.pem and key.pem.
//
// ListenAndServeTLS always returns a non-nil error.
func ListenAndServeNoise(addr, certFile, keyFile string, handler Handler) error {

	server := &Server{Addr: addr, Handler: handler}

	return server.ListenAndServeNoise(certFile, keyFile)

}

// ListenAndServeTLS listens on the TCP network address srv.Addr and
// then calls Serve to handle requests on incoming TLS connections.
// Accepted connections are configured to enable TCP keep-alives.
//
// Filenames containing a certificate and matching private key for the
// server must be provided if neither the Server's TLSConfig.Certificates
// nor TLSConfig.GetCertificate are populated. If the certificate is
// signed by a certificate authority, the certFile should be the
// concatenation of the server's certificate, any intermediates, and
// the CA's certificate.
//
// If srv.Addr is blank, ":https" is used.
//
// ListenAndServeTLS always returns a non-nil error.
func (srv *Server) ListenAndServeNoise(certFile, keyFile string) error {

	addr := srv.Addr

	if addr == "" {

		addr = ":noise"

	}

	ln, err := net.Listen("tcp", addr)

	if err != nil {

		return err

	}

	return srv.ServeNoise(tcpKeepAliveListener{ln.(*net.TCPListener)}, certFile, keyFile)

}*/
