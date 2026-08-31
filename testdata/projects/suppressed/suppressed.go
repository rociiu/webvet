package suppressed

import "net/http"

func server() *http.Server {
	//webvet:ignore WEBVET-HTTP-001 -- deadline is enforced by a private ingress
	return &http.Server{Addr: ":8080"}
}
