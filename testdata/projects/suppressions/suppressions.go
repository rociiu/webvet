package suppressions

import "net/http"

func servers() {
	//webvet:ignore WEBVET-HTTP-001 -- ingress owns the deadline
	_ = &http.Server{Addr: ":1"}

	//webvet:ignore WEBVET-HTTP-001
	_ = &http.Server{Addr: ":2"}

	//webvet:ignore WEBVET-COOKIE-001 -- unrelated rule
	_ = &http.Server{Addr: ":3"}

	//webvet:ignore WEBVET-HTTP-001 -- too far from target
	_ = 1
	_ = 2
	_ = &http.Server{Addr: ":4"}
}
