package stateless

import (
	"iter"

	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/header"
)

// TODO: Why seq2 in message?
func headersVia(hdrs sip.Headers) iter.Seq[header.ViaHop] {
	return func(yield func(header.ViaHop) bool) {
		for _, hdr := range hdrs.Get("Via") {
			if via, ok := hdr.(header.Via); ok {
				for j := range via {
					if !yield(via[j]) {
						return
					}
				}
			}
		}
	}
}
