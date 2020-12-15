package dht

import (
	"encoding/base64"
	"fmt"

	"github.com/esote/dht/core"
)

func nodeToString(n *core.NodeTriple) string {
	return fmt.Sprintf("%s %s:%d", base64.RawURLEncoding.EncodeToString(n.ID), n.IP, n.Port)
}
