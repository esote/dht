package dht

import (
	"encoding/base64"
	"fmt"

	"github.com/esote/dht/core"
)

func nodeToString(n *core.NodeTriple) string {
	return fmt.Sprintf("%s %s:%d", base64.RawURLEncoding.EncodeToString(n.ID), n.IP, n.Port)
}

func msgTypeString(t uint8) string {
	switch t {
	case core.TypePing:
		return "PING"
	case core.TypeStore:
		return "STORE"
	case core.TypeData:
		return "DATA"
	case core.TypeFindNode:
		return "FIND_NODE"
	case core.TypeFindNodeResp:
		return "FIND_NODE_RESP"
	case core.TypeFindValue:
		return "FIND_VALUE"
	case core.TypeError:
		return "ERROR"
	default:
		return "<nil>"
	}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
