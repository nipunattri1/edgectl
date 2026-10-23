package bpf

import (
	"net"
)

type IPNet struct {
	IP        net.IP
	PrefixLen int
	Family    string
}