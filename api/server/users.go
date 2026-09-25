package server

import (
	"github.com/0xrawsec/sod"
)

// AdminAPIUser structure definition
type AdminAPIUser struct {
	sod.Item
	Uuid        string `json:"uuid" sod:"unique"`
	Identifier  string `json:"identifier" sod:"unique"`
	Key         string `json:"key,omitempty" sod:"unique"`
	Group       string `json:"group" sod:"index"`
	Description string `json:"description"`
}

// Copy returns a pointer to a new copy of the AdminAPIUser
func (u *AdminAPIUser) Copy() *AdminAPIUser {
	new := *u
	return &new
}
