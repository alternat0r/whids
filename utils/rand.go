package utils

import (
	"crypto/rand"
	"fmt"

	"github.com/google/uuid"
)

func randByte() (byte, error) {
	var b [1]byte
	if _, err := rand.Reader.Read(b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// UnsafeUUID generates a random UUID.
//
// Despite the historical name, it is now backed by crypto/rand
// (uuid.NewRandom) rather than math/rand, which made command and drop-file
// identifiers predictable. The name is kept only for backward compatibility.
func UnsafeUUID() uuid.UUID {
	u, err := uuid.NewRandom()
	if err != nil {
		panic(fmt.Errorf("UnsafeUUID: failed to generate random uuid: %w", err))
	}
	return u
}

func UUIDOrPanic() (u uuid.UUID) {
	var err error

	if u, err = NewUUID(); err != nil {
		panic(err)
	}

	return
}

// UUIDGen generates a random UUID
func NewUUIDString() (string, error) {
	var u uuid.UUID
	var err error
	if u, err = NewUUID(); err != nil {
		return "", err
	}
	return u.String(), err
}

// NewUUID generates a random UUID
func NewUUID() (uuid.UUID, error) {
	return uuid.NewRandom()
}

func NewKeyOrPanic(size int) (key string) {
	var err error

	if key, err = NewKey(size); err != nil {
		panic(err)
	}

	return
}

// NewKey is an API key generator, supposed to generate an [[:alnum:]] key
func NewKey(size int) (key string, err error) {
	var b byte
	tmp := make([]byte, 0, size)
	for len(tmp) < size {
		//b := uint8(rand.Uint32() >> 24)
		if b, err = randByte(); err != nil {
			return
		}
		switch {
		case b > 47 && b < 58:
			// 0 to 9
			tmp = append(tmp, b)
		case b > 65 && b < 90:
			// A to Z
			tmp = append(tmp, b)
		case b > 96 && b < 123:
			// a to z
			tmp = append(tmp, b)
		}
	}
	key = string(tmp)
	return
}

func UUIDKeyPair(skey int) (suuid, key string, err error) {
	var u uuid.UUID

	if u, err = NewUUID(); err != nil {
		return
	}
	suuid = u.String()

	if key, err = NewKey(skey); err != nil {
		return
	}

	return
}
