package sessiontest

import (
	"testing"
	"time"

	"DVGA/internal/session"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSigned_ValidToken(t *testing.T) {
	m := session.NewManager()
	token := m.CreateSigned(1, "admin", "admin")
	require.NotEmpty(t, token)

	sess := m.GetSigned(token)
	require.NotNil(t, sess)
	assert.Equal(t, 1, sess.UserID)
	assert.Equal(t, "admin", sess.Username)
	assert.Equal(t, "admin", sess.Role)
}

func TestGetSigned_TamperedPayload(t *testing.T) {
	m := session.NewManager()
	token := m.CreateSigned(1, "gordonb", "user")

	runes := []rune(token)
	runes[0] = 'X'
	tampered := string(runes)

	assert.Nil(t, m.GetSigned(tampered), "tampered token must be rejected")
}

func TestGetSigned_TamperedSignature(t *testing.T) {
	m := session.NewManager()
	token := m.CreateSigned(1, "gordonb", "user")

	last := len(token) - 1
	corrupted := token[:last] + "X"

	assert.Nil(t, m.GetSigned(corrupted), "corrupted signature must be rejected")
}

func TestGetSigned_WrongSecret(t *testing.T) {
	m1 := session.NewManager()
	m2 := session.NewManager()

	token := m1.CreateSigned(1, "admin", "admin")
	assert.Nil(t, m2.GetSigned(token), "token from different secret must be rejected")
}

func TestGetSigned_MalformedToken(t *testing.T) {
	m := session.NewManager()
	assert.Nil(t, m.GetSigned("notavalidtoken"))
	assert.Nil(t, m.GetSigned(""))
	assert.Nil(t, m.GetSigned("a.b.c"))
}

func TestGetSigned_RoleCannotBeElevated(t *testing.T) {
	m := session.NewManager()
	token := m.CreateSigned(2, "gordonb", "user")

	sess := m.GetSigned(token)
	require.NotNil(t, sess)
	assert.Equal(t, "user", sess.Role)
	assert.NotEqual(t, "admin", sess.Role)
}

func TestGetSigned_TokenIsValidNow(t *testing.T) {
	m := session.NewManager()
	token := m.CreateSigned(1, "admin", "admin")
	sess := m.GetSigned(token)
	require.NotNil(t, sess)
	assert.True(t, sess.CreatedAt.Before(time.Now().Add(time.Second)))
}
