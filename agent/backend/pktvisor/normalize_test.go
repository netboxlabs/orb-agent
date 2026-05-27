package pktvisor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripPktvisorPrefix_NoBrackets(t *testing.T) {
	assert.Equal(t, "hello world", stripPktvisorPrefix("hello world"))
}

func TestStripPktvisorPrefix_SingleBracket(t *testing.T) {
	assert.Equal(t, "hello", stripPktvisorPrefix("[INFO] hello"))
}

func TestStripPktvisorPrefix_MultipleBrackets(t *testing.T) {
	assert.Equal(t, "hello", stripPktvisorPrefix("[2024-01-01] [INFO] hello"))
}

func TestStripPktvisorPrefix_UnclosedBracket(t *testing.T) {
	assert.Equal(t, "[unclosed", stripPktvisorPrefix("[unclosed"))
}

func TestStripPktvisorPrefix_Empty(t *testing.T) {
	assert.Equal(t, "", stripPktvisorPrefix(""))
}

func TestParsePktvisorEntity_Tap(t *testing.T) {
	entity, name, rest, ok := parsePktvisorEntity("tap [default]: some message")
	assert.True(t, ok)
	assert.Equal(t, "tap", entity)
	assert.Equal(t, "default", name)
	assert.Equal(t, "some message", rest)
}

func TestParsePktvisorEntity_Policy(t *testing.T) {
	entity, name, rest, ok := parsePktvisorEntity("policy [my-policy]: applied")
	assert.True(t, ok)
	assert.Equal(t, "policy", entity)
	assert.Equal(t, "my-policy", name)
	assert.Equal(t, "applied", rest)
}

func TestParsePktvisorEntity_NoMatch(t *testing.T) {
	_, _, _, ok := parsePktvisorEntity("plain message")
	assert.False(t, ok)
}

func TestParsePktvisorEntity_EmptyName(t *testing.T) {
	_, _, _, ok := parsePktvisorEntity("tap []: message")
	assert.False(t, ok)
}

func TestParsePktvisorEntity_UnclosedBracket(t *testing.T) {
	_, _, _, ok := parsePktvisorEntity("tap [unclosed")
	assert.False(t, ok)
}

func TestParsePktvisorEntity_NoRest(t *testing.T) {
	entity, name, rest, ok := parsePktvisorEntity("tap [default]")
	assert.True(t, ok)
	assert.Equal(t, "tap", entity)
	assert.Equal(t, "default", name)
	assert.Equal(t, "", rest)
}

func TestNormalizePktvisorLine_Empty(t *testing.T) {
	msg, attrs := normalizePktvisorLine("")
	assert.Equal(t, "", msg)
	assert.Nil(t, attrs)
}

func TestNormalizePktvisorLine_PlainMessage(t *testing.T) {
	msg, attrs := normalizePktvisorLine("  hello world  ")
	assert.Equal(t, "hello world", msg)
	assert.Empty(t, attrs)
}

func TestNormalizePktvisorLine_WithBracketPrefix(t *testing.T) {
	msg, attrs := normalizePktvisorLine("[INFO] hello world")
	assert.Equal(t, "hello world", msg)
	assert.Empty(t, attrs)
}

func TestNormalizePktvisorLine_TapEntity(t *testing.T) {
	msg, attrs := normalizePktvisorLine("tap [default]: started")
	assert.NotEmpty(t, msg)
	assert.Len(t, attrs, 1)
	assert.Equal(t, "tap", attrs[0].Key)
	assert.Equal(t, "default", attrs[0].Value.String())
}

func TestNormalizePktvisorLine_PolicyEntity(t *testing.T) {
	msg, attrs := normalizePktvisorLine("policy [my-policy]: applied")
	assert.NotEmpty(t, msg)
	assert.Len(t, attrs, 1)
	assert.Equal(t, "policy", attrs[0].Key)
}

func TestNormalizePktvisorLine_EntityNoRest(t *testing.T) {
	msg, attrs := normalizePktvisorLine("tap [default]")
	assert.Equal(t, "tap", msg)
	assert.Len(t, attrs, 1)
}
