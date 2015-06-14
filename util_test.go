package haproxy

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_FindStringSubmatchMap_MatchAll(t *testing.T) {
	pattern := `(?P<first_name>\w+) (?P<last_name>\w+)`
	re := myRegexp{regexp.MustCompile(pattern)}
	match := re.FindStringSubmatchMap("John Wayne")

	assert.Equal(t, 2, len(match), "Length of map[] should be 2")

	assert.Equal(t, "John", match["first_name"], "First string group should match")
	assert.Equal(t, "Wayne", match["last_name"], "Last string group should match")
}

func Test_FindStringSubmatchMap_NoMatch(t *testing.T) {
	pattern := `(?P<first_name>\w+) (?P<last_name>\w+)`
	re := myRegexp{regexp.MustCompile(pattern)}
	match := re.FindStringSubmatchMap("JohnWayne")

	assert.Equal(t, 0, len(match), "Length of map[] should be 0")
}

func Test_FindStringSubmatchMap_MatchUnnamedGroups(t *testing.T) {
	pattern := `((?P<first_name>\w+)(\s)(?P<last_name>\w+))`
	re := myRegexp{regexp.MustCompile(pattern)}
	match := re.FindStringSubmatchMap("John Wayne")

	assert.Equal(t, 2, len(match), "Length of match map[] should only include matched groups")
}

func Test_FindStringSubmatchMap_MatchSome(t *testing.T) {
	pattern := `(?P<first_name>\w+)( (?P<last_name>\w+))?`
	re := myRegexp{regexp.MustCompile(pattern)}
	match := re.FindStringSubmatchMap("John")

	assert.Equal(t, 2, len(match), "Length of map[] should be 2")

	assert.Equal(t, "John", match["first_name"], "First string group should match")
	assert.Equal(t, "", match["last_name"], "Last string group should be empty string")
}
