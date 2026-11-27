package bpffsguard

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// bpffsMountPoints returns the mount points of every bpffs ("bpf") mount
// listed in a /proc/<pid>/mountinfo stream.
func bpffsMountPoints(r io.Reader) ([]string, error) {
	var points []string
	s := bufio.NewScanner(r)
	for s.Scan() {
		// <id> <parent> <maj:min> <root> <mountpoint> <opts> [optional...] - <fstype> <source> <superopts>
		fields := strings.Fields(s.Text())
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+1 >= len(fields) || fields[sep+1] != "bpf" {
			continue
		}
		points = append(points, unescapeMountinfo(fields[4]))
	}
	return points, s.Err()
}

// unescapeMountinfo decodes the octal escapes (\040, \011, \012, \134) the
// kernel uses for whitespace and backslashes in mountinfo paths.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
