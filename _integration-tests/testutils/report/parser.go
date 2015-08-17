// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2015 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package report

import (
	"fmt"
	"io"
	"os/exec"
	"regexp"
)

const (
	commonPattern       = `(?U)%s\: \/.*: (.*)`
	announcePattern     = `(?U)\*\*\*\*\*\* Running (.*)\n`
	successPatternSufix = `\s*\d*\.\d*s\n`
	skipPatternSufix    = `\s*\((.*)\)\n`
)

var (
	announceRegexp = regexp.MustCompile(announcePattern)
	successRegexp  = regexp.MustCompile(fmt.Sprintf(commonPattern, "PASS") + successPatternSufix)
	failureRegexp  = regexp.MustCompile(fmt.Sprintf(commonPattern, "FAIL") + "\n")
	skipRegexp     = regexp.MustCompile(fmt.Sprintf(commonPattern, "SKIP") + skipPatternSufix)
)

// ParserReporter is a type implementing io.Writer that
// parses the input data and sends the results to the Next
// reporter
//
// The input data is expected to be of the form of the textual
// output of gocheck with verbose mode enabled, and the output
// will be subunit protocol version 2. There are constants reflecting the
// expected patterns for this texts. Additionally, it doesn't take  into
// account the SKIPs done from a SetUpTest method, due to the nature of the
// snappy test suite we are using those for resuming execution after a reboot
// and they shouldn't be reflected as skipped tests in the final
// output. For the same reason we use a special marker for the
// test's announce.
type ParserReporter struct {
	Next io.Writer
}

func (fr *ParserReporter) Write(data []byte) (n int, err error) {
	var output []byte

	if matches := announceRegexp.FindStringSubmatch(string(data)); len(matches) == 2 {
		output, err = exec.Command(
			"subunit-output", "--exists", matches[1]).Output()
	} else if matches := successRegexp.FindStringSubmatch(string(data)); len(matches) == 2 {
		output, err = exec.Command(
			"subunit-output", "--success", matches[1]).Output()
	} else if matches := failureRegexp.FindStringSubmatch(string(data)); len(matches) == 2 {
		output, err = exec.Command("subunit-output", "--fail", matches[1]).Output()

	} else if matches := skipRegexp.FindStringSubmatch(string(data)); len(matches) == 3 {
		output, err = exec.Command("subunit-output", "--skip", matches[1]).Output()
		// matches[2]
	}

	if err == nil {
		n = len(output)
		fr.Next.Write(output)
	}
	return
}
