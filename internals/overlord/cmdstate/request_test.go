// Copyright (c) 2026 Canonical Ltd
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 3 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmdstate_test

import (
	"os"
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/canonical/pebble/internals/overlord/cmdstate"
	"github.com/canonical/pebble/internals/overlord/state"
	"github.com/canonical/pebble/internals/testutil"
)

type requestSuite struct {
	testutil.BaseTest
}

var _ = Suite(&requestSuite{})

func (s *requestSuite) TestGetWorkingDirBothEmpty(c *C) {
	dir, err := cmdstate.GetWorkingDir("", "")
	c.Assert(err, IsNil)
	c.Assert(dir, Equals, "/")
}

func (s *requestSuite) TestGetWorkingDirUsesHomeWhenWorkingDirEmpty(c *C) {
	home := c.MkDir()
	dir, err := cmdstate.GetWorkingDir("", home)
	c.Assert(err, IsNil)
	c.Assert(dir, Equals, home)
}

func (s *requestSuite) TestGetWorkingDirExplicit(c *C) {
	wd := c.MkDir()
	dir, err := cmdstate.GetWorkingDir(wd, "")
	c.Assert(err, IsNil)
	c.Assert(dir, Equals, wd)
}

func (s *requestSuite) TestGetWorkingDirExplicitTakesPrecedenceOverHome(c *C) {
	wd := c.MkDir()
	home := c.MkDir()
	dir, err := cmdstate.GetWorkingDir(wd, home)
	c.Assert(err, IsNil)
	c.Assert(dir, Equals, wd)
}

func (s *requestSuite) TestGetWorkingDirNotExist(c *C) {
	_, err := cmdstate.GetWorkingDir("/does/not/exist", "")
	c.Assert(err, ErrorMatches, `working directory "/does/not/exist" does not exist`)
}

func (s *requestSuite) TestGetWorkingDirHomeNotExist(c *C) {
	_, err := cmdstate.GetWorkingDir("", "/does/not/exist")
	c.Assert(err, ErrorMatches, `home directory "/does/not/exist" does not exist`)
}

func (s *requestSuite) TestGetWorkingDirNotADirectory(c *C) {
	f := filepath.Join(c.MkDir(), "file.txt")
	err := os.WriteFile(f, []byte("data"), 0644)
	c.Assert(err, IsNil)

	_, err = cmdstate.GetWorkingDir(f, "")
	c.Assert(err, ErrorMatches, `working directory ".*" not a directory`)
}

func (s *requestSuite) TestGetWorkingDirHomeNotADirectory(c *C) {
	f := filepath.Join(c.MkDir(), "file.txt")
	err := os.WriteFile(f, []byte("data"), 0644)
	c.Assert(err, IsNil)

	_, err = cmdstate.GetWorkingDir("", f)
	c.Assert(err, ErrorMatches, `home directory ".*" not a directory`)
}

func (s *requestSuite) TestExecInteractiveWithoutTerminalErrors(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	_, _, err := cmdstate.Exec(st, &cmdstate.ExecArgs{
		Command:     []string{"/bin/true"},
		Interactive: true,
		Terminal:    false,
	})
	c.Assert(err, ErrorMatches, "cannot use interactive mode without a terminal")
}

func (s *requestSuite) TestExecCreatesTaskWithCorrectKind(c *C) {
	s.AddCleanup(cmdstate.FakeEnviron(func() map[string]string {
		return map[string]string{"HOME": c.MkDir()}
	}))

	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	task, _, err := cmdstate.Exec(st, &cmdstate.ExecArgs{
		Command: []string{"/bin/true"},
	})
	c.Assert(err, IsNil)
	c.Assert(task.Kind(), Equals, "exec")
	c.Assert(task.Summary(), Equals, `Execute command "/bin/true"`)
}

func (s *requestSuite) TestExecMetadataTaskID(c *C) {
	s.AddCleanup(cmdstate.FakeEnviron(func() map[string]string {
		return map[string]string{"HOME": c.MkDir()}
	}))

	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	task, metadata, err := cmdstate.Exec(st, &cmdstate.ExecArgs{
		Command: []string{"/bin/true"},
	})
	c.Assert(err, IsNil)
	c.Assert(metadata.TaskID, Equals, task.ID())
}

func (s *requestSuite) TestExecMetadataWorkingDir(c *C) {
	wd := c.MkDir()
	s.AddCleanup(cmdstate.FakeEnviron(func() map[string]string {
		return map[string]string{}
	}))

	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	_, metadata, err := cmdstate.Exec(st, &cmdstate.ExecArgs{
		Command:    []string{"/bin/true"},
		WorkingDir: wd,
	})
	c.Assert(err, IsNil)
	c.Assert(metadata.WorkingDir, Equals, wd)
}

func (s *requestSuite) TestExecMetadataEnvironmentContainsEnvVars(c *C) {
	home := c.MkDir()
	s.AddCleanup(cmdstate.FakeEnviron(func() map[string]string {
		return map[string]string{"HOME": home}
	}))

	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	_, metadata, err := cmdstate.Exec(st, &cmdstate.ExecArgs{
		Command: []string{"/bin/true"},
	})
	c.Assert(err, IsNil)
	c.Assert(metadata.Environment, NotNil)
	c.Assert(metadata.Environment["HOME"], Equals, home)
}

func (s *requestSuite) TestExecArgsEnvironmentOverridesInherited(c *C) {
	s.AddCleanup(cmdstate.FakeEnviron(func() map[string]string {
		return map[string]string{
			"HOME":   c.MkDir(),
			"CUSTOM": "inherited",
		}
	}))

	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	_, metadata, err := cmdstate.Exec(st, &cmdstate.ExecArgs{
		Command: []string{"/bin/true"},
		Environment: map[string]string{
			"CUSTOM": "override",
		},
	})
	c.Assert(err, IsNil)
	c.Assert(metadata.Environment["CUSTOM"], Equals, "override")
}

func (s *requestSuite) TestExecDefaultPathIsSet(c *C) {
	// When the inherited environment has no PATH, a sensible default
	// is used.
	s.AddCleanup(cmdstate.FakeEnviron(func() map[string]string {
		return map[string]string{"HOME": c.MkDir()}
	}))

	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	_, metadata, err := cmdstate.Exec(st, &cmdstate.ExecArgs{
		Command: []string{"/bin/true"},
	})
	c.Assert(err, IsNil)
	c.Assert(
		metadata.Environment["PATH"],
		Equals,
		"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	)
}

func (s *requestSuite) TestExecExplicitPathIsPreserved(c *C) {
	s.AddCleanup(cmdstate.FakeEnviron(func() map[string]string {
		return map[string]string{"HOME": c.MkDir()}
	}))

	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	_, metadata, err := cmdstate.Exec(st, &cmdstate.ExecArgs{
		Command:     []string{"/bin/true"},
		Environment: map[string]string{"PATH": "/custom/bin"},
	})
	c.Assert(err, IsNil)
	c.Assert(metadata.Environment["PATH"], Equals, "/custom/bin")
}

func (s *requestSuite) TestExecDefaultLangIsSet(c *C) {
	// When neither the inherited environment nor args contain LANG, the
	// default "C.UTF-8" is used.
	s.AddCleanup(cmdstate.FakeEnviron(func() map[string]string {
		return map[string]string{"HOME": c.MkDir()}
	}))

	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	_, metadata, err := cmdstate.Exec(st, &cmdstate.ExecArgs{
		Command: []string{"/bin/true"},
	})
	c.Assert(err, IsNil)
	c.Assert(metadata.Environment["LANG"], Equals, "C.UTF-8")
}

func (s *requestSuite) TestExecExplicitLangIsPreserved(c *C) {
	s.AddCleanup(cmdstate.FakeEnviron(func() map[string]string {
		return map[string]string{"HOME": c.MkDir()}
	}))

	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	_, metadata, err := cmdstate.Exec(st, &cmdstate.ExecArgs{
		Command:     []string{"/bin/true"},
		Environment: map[string]string{"LANG": "en_AU.UTF-8"},
	})
	c.Assert(err, IsNil)
	c.Assert(metadata.Environment["LANG"], Equals, "en_AU.UTF-8")
}

func (s *requestSuite) TestExecWorkingDirDefaultsToHome(c *C) {
	home := c.MkDir()
	s.AddCleanup(cmdstate.FakeEnviron(func() map[string]string {
		return map[string]string{"HOME": home}
	}))

	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	_, metadata, err := cmdstate.Exec(st, &cmdstate.ExecArgs{
		Command: []string{"/bin/true"},
	})
	c.Assert(err, IsNil)
	c.Assert(metadata.WorkingDir, Equals, home)
}

func (s *requestSuite) TestExecWorkingDirDoesNotExistErrors(c *C) {
	s.AddCleanup(cmdstate.FakeEnviron(func() map[string]string {
		return map[string]string{}
	}))

	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	_, _, err := cmdstate.Exec(st, &cmdstate.ExecArgs{
		Command:    []string{"/bin/true"},
		WorkingDir: "/no/such/directory",
	})
	c.Assert(err, ErrorMatches, `working directory "/no/such/directory" does not exist`)
}

func (s *requestSuite) TestExecSetupCachedOnState(c *C) {
	home := c.MkDir()
	s.AddCleanup(cmdstate.FakeEnviron(func() map[string]string {
		return map[string]string{"HOME": home}
	}))

	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	task, _, err := cmdstate.Exec(st, &cmdstate.ExecArgs{
		Command: []string{"/bin/echo", "hello"},
	})
	c.Assert(err, IsNil)

	// The execSetup should be stored in the state cache under the task's ID.
	cached := st.Cached(cmdstate.NewExecSetupKey(task.ID()))
	c.Assert(cached, NotNil)
}
