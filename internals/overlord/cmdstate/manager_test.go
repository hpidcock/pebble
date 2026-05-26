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
	. "gopkg.in/check.v1"

	"github.com/canonical/pebble/internals/overlord/cmdstate"
	"github.com/canonical/pebble/internals/overlord/state"
	"github.com/canonical/pebble/internals/testutil"
)

type managerSuite struct{}

var _ = Suite(&managerSuite{})

func (s *managerSuite) TestNewManagerIsNotNil(c *C) {
	st := state.New(nil)
	runner := state.NewTaskRunner(st)
	mgr := cmdstate.NewManager(runner)
	c.Assert(mgr, NotNil)
}

func (s *managerSuite) TestNewManagerRegistersExecHandler(c *C) {
	st := state.New(nil)
	runner := state.NewTaskRunner(st)
	cmdstate.NewManager(runner)

	kinds := runner.KnownTaskKinds()
	c.Assert(kinds, testutil.Contains, "exec")
}

func (s *managerSuite) TestEnsureReturnsNil(c *C) {
	st := state.New(nil)
	runner := state.NewTaskRunner(st)
	mgr := cmdstate.NewManager(runner)

	err := mgr.Ensure()
	c.Assert(err, IsNil)
}

func (s *managerSuite) TestWaitTestExecutionPresentImmediately(c *C) {
	st := state.New(nil)
	runner := state.NewTaskRunner(st)
	mgr := cmdstate.NewManager(runner)

	st.Lock()
	task := st.NewTask("exec", "test")
	st.Unlock()

	mgr.AddTestExecution(task.ID())

	stop := make(chan struct{})
	defer close(stop)
	c.Assert(mgr.WaitTestExecution(task.ID(), stop), Equals, true)
}

func (s *managerSuite) TestWaitTestExecutionStopReturnsFalse(c *C) {
	st := state.New(nil)
	runner := state.NewTaskRunner(st)
	mgr := cmdstate.NewManager(runner)

	st.Lock()
	task := st.NewTask("exec", "test")
	st.Unlock()

	stop := make(chan struct{})
	close(stop)
	// No execution added; stop is already closed, so it should return false.
	c.Assert(mgr.WaitTestExecution(task.ID(), stop), Equals, false)
}

func (s *managerSuite) TestWaitTestExecutionWaitsUntilAdded(c *C) {
	st := state.New(nil)
	runner := state.NewTaskRunner(st)
	mgr := cmdstate.NewManager(runner)

	st.Lock()
	task := st.NewTask("exec", "test")
	st.Unlock()

	resultCh := make(chan bool, 1)
	stop := make(chan struct{})
	go func() {
		resultCh <- mgr.WaitTestExecution(task.ID(), stop)
	}()

	mgr.AddTestExecution(task.ID())

	c.Assert(<-resultCh, Equals, true)
	close(stop)
}
