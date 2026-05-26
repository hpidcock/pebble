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
	"context"
	"errors"
	"time"

	. "gopkg.in/check.v1"
	"gopkg.in/tomb.v2"

	"github.com/canonical/pebble/internals/overlord/cmdstate"
	"github.com/canonical/pebble/internals/overlord/state"
	"github.com/canonical/pebble/internals/testutil"
)

type handlersSuite struct {
	testutil.BaseTest
}

var _ = Suite(&handlersSuite{})

// TestDoExecNoSetupReturnsNil covers the case where a previously-running
// task was in DoingStatus when the daemon was killed. On restart the task
// runner retries it, but no execSetup is cached, so doExec should return nil
// immediately and not attempt to re-run the command.
func (s *handlersSuite) TestDoExecNoSetupReturnsNil(c *C) {
	st := state.New(nil)
	runner := state.NewTaskRunner(st)
	mgr := cmdstate.NewManager(runner)

	st.Lock()
	task := st.NewTask("exec", "test cmd")
	st.Unlock()

	var tb tomb.Tomb
	err := mgr.DoExec(task, &tb)
	c.Assert(err, IsNil)
}

// TestWaitIOConnectedSuccess verifies that waitIOConnected returns nil once
// the ioConnected channel is closed.
func (s *handlersSuite) TestWaitIOConnectedSuccess(c *C) {
	e := cmdstate.NewTestExecution(false)
	e.SignalIOConnected()

	err := e.WaitIOConnected(context.Background(), "task-1")
	c.Assert(err, IsNil)
}

// TestWaitIOConnectedSuccessSplitStderr is the same as above but with a
// separate stderr websocket requested.
func (s *handlersSuite) TestWaitIOConnectedSuccessSplitStderr(c *C) {
	e := cmdstate.NewTestExecution(true)
	e.SignalIOConnected()

	err := e.WaitIOConnected(context.Background(), "task-2")
	c.Assert(err, IsNil)
}

// TestWaitIOConnectedContextCancelled verifies that waitIOConnected returns
// the context error when the caller's context is cancelled before the
// websockets connect.
func (s *handlersSuite) TestWaitIOConnectedContextCancelled(c *C) {
	e := cmdstate.NewTestExecution(false)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := e.WaitIOConnected(ctx, "task-3")
	c.Assert(errors.Is(err, context.Canceled), Equals, true)
}

// TestWaitIOConnectedTimeout verifies that waitIOConnected returns a
// DeadlineExceeded-wrapped error when connectTimeout elapses before the
// websockets connect.
func (s *handlersSuite) TestWaitIOConnectedTimeout(c *C) {
	s.AddCleanup(cmdstate.FakeConnectTimeout(5 * time.Millisecond))

	e := cmdstate.NewTestExecution(false)
	// Do not signal ioConnected; let the timeout fire.
	err := e.WaitIOConnected(context.Background(), "task-4")
	c.Assert(err, ErrorMatches, `exec task-4: timeout waiting for websocket connections: .*`)
	c.Assert(errors.Is(err, context.DeadlineExceeded), Equals, true)
}
