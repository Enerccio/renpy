# Copyright 2004-2019 Tom Rothamel <pytom@bishoujo.us>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# This file contains debugging code that isn't enabled in normal Ren'Py
# operation.

from __future__ import print_function

import renpy

import os
import sys
import threading
import socket

debugger_port = 4711

# whether debugging is enabled or not
enabled = False

# Holds the instance of renpy debugger if debug mode is on
debugger = None
# instance of debug handler,
handler = None


class DAPMessage(object):

    @staticmethod
    def recv(socket):
        pass


class DebugAdapterProtocolServer(threading.Thread):

    def __init__(self):
        super(DebugAdapterProtocolServer, self).__init__(name="DAP")
        self.daemon = True

        self.start()

        self._current_client = None

    def run(self):
        listen_port = debugger_port if "RENPY_DEBUGGER_PORT" not in os.environ else os.environ["RENPY_DEBUGGER_PORT"]

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", listen_port))
        server.listen(0)

        while True:
            client, client_address = server.accept()

            self.attach_one_client(client)

    def attach_one_client(self, csocket):
        self._current_client = csocket

        self.enter_read_loop()

    def enter_read_loop(self):
        try:
            while True:
                request = DAPMessage.recv(self._current_client)
                if request is None:
                    # client terminated without termination request
                    return

        except:
            # failure while communicating
            pass
        finally:
            self._current_client = None


class Breakpoint(object):
    def __init__(self, source, line, eval_condition=None, counter=None):
        self.source = source
        self.line = line
        self.eval_condition = eval_condition
        self.counter = counter
        self.times_hit = 0

    def applies(self, frame):
        if frame.f_code.co_filename == self.source and frame.f_lineno == self.line:
            # breakpoint hits, now try eval if it is eval

            eval_passed = True
            if self.eval_condition is not None:
                eval_passed = False
                try:
                    if eval(self.eval_condition, frame.f_globals, frame.f_locals):
                        # so eval_passed is boolean not whatever eval returned, it is in separate if!
                        eval_passed = True
                except:
                    # eval failure, ignore
                    pass

            if eval_passed:
                # eval passed, check for counter
                self.times_hit += 1

                if self.counter is None or self.counter < self.times_hit:
                    return True

        return False


class SteppingMode(object):
    STEP_NO_STEP = 0
    STEP_NEXT = 1
    STEP_INTO = 2
    STEP_OUT = 3


class RenpyPythonDebugger(object):

    def __init__(self):
        super(RenpyPythonDebugger, self).__init__()

        self._attach_count = 0

        self.active_breakpoints = set()

        self.stepping = SteppingMode.STEP_NO_STEP

        self.active_call = None
        self.active_frame = None


    def register_breakpoint(self, breakpoint):
        self.active_breakpoints.add(breakpoint)

    def attach(self):
        if self._attach_count == 0:
            sys.settrace(self.trace_event)
        self._attach_count += 1

    def detach(self):
        self._attach_count -= 1
        if self._attach_count == 0:
            sys.settrace(None)

            self.active_frame = None
            self.active_call = None

    def trace_event(self, frame, event, arg):
        # print "Tracing %s %s %s (%s))" % (event, "<File %s, Line %s>" % (frame.f_code.co_filename, frame.f_lineno), str(arg), str(id(threading.current_thread())))

        self.active_frame = frame
        self.active_call = frame

        if event == "call":
            frame.f_trace = self.trace_line

        self.base_trace(frame, event, arg)

    def trace_line(self, frame, event, arg):
        self.active_frame = frame

        self.base_trace(frame, event, arg)

    def base_trace(self, frame, event, arg):
        if self.stepping != SteppingMode.STEP_NO_STEP:
            pass # TODO
        else:
            for breakpoint in self.active_breakpoints:
                if breakpoint.applies(frame):
                    self.break_code(breakpoint) # blocks

    def break_code(self, breakpoint):
        # TODO send breakpoint data

        self.start_interaction_loop()

    def start_interaction_loop(self):
        pass



def py_exec_bytecode(bytecode, globals, locals):
    try:
        debugger.attach()
        exec bytecode in globals, locals
    finally:
        debugger.detach()


def py_exec(bytecode, store, locals):
    try:
        debugger.attach()
        exec bytecode in store, locals
    finally:
        debugger.detach()


def py_eval_bytecode(bytecode, globals, locals):
    try:
        debugger.attach()
        return eval(bytecode, globals, locals)
    finally:
        debugger.detach()


def init():
    global enabled
    enabled = "RENPY_DEBUGGER" in os.environ and os.environ["RENPY_DEBUGGER"] == "enabled"

    if enabled:
        global debugger, handler

        debugger = RenpyPythonDebugger()
        handler = DebugAdapterProtocolServer()
