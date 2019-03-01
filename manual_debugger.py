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

import os
import sys
import threading
import socket
import json
import readline
import traceback

from renpy.debugger import DAPMessage, debugger_port


class Counter(object):
    def __init__(self):
        self.state = 0

    def get(self):
        s = self.state
        self.state += 1
        return s

rq_counter = Counter()
rq_arguments = {}

class State(object):
    @staticmethod
    def load_state(stage=0, tid=0):
        global state

        if stage == 0:
            state = State()
            DAPMessage.send_text(s, json.dumps({"seq": rq_counter.get(), "command":"threads"}))
        if stage == 1:
            DAPMessage.send_text(s, json.dumps({"seq": rq_counter.get(), "command":"stackTrace", "arguments": {"threadId": tid, "startFrame": 0, "levels": 0}}))

    @staticmethod
    def load_scopes():
        global state

        DAPMessage.send_text(s, json.dumps({"seq": rq_counter.get(), "command":"scopes", "arguments": {"frameId": state.active_stack}}))

    def __init__(self):
        self.threads = []
        self.stacks = {}
        self.active_stack = 0
        self.locs = None
        self.globs = None
        self.vars = {}

    def load_variable(self, vref):
        if vref not in self.vars:
            sq = rq_counter.get()
            rq_arguments[sq] = vref
            DAPMessage.send_text(s, json.dumps({"seq": sq, "command":"variables", "arguments": {"variablesReference": vref}}))
        while vref not in self.vars:
            pass
        if self.vars[vref] is None:
            print "Error retrieving variable %s" % str(vref)
            del self.vars[vref]
            return

    def print_variable(self, vref):
        if vref not in self.vars:
            return

        variables = self.vars[vref]
        for v in variables:
            fmt = "#%s: %s (%s)=%s"
            if len(v["value"]) > 60:
                # move to new line
                "#%s: %s (%s)=\n  %s"
            print fmt % (str(v["variablesReference"]), str(v["name"]), str(v["type"]), str(v["value"]))


class StackTraceElement(object):
    def __init__(self):
        self.id = None
        self.name = None
        self.source = "<unavailable>"
        self.line = None
        self.bytepos = None
        self.sselements = []


class PrintingDAPMessage(threading.Thread):
    def __init__(self, socket):
        threading.Thread.__init__(self)
        self.daemon = True

        self.socket = socket
        self.start()

    def run(self):
        global in_wait

        try:
            while True:
                request = DAPMessage.recv_raw(self.socket)
                # print request

                if request is None:
                    print "Disconnected"
                    return

                if request["type"] == "response" and not request["success"]:
                    if int(request["request_seq"]) in rq_arguments:
                        parent_varref = rq_arguments[int(request["request_seq"])]
                        self.vars[vref] = None
                    print request["type"]["message"], request["type"]["body"]["error"]
                elif request["type"] == "event":
                    if request["event"] == "stopped":
                        print "Stopped (" + request["body"]["reason"] + ")", request["body"]["description"]
                        in_wait = True
                        State.load_state(0)
                elif request["type"] == "response":
                    if request["command"] == "threads":
                        for t in request["body"]["threads"]:
                            state.threads.append((t["id"], t["name"]))
                            State.load_state(1, tid=t["id"])
                    elif request["command"] == "stackTrace":
                        stacks = []
                        for sf in request["body"]["stackFrames"]:
                            st = StackTraceElement()
                            st.id = sf["id"]
                            st.name = sf["name"]
                            st.source = sf["source"]["path"] if sf["source"] is not None else None
                            st.line = sf["line"]
                            st.bytepos = sf["subsourceElement"] if sf["subsourceElement"] is not None else None
                            st.sselements = [x["text"] for x in sf["subsource"]["sources"]] if sf["subsource"] is not None else []
                            stacks.append(st)
                        state.stacks["0"] = stacks
                        state.active_stack = 0
                        state.locs = None
                        state.globs = None
                        state.vars = {}
                        State.load_scopes()
                    elif request["command"] == "scopes":
                        state.locs = request["body"]["scopes"][0]
                        state.globs = request["body"]["scopes"][1]
                        state.vars = {}
                    elif request["command"] == "variables":
                        parent_varref = rq_arguments[int(request["request_seq"])]
                        state.vars[parent_varref] = request["body"]["variables"]


        except BaseException as e:
            # failure while communicating
            traceback.print_exc()

s = None
in_wait = False
state = None

breakpoints = set()

def mk_breakpoints():
    source_map = {}
    for src, line in breakpoints:
        if src not in source_map:
            source_map[src] = set()
        source_map[src].add(line)

    breakpoint_requests = []
    for source in source_map:
        req = {}
        req["seq"] = rq_counter.get() # renpy debugger ignores seq anyways, but tries to be correct
        req["command"] = "setBreakpoints"
        args = {}
        req["arguments"] = args
        args["source"] = { "path": source }
        args["breakpoints"] = [{"line": l} for l in source_map[source]]

        display = "Installed breakpoints %s for source %s" %(str(source_map[source]), source)

        breakpoint_requests.append((req, display))

    return breakpoint_requests


while True:
    data = raw_input("")

    if data == "connect":
        print "Establishing connection"

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", debugger_port))
            PrintingDAPMessage(s)
        except:
            print "Failed. Is renpy debugged game running?"
            s = None
            continue

        DAPMessage.send_text(s, json.dumps({"seq": rq_counter.get(), "command":"initialize"}))
        for breakpoint_request, display in mk_breakpoints():
            DAPMessage.send_text(s, json.dumps(breakpoint_request))
            print display
        DAPMessage.send_text(s, json.dumps({"seq": rq_counter.get(), "command":"configurationDone"}))
        DAPMessage.send_text(s, json.dumps({"seq": rq_counter.get(), "command":"launch"}))
        print "Connected!"
    elif data.startswith("b "):
        try:
            file, line = data[2:].split(":")
            breakpoints.add((file, int(line)))
        except:
            print "Failed to insert breakpoint, check syntax"
    elif data.startswith("c") and in_wait:
        state = None
        DAPMessage.send_text(s, json.dumps({"seq": rq_counter.get(), "command":"continue", "arguments":{"threadId":0}}))
    elif data == "threads" and state is not None:
        print "Threads:"
        for t in state.threads:
            print "Threads #%s: %s" % (str(t[0]), t[1])
    elif data.startswith("bt") and state is not None:
        try:
            if data == "bt":
                thread_id = "0"
            else:
                thread_id = data[3:]
            print "Backtrace for thread [%s]" % thread_id

            if thread_id not in state.stacks:
                print "No thread %s available" % thread_id
            else:
                for st in state.stacks[thread_id]:
                    print "#%s: <%s:%s> %s " % (st.id, st.source, str(st.line), st.name)
        except:
            print "Failed to display bt, check syntax"
    elif data.startswith("bytet") and state is not None:
        st = state.stacks["0"][state.active_stack]
        print "Bytecode of stack frame #%s: <%s:%s> %s  "  % (st.id, st.source, str(st.line), st.name)
        i = 0
        for bytecode in st.sselements:
            if i == st.bytepos:
                print "* ",
            print bytecode
            i += 1
    elif (data == "st" or data.startswith("st ")) and state is not None:
        if data == "st":
            state.active_stack = 0
            state.locs = None
            state.globs = None
            state.vars = {}
            State.load_scopes()
        else:
            try:
                state.active_stack = int(data[3:])
                if state.active_stack >= len(state.stacks["0"]):
                    print "Invalid stack frame number, set to " + str(len(state.stacks["0"]) - 1)
                    state.active_stack = len(state.stacks["0"]) - 1
                state.locs = None
                state.globs = None
                state.vars = {}
                State.load_scopes()
            except:
                print "Failed to set active stack frame, check syntax"
        st = state.stacks["0"][state.active_stack]
        print "Set stack to #%s: <%s:%s> %s  "  % (st.id, st.source, str(st.line), st.name)
    elif data == "locals" and state is not None:
        state.load_variable(state.locs["variablesReference"])
        state.print_variable(state.locs["variablesReference"])
    elif data == "globals" and state is not None:
        state.load_variable(state.globs["variablesReference"])
        state.print_variable(state.globs["variablesReference"])
    elif data.startswith("v "):
        try:
            varRef = int(data[2:])
        except:
            print "Failed to get variable, check syntax"
        state.load_variable(varRef)
        state.print_variable(varRef)

    elif data.startswith("{") and s: # raw request
        DAPMessage.send_text(s, data)
