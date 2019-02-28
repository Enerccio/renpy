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


class State(object):
    @staticmethod
    def load_state(stage=0, tid=0):
        global state

        if stage == 0:
            state = State()
            DAPMessage.send_text(s, json.dumps({"seq":0, "command":"threads"}))
        if stage == 1:
            DAPMessage.send_text(s, json.dumps({"seq":0, "command":"stackTrace", "arguments": {"threadId": tid, "startFrame": 0, "levels": 0}}))

    def __init__(self):
        self.threads = []
        self.stacks = {}


class StackTraceElement(object):
    def __init__(self):
        self.id = None
        self.name = None
        self.source = "<unavailable>"
        self.line = None


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
                            stacks.append(st)
                        state.stacks["0"] = stacks

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
        req["seq"] = 0 # renpy debugger ignores seq anyways, but tries to be correct
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

        DAPMessage.send_text(s, json.dumps({"seq":0, "command":"initialize"}))
        for breakpoint_request, display in mk_breakpoints():
            DAPMessage.send_text(s, json.dumps(breakpoint_request))
            print display
        DAPMessage.send_text(s, json.dumps({"seq":0, "command":"configurationDone"}))
        DAPMessage.send_text(s, json.dumps({"seq":0, "command":"launch"}))
        print "Connected!"
    elif data.startswith("b "):
        try:
            file, line = data[2:].split(":")
            breakpoints.add((file, int(line)))
        except:
            print "Failed to insert breakpoint, check syntax"
    elif data.startswith("c") and in_wait:
        state = None
        DAPMessage.send_text(s, json.dumps({"seq":0, "command":"continue", "arguments":{"threadId":0}}))
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
    elif data.startswith("{") and s: # raw request
        DAPMessage.send_text(s, data)
