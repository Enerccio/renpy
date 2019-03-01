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
import json
import traceback
import types

from opcode import *

debugger_port = 14711

# whether debugging is enabled or not
enabled = False

# Holds the instance of renpy debugger if debug mode is on
debugger = None
# instance of debug handler,
handler = None

# enabled features
features = {
    "supportsExceptionInfoRequest": False,
    "supportTerminateDebuggee": False,
    "supportsTerminateThreadsRequest": False,
    "supportsDataBreakpoints": False,
    "supportsStepInTargetsRequest": False,
    "supportsSetExpression": False,
    "supportsGotoTargetsRequest": False,
    "supportsFunctionBreakpoints": False,

    "supportsConditionalBreakpoints": True,
    "supportsHitConditionalBreakpoints": True,
}

class NoneDict(dict):
    def __init__(self, other):
        for key in other:
            self[key] = other[key]

    def __getitem__(self, key):
        if key not in self:
            return None
        return dict.__getitem__(self, key)


class DAPMessage(object):
    def __init__(self):
        self.seq = None

    def set_seq(self, seq):
        self.seq = seq
        return self

    @staticmethod
    def recv(socket):
        body = DAPMessage.recv_raw(socket)

        if body is not None:
            kwargs = body["arguments"]
            if kwargs is None:
                kwargs = {}
            rq = DAPRequest(command=body["command"], **kwargs)
            rq.set_seq(body["seq"])
            return rq

    @staticmethod
    def recv_raw(socket):
        headers = []

        cread_line = ""

        while True:
            c = socket.recv(1)
            if c == "":
                # end of stream
                return None
            cread_line += c

            if cread_line.endswith("\r\n"):
                if cread_line == "\r\n":
                    break
                else:
                    headers.append(cread_line)
                    cread_line = ""

        headers = DAPMessage.parse_headers(headers)

        content_size = int(headers["Content-Length"])

        data = ""

        while (len(data) < content_size):
            data += socket.recv(content_size-len(data))
            if data == "":
                return None

        body = json.loads(data, object_hook=NoneDict)
        # print("RECEIVED: " + str(body))
        return body

    @staticmethod
    def parse_headers(headers):
        h = NoneDict({})
        for hl in headers:
            type, value = hl.split(":")
            type = type.strip()
            value = value.strip()
            h[type] = value
        return h

    def send(self, socket):
        data = self.serialize(self.seq)
        # print("SENT: " + str(data))
        DAPMessage.send_text(socket, data)

    def serialize(self, seq):
        message = {}
        message["seq"] = seq
        message["type"] = self.get_type()

        self.serialize_context(message)

        return json.dumps(message)

    def serialize_context(self, message):
        pass

    def get_type(self):
        raise NotImplementedError()

    @staticmethod
    def send_text(socket, text):
        socket.sendall("Content-Length: " + str(len(text)) + "\r\n")
        socket.sendall("\r\n")
        socket.sendall(text)

    @staticmethod
    def remove_nones(dict):
        d = {}
        for key in dict:
            if dict[key] is not None:
                d[key] = dict[key]
        return d


class DAPRequest(DAPMessage):
    def __init__(self, command, **kwargs):
        self.command = command
        self.kwargs = DAPMessage.remove_nones(kwargs)

    def serialize_context(self, message):
        message["command"] = self.command
        message["args"] = self.kwargs

    def get_type(self):
        return "type"


class DAPEvent(DAPMessage):
    def __init__(self, event):
        self.event = event

    def serialize_context(self, message):
        message["event"] = self.event
        self.serialize_event_context(message)

    def serialize_event_context(self, message):
        raise NotImplementedError()

    def get_type(self):
        return "event"


class DAPResponse(DAPMessage):
    def __init__(self, rqs, command, success=True, message=None):
        self.rqs = rqs
        self.command = command
        self.success = success
        self.message = message

    def serialize_context(self, message):
        message["request_seq"] = self.rqs
        message["command"] = self.command
        message["success"] = self.success
        if self.message is not None:
            message["success"] = self.message
        self.serialize_response_context(message)

    def serialize_response_context(self, message):
        pass

    def get_type(self):
        return "response"


class DAPErrorResponse(DAPResponse):
    def __init__(self, rqs, command, message="", detailed_message=None):
        DAPResponse.__init__(self, rqs, command, success=False, message=message)
        self.dm = detailed_message

    def serialize_response_context(self, message):
        message["body"] = {}
        if self.dm is not None:
            message["body"]["error"] = self.dm


class DAPInitializedEvent(DAPEvent):
    def __init__(self):
        DAPEvent.__init__(self, "initialized")

    def serialize_event_context(self, message):
        pass


class DAPStoppedEvent(DAPEvent):
    def __init__(self, reason, description=None, thread_id=None, preserve_focus_hint=None, text=None, all_threads_stopped=None):
        DAPEvent.__init__(self, "stopped")

        self.reason = reason
        self.description = description
        self.thread_id = thread_id
        self.preserve_focus_hint = preserve_focus_hint
        self.text = text
        self.all_threads_stopped = all_threads_stopped

    def serialize_event_context(self, message):
        body = {}
        message["body"] = body

        body["reason"] = self.reason

        if self.description is not None:
            body["description"] = self.description
        if self.thread_id is not None:
            body["threadId"] = self.thread_id
        if self.preserve_focus_hint is not None:
            body["preserveFocusHint"] = self.preserve_focus_hint
        if self.text is not None:
            body["text"] = self.text
        if self.all_threads_stopped is not None:
            body["allThreadsStopped"] = self.all_threads_stopped


class DAPContinueEvent(DAPEvent):
    def __init__(self, thread_id, all_threads_continue=None):
        DAPEvent.__init__(self, "continued")

        self.thread_id = thread_id
        self.all_threads_continue = all_threads_continue

    def serialize_event_context(self, message):
        body = {}
        message["body"] = body

        body["threadId"] = self.thread_id

        if self.all_threads_continue is not None:
            body["allThreadsContinued"] = self.all_threads_continue


class DAPExitedEvent(DAPEvent):
    def __init__(self, ec):
        DAPEvent.__init__(self, "exited")

        self.ec = ec

    def serialize_event_context(self, message):
        body = {}
        message["body"] = body

        body["exitCode"] = self.ec


class DAPTerminatedEvent(DAPEvent):
    def __init__(self, restart=None):
        DAPEvent.__init__(self, "terminated")

        self.restart = restart

    def serialize_event_context(self, message):
        if self.restart is not None:
            body = {}
            message["body"] = body

            body["restart"] = self.restart


class DAPThreadEvent(DAPEvent):
    def __init__(self, reason, thread_id):
        DAPEvent.__init__(self, "thread")

        self.reason = reason
        self.thread_id = thread_id

    def serialize_event_context(self, message):
        body = {}
        message["body"] = body

        body["reason"] = self.reason
        body["threadId"] = self.thread_id


class DAPOutputEvent(DAPEvent):
    def __init__(self, output, category=None, variables_reference=None, source=None, line=None, column=None, data=None):
        DAPEvent.__init__(self, "output")

        self.output = output
        self.category = category
        self.variables_reference = variables_reference
        self.source = source
        self.line = line
        self.column = column
        self.data = data

    def serialize_event_context(self, message):
        body = {}
        message["body"] = body

        if self.category is not None:
            body["category"] = self.category

        body["output"] = self.output

        if self.variables_reference is not None:
            body["variablesReference"] = self.variables_reference

        if self.source is not None:
            body["source"] = self.source

        if self.line is not None:
            body["line"] = self.line

        if self.column is not None:
            body["column"] = self.column

        if self.data is not None:
            body["data"] = self.data


class DAPBreakpointEvent(DAPEvent):
    def __init__(self, reason, breakpoint):
        DAPEvent.__init__(self, "breakpoint")

        self.reason = reason
        self.breakpoint = breakpoint

    def serialize_event_context(self, message):
        body = {}
        message["body"] = body

        body["reason"] = self.reason
        body["breakpoint"] = self.breakpoint


class DAPModuleEvent(DAPEvent):
    def __init__(self, reason, module):
        DAPEvent.__init__(self, "module")

        self.reason = reason
        self.module = module

    def serialize_event_context(self, message):
        body = {}
        message["body"] = body

        body["reason"] = self.reason
        body["module"] = self.module


class DAPLoadedSourceEvent(DAPEvent):
    def __init__(self, reason, source):
        DAPEvent.__init__(self, "loadedSource")

        self.reason = reason
        self.source = source

    def serialize_event_context(self, message):
        body = {}
        message["body"] = body

        body["reason"] = self.reason
        body["source"] = self.source


class DAPProcessEvent(DAPEvent):
    def __init__(self, name, process_id=None, is_local=None, start_method=None):
        DAPEvent.__init__(self, "process")

        self.name = name
        self.process_id = process_id
        self.is_local = is_local
        self.start_method = start_method

    def serialize_event_context(self, message):
        body = {}
        message["body"] = body

        body["name"] = self.name

        if self.process_id is not None:
            body["systemProcessId"] = self.process_id

        if self.is_local is not None:
            body["isLocalProcess"] = self.is_local

        if self.start_method is not None:
            body["startMethod"] = self.start_method


class DAPCapabilitiesEvent(DAPEvent):
    def __init__(self, capabilities):
        DAPEvent.__init__(self, "capabilities")

        self.capabilities = capabilities

    def serialize_event_context(self, message):
        body = {}
        message["body"] = body

        body["capabilities"] = self.capabilities


class DAPRunInTerminalRequest(DAPRequest):
    def __init__(self, cwd, args, kind=None, title=None, env=None):
        DAPRequest.__init__(self, "runInTerminal", kind, title, cwd, args, env)


class DAPRunInTerminalResponse(DAPResponse):
    def __init__(self, rqs, process_id=None, shell_process_id=None):
        DAPResponse.__init__(self, rqs, "runInTerminal")
        self.process_id = process_id
        self.shell_process_id = shell_process_id

    def serialize_response_context(self, message):
        body = {}
        message["body"] = body

        if self.process_id is not None:
            body["processId"] = self.process_id

        if self.shell_process_id is not None:
            body["shellProcessId"] = self.shell_process_id


### ONLY SUPPORTED RESPONSES (and thus requests) ARE IMPLEMENTED!

class DAPSetBreakpointsResponse(DAPResponse):
    def __init__(self, rqs, breakpoints):
        DAPResponse.__init__(self, rqs, "setBreakpoints")
        self.breakpoints = breakpoints

    def serialize_response_context(self, message):
        body = {}
        message["body"] = body

        body["breakpoints"] = self.breakpoints


class DAPSetFunctionBreakpointsResponse(DAPResponse):
    def __init__(self, rqs, breakpoints):
        DAPResponse.__init__(self, rqs, "setFunctionBreakpoints")
        self.breakpoints = breakpoints

    def serialize_response_context(self, message):
        body = {}
        message["body"] = body

        body["breakpoints"] = self.breakpoints


class DAPContinueResponse(DAPResponse):
    def __init__(self, rqs, all_threads_continue=None):
        DAPResponse.__init__(self, rqs, "continue")
        self.all_threads_continue = all_threads_continue

    def serialize_response_context(self, message):
        body = {}
        message["body"] = body

        if self.all_threads_continue is not None:
            body["allThreadsContinued"] = self.all_threads_continue

# next has no special response

# step has no special response

# step out has no special response

# pause has no response

class DAPInitializeResponse(DAPResponse):
    def __init__(self, rqs, capabilities):
        DAPResponse.__init__(self, rqs, "initialize")
        self.capabilities = capabilities

    def serialize_response_context(self, message):
        body = {}
        message["body"] = self.capabilities


class DAPStackTraceResponse(DAPResponse):
    def __init__(self, rqs, stack_frames):
        DAPResponse.__init__(self, rqs, "stackTrace")
        self.stack_frames = stack_frames

    def serialize_response_context(self, message):
        body = {}
        message["body"] = body

        body["stackFrames"] = self.stack_frames
        body["totalFrames"] = len(self.stack_frames)


class DAPScopesResponse(DAPResponse):
    def __init__(self, rqs, scopes):
        DAPResponse.__init__(self, rqs, "scopes")
        self.scopes = scopes

    def serialize_response_context(self, message):
        body = {}
        message["body"] = body

        body["scopes"] = self.scopes


class DAPVariablesResponse(DAPResponse):
    def __init__(self, rqs, variables):
        DAPResponse.__init__(self, rqs, "variables")
        self.variables = variables

    def serialize_response_context(self, message):
        body = {}
        message["body"] = body

        body["variables"] = self.variables


class DAPSetVariableResponse(DAPResponse):
    def __init__(self, rqs, value, type=None, variables_reference=None, named_variables=None, indexed_variables=None):
        DAPResponse.__init__(self, rqs, "setVariable")
        self.value = value
        self.type = type
        self.variables_reference = variables_reference
        self.named_variables = named_variables
        self.indexed_variables = indexed_variables

    def serialize_response_context(self, message):
        body = {}
        message["body"] = body

        body["value"] = self.value
        if self.type is not None:
            body["type"] = self.type
        if self.variables_reference is not None:
            body["variablesReference"] = self.variables_reference
        if self.named_variables is not None:
            body["namedVariables"] = self.named_variables
        if self.indexed_variables is not None:
            body["indexedVariables"] = self.indexed_variables


class DAPSourceResponse(DAPResponse):
    def __init__(self, rqs, source, mime_type=None):
        DAPResponse.__init__(self, rqs, "source")
        self.source = source
        self.mime_type = mime_type

    def serialize_response_context(self, message):
        body = {}
        message["body"] = body

        body["source"] = self.source
        if self.mime_type is not None:
            body["mimeType"] = self.mime_type


class DAPThreadsResponse(DAPResponse):
    def __init__(self, rqs, threads):
        DAPResponse.__init__(self, rqs, "threads")
        self.threads = threads

    def serialize_response_context(self, message):
        body = {}
        message["body"] = body

        body["threads"] = self.threads


class DAPEvaluateResponse(DAPResponse):
    def __init__(self, rqs, result, type=None, presentation_hint=None, variables_reference=None, named_variables=None, indexed_variables=None):
        DAPResponse.__init__(self, rqs, "evaluate")
        self.result = result
        self.type = type
        self.presentation_hint = presentation_hint
        self.variables_reference = variables_reference
        self.named_variables = named_variables
        self.indexed_variables = indexed_variables

    def serialize_response_context(self, message):
        body = {}
        message["body"] = body

        body["value"] = self.value
        if self.type is not None:
            body["type"] = self.type
        if self.presentation_hint is not None:
            body["presentationHint"] = self.presentation_hint
        if self.variables_reference is not None:
            body["variablesReference"] = self.variables_reference
        if self.named_variables is not None:
            body["namedVariables"] = self.named_variables
        if self.indexed_variables is not None:
            body["indexedVariables"] = self.indexed_variables


class DebugAdapterProtocolServer(threading.Thread):

    def __init__(self):
        super(DebugAdapterProtocolServer, self).__init__(name="DAP")
        self.daemon = True
        self._current_client = None

        self.start()

    def run(self):
        listen_port = debugger_port if "RENPY_DEBUGGER_PORT" not in os.environ else os.environ["RENPY_DEBUGGER_PORT"]

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", listen_port))
        server.listen(0)

        while True:
            client, client_address = server.accept()
            self.attach_one_client(client)

    def attach_one_client(self, csocket):
        self._current_client = csocket
        self.next_seq = 0

        # manual requests

        self.enter_read_loop()

    def enter_read_loop(self):
        try:
            while True:
                try:
                    request = DAPMessage.recv(self._current_client)
                except Exception as e:
                    # TODO send error
                    traceback.print_exc()
                    continue

                if request is None:
                    # client terminated without termination request
                    return
                try:
                    self.resolve_message(request)
                except Exception as e:
                    # TODO send error
                    traceback.print_exc()
                    continue

                if self._current_client is None:
                    return # terminated

        except BaseException as e:
            # failure while communicating
            traceback.print_exc()
            pass
        finally:
            self._current_client = None

            debugger.reset()

    def resolve_message(self, rq):
        if rq.command == "initialize":
            DAPInitializeResponse(rq.seq, features).set_seq(self.next_seq).send(self._current_client)
            self.next_seq += 1
            DAPInitializedEvent().set_seq(self.next_seq).send(self._current_client)
            self.next_seq += 1
        elif rq.command == "setBreakpoints":
            bkps = self.create_breakpoints(**rq.kwargs)
            self.next_seq += 1
            DAPSetBreakpointsResponse(rq.seq, [b.serialize() for b in bkps]).set_seq(self.next_seq).send(self._current_client)
            self.next_seq += 1
        elif rq.command == "configurationDone":
            DAPResponse(rq.seq, "configurationDone").set_seq(self.next_seq).send(self._current_client)
            self.next_seq += 1
        elif rq.command == "launch":
            # no special noDebug
            DAPResponse(rq.seq, "launch").set_seq(self.next_seq).send(self._current_client)
            self.next_seq += 1
        elif rq.command == "continue":
            DAPContinueResponse(rq.seq, all_threads_continue=True).set_seq(self.next_seq).send(self._current_client)
            self.next_seq += 1
            debugger.stepping = SteppingMode.STEP_NO_STEP
            debugger.cont = True
        elif rq.command == "threads":
            DAPThreadsResponse(rq.seq, [{"id": 0, "name": "renpy_main"}]).set_seq(self.next_seq).send(self._current_client)
            self.next_seq += 1
        elif rq.command == "stackTrace":
            DAPStackTraceResponse(rq.seq, debugger.get_stack_frames(**rq.kwargs)).set_seq(self.next_seq).send(self._current_client)
            self.next_seq += 1
        elif rq.command == "scopes":
            DAPScopesResponse(rq.seq, debugger.get_scopes(int(rq.kwargs["frameId"]))).set_seq(self.next_seq).send(self._current_client)
            self.next_seq += 1
        elif rq.command == "variables":
            DAPVariablesResponse(rq.seq, debugger.format_variable(**rq.kwargs)).set_seq(self.next_seq).send(self._current_client)
            self.next_seq += 1
        else:
            DAPErrorResponse(rqs=rq.seq, command=rq.command, message="NotImplemented").set_seq(self.next_seq).send(self._current_client)
            self.next_seq += 1

    def create_breakpoints(self, source, breakpoints=[], lines=[], sourceModified=False):
        path = source["path"]
        created_breakpoints = []

        for bkp_info in breakpoints:
            line = bkp_info["line"]
            condition = bkp_info["condition"]
            hit_condition = bkp_info["hitCondition"]
            if hit_condition is not None:
                hit_condition = int(hit_condition)
            # log message not suppored (yet?)

            breakpoint = Breakpoint(path, line, eval_condition=condition, counter=hit_condition)
            debugger.register_breakpoint(breakpoint)
            created_breakpoints.append(breakpoint)

        return created_breakpoints

    def send_breakpoint_event(self, breakpoint):
        DAPStoppedEvent(reason="breakpoint", description=debugger.frame_location_info(),
                        thread_id=0, preserve_focus_hint=False,
                        all_threads_stopped=True).set_seq(self.next_seq).send(self._current_client)
        self.next_seq += 1



class Breakpoint(object):
    def __init__(self, source, line, eval_condition=None, counter=None):
        self.source = source
        self.line = int(line) if isinstance(line, str) else line
        self.eval_condition = eval_condition
        self.counter = counter
        self.times_hit = 0

    def serialize(self):
        data = {}

        data["verified"] = True

        return data

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
        self.cont = True

        # holds paths to variables for each scope opened
        # scope assign containts tuples (value, parent_accessor, type (None for scope), parent_object)
        self.scope_assign = {}
        # current break var id generator (0->more)
        self.scope_var_id = 0

        self.active_call = None
        self.active_frame = None
        self.bkp_lock = threading.Lock()

    def reset(self):
        with self.bkp_lock:
            self.active_breakpoints = set()
            self.stepping = SteppingMode.STEP_NO_STEP
            self.continue_next()

    def continue_next(self):
        self.scope_assign = {}
        self.scope_var_id = 0
        self.cont = True

    def register_breakpoint(self, breakpoint):
        with self.bkp_lock:
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

    def frame_location_info(self):
        """Returns location information about current frame.

        Should be used by other thread when debugged main thread is cont=False
        """
        return str(self.active_frame.f_code.co_filename) + ":" + str(self.active_frame.f_lineno)

    def get_frame(self, frame_ord):
        cframe = self.active_frame
        c = 0
        while cframe is not None:
            if c == frame_ord:
                return cframe
            cframe = cframe.f_back
            c += 1
        return None

    def get_stack_frames(self, threadId=0, startFrame=0, levels=0, format=None):
        # format is ignored, TODO?
        # threadId is ignored since renpy is single threaded for stuff we need

        clevel = 0
        slevel = 0 if startFrame is None else startFrame
        elevel = None if levels is None or levels == 0 else levels

        frames = []
        cframe = self.active_frame
        while cframe is not None:
            if clevel >= slevel:
                finfo = {}

                finfo["id"] = clevel
                finfo["name"] = cframe.f_code.co_name + self.format_method_signature(cframe.f_locals, cframe.f_code)
                finfo["source"] = {"path" : cframe.f_code.co_filename }
                finfo["line"] = cframe.f_lineno
                finfo["presentationHint"] = "normal"
                finfo["column"] = 0

                dis_info = {}
                finfo["subsource"] = dis_info

                disassembled = dis(cframe.f_code, cframe.f_lasti)
                dis_info["sources"] = [{"text": self.format_disassembly(cframe.f_lineno, *de), "line": de[1], "source": finfo["source"]} for de in disassembled]
                ord = 0
                for de in disassembled:
                    if de[0]:
                        break
                    ord += 1
                finfo["subsourceElement"] = ord

                frames.append(finfo)
            clevel += 1
            if elevel is not None and clevel >= elevel:
                break
            cframe = cframe.f_back

        return frames

    def format_disassembly(self, cline, current, python_lineno, bytecode_offset, instruction, arg, constant):
        fmtd = ""

        if bytecode_offset is not None:
            fmtd += str(bytecode_offset) + " "

        fmtd += "[" + instruction + "]"

        if python_lineno is not None:
            fmtd += " at line " + str(python_lineno + cline)

        if arg is not None:
            fmtd += " (%s, %s)" % (str(arg), str(constant))

        return fmtd

    def format_method_signature(self, locals, code):
        res = ""
        is_args = code.co_flags & 4
        is_kwargs = code.co_flags & 8
        total_args = code.co_argcount
        if is_args:
            total_args += 1
        if is_kwargs:
            total_args += 1
        for i in xrange(total_args):
            varname = code.co_varnames[i]
            #varname += "=" + str(locals[varname])

            if is_args and is_kwargs and i == total_args - 2:
                varname = "*" + varname
            elif is_args and is_kwargs and i == total_args - 1:
                varname = "**" + varname
            elif is_args and i == total_args - 1:
                varname = "*" + varname
            elif is_kwargs and i == total_args - 1:
                varname = "**" + varname
            if res == "":
                res = varname
            else:
                res += ", " + varname

        return "(%s)" % res

    def get_scopes(self, frame_ord):
        frame = self.get_frame(frame_ord)

        return [self.get_scope(frame, frame.f_locals, "Locals", False), self.get_scope(frame, frame.f_globals, "Globals", True)]

    def get_scope(self, f, scope_dict, name, expensive):
        scope_id = self.scope_var_id
        self.scope_assign[scope_id] = (scope_dict, None, None, None)
        self.scope_var_id += 1

        return {
            "name": name,
            "variablesReference": scope_id,
            "expensive": expensive,
            "namedVariables": len(scope_dict.keys())
        }

    def format_variable(self, variablesReference, filter=None, start=None, count=None, format=None):
        # format is ignored, TODO?

        vs = None if start is None or start == 0 else start
        es = None if count is None or count == 0 else count

        var, name, tt, parent = self.scope_assign[variablesReference]

        # print(str(var) + ", " + str(name) + ", " + str(tt))

        is_slotted = False

        if not isinstance(var, dict) and not isinstance(var, list):
            if hasattr(var, "__dict__"):
                var = var.__dict__
            else:
                is_slotted = True

        # print (str(var))

        if not is_slotted and isinstance(var, dict):
            if filter is not None and filter == "indexed":
                return []
            keys = sorted(var.keys())
        elif not is_slotted:
            if filter is not None and filter == "named":
                return []
            keys = range(len(var))
        elif is_slotted:
            keys = dir(var)

        if "self" in keys:
            keys.remove("self")
            keys = ["self"] + keys

        # print (str(keys))

        it = 0
        total = 0
        variables = []
        for vkey in keys:
            if vs is None or it >= vs:
                var_ref = self.scope_var_id
                if is_slotted:
                    value = getattr(var, vkey)
                else:
                    value = var[vkey]

                vardesc = {}
                variables.append(vardesc)

                vardesc["name"] = vkey
                vardesc["value"] = str(value)
                vardesc["type"] = str(type(value))
                # vardesc["presentationHint"] # TODO!!!
                vardesc["evaluateName"] = vkey
                vardesc["variablesReference"] = var_ref

                vv_inner = value
                vv_slotted = False
                if not isinstance(vv_inner, dict) and not isinstance(vv_inner, list):
                    if hasattr(vv_inner, "__dict__"):
                        vv_inner = vv_inner.__dict__
                    else:
                        vv_slotted = True

                if not vv_slotted and isinstance(vv_inner, dict):
                    vardesc["namedVariables"] = len(vv_inner.keys())
                elif not vv_slotted:
                    vardesc["indexedVariables"] = len(vv_inner)
                else:
                    vardesc["namedVariables"] = len(dir(vv_inner))

                self.scope_assign[var_ref] = (value, vkey, str(type(value)), var)

                self.scope_var_id += 1
                total += 1
            it += 1
            if es is not None and total >= es:
                break

        return variables

    def trace_event(self, frame, event, arg):
        self.active_frame = frame
        self.active_call = frame

        if event == "call":
            frame.f_trace = self.trace_line

        self.base_trace(frame, event, arg)

    def trace_line(self, frame, event, arg):
        self.active_frame = frame

        self.base_trace(frame, event, arg)

    def base_trace(self, frame, event, arg):
        # print("Tracing %s %s %s (%s))" % (event, "<File %s, Line %s>" % (frame.f_code.co_filename, frame.f_lineno), str(arg), str(id(threading.current_thread()))))

        if self.stepping != SteppingMode.STEP_NO_STEP:
            pass # TODO
        else:
            breaking_on = None
            with self.bkp_lock:
                for breakpoint in self.active_breakpoints:
                    if breakpoint.applies(frame):
                        breaking_on = breakpoint
                        break

            if breaking_on is not None:
                print("Broke at %s %s %s (%s))" % (event, "<File %s, Line %s>" % (frame.f_code.co_filename, frame.f_lineno), str(arg), str(id(threading.current_thread()))))
                self.break_code(breaking_on) # blocks

        while not self.cont:
            pass

    def break_code(self, breakpoint):
        self.cont = False
        self.scope_assign = {}
        self.scope_var_id = 0
        handler.send_breakpoint_event(breakpoint)


def init(continue_callback):
    global enabled
    enabled = "RENPY_DEBUGGER" in os.environ and os.environ["RENPY_DEBUGGER"] == "enabled"

    if enabled:
        global debugger, handler

        debugger = RenpyPythonDebugger()
        handler = DebugAdapterProtocolServer()

        debugger.attach()
        try:
            continue_callback()
        finally:
            debugger.detach()
    else:
        continue_callback()


# disassembler - sane one

class DisElement(object):
    def __init__(self):
        self.py_line = None
        self.bytecode_offset = None
        self.instruction = None
        self.arg = None
        self.readable_arg = None
        self.current = False

    # resulted object is (current, python_lineno, bytecode_offset, instruction, arg, constant)
    def to_tuple(self):
        return (self.current, self.py_line, self.bytecode_offset, self.instruction, self.arg, self.readable_arg)


def dis(co, lasti=-1):
    """Disassemble a code object."""
    result = []

    code = co.co_code
    labels = findlabels(code)
    linestarts = dict(findlinestarts(co))
    n = len(code)
    i = 0
    extended_arg = 0
    free = None
    while i < n:
        c = code[i]
        op = ord(c)
        de = DisElement()
        result.append(de)

        if i in linestarts:
            de.python_lineno = linestarts[i]

        de.current = i == lasti
        de.bytecode_offset = i
        de.instruction = opname[op]
        i = i+1
        if op >= HAVE_ARGUMENT:
            oparg = ord(code[i]) + ord(code[i+1])*256 + extended_arg
            extended_arg = 0
            i = i+2
            if op == EXTENDED_ARG:
                extended_arg = oparg*65536L
            de.arg = oparg


            if op in hasconst:
                de.readable_arg = co.co_consts[oparg]
            elif op in hasname:
                de.readable_arg = co.co_names[oparg]
            elif op in hasjrel:
                de.readable_arg = i + oparg
            elif op in haslocal:
                de.readable_arg = co.co_varnames[oparg]
            elif op in hascompare:
                de.readable_arg = cmp_op[oparg]
            elif op in hasfree:
                if free is None:
                    free = co.co_cellvars + co.co_freevars
                de.readable_arg = free[oparg]

    r = [d.to_tuple() for d in result]
    return r


def findlabels(code):
    """Detect all offsets in a byte code which are jump targets.

    Return the list of offsets.

    """
    labels = []
    n = len(code)
    i = 0
    while i < n:
        c = code[i]
        op = ord(c)
        i = i+1
        if op >= HAVE_ARGUMENT:
            oparg = ord(code[i]) + ord(code[i+1])*256
            i = i+2
            label = -1
            if op in hasjrel:
                label = i+oparg
            elif op in hasjabs:
                label = oparg
            if label >= 0:
                if label not in labels:
                    labels.append(label)
    return labels


def findlinestarts(code):
    """Find the offsets in a byte code which are start of lines in the source.

    Generate pairs (offset, lineno) as described in Python/compile.c.

    """
    byte_increments = [ord(c) for c in code.co_lnotab[0::2]]
    line_increments = [ord(c) for c in code.co_lnotab[1::2]]

    lastlineno = None
    lineno = code.co_firstlineno
    addr = 0
    for byte_incr, line_incr in zip(byte_increments, line_increments):
        if byte_incr:
            if lineno != lastlineno:
                yield (addr, lineno)
                lastlineno = lineno
            addr += byte_incr
        lineno += line_incr
    if lineno != lastlineno:
        yield (addr, lineno)
