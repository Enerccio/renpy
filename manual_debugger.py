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

from renpy.debugger import DAPMessage, debugger_port

class PrintingDAPMessage(threading.Thread):
    def __init__(self, socket):
        threading.Thread.__init__(self)
        self.daemon = True

        self.socket = socket
        self.start()

    def run(self):
        try:
            while True:
                request = DAPMessage.recv_raw(self.socket)
                print request
                if request is None:
                    # client terminated without termination request
                    return

        except BaseException as e:
            # failure while communicating
            print(e)
            pass
        finally:
            self._current_client = None

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", debugger_port))
PrintingDAPMessage(s)

while True:
    data = raw_input(">>>")
    if data == "reconnect":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", debugger_port))
        PrintingDAPMessage(s)
    else:
        DAPMessage.send_text(s, data)
