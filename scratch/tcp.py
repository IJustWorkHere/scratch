#!/usr/bin/env python
# A generic script that can be used to test a test connection between two points
# on a given port

# Python Imports
import socket, time
import threading
import argparse
import inspect

class Main(object):
    def __init__(self):
        self._connected = False
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        for name in dir(self):
            if not name.startswith("_"):
                p = subparsers.add_parser(name)
                method = getattr(self, name)
                argnames = inspect.getargspec(method).args[1:]
                for argname in argnames:
                    p.add_argument(argname)
                p.set_defaults(func=method, argnames=argnames)
        self.args = parser.parse_args()

    def connect(self, host, port, timeout):
        try:
            ai_list = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for (family, socktype, proto, canon, sockaddr) in ai_list:
                s = socket.socket(family, socktype)
                s.connect(sockaddr)
                s.close()
            self._connected = True
        except Exception:
            pass

    def __call__(self):
        a = self.args
        callargs = [getattr(a, name) for name in a.argnames]
        self._timeout = int(callargs[-1])
        t = threading.Thread(target=self.connect, args=(callargs))
        t.setDaemon(True)
        t.start()
        while self._timeout > 0 and t.isAlive():
            self._timeout -= 1
            time.sleep(1)
        print self._connected

if __name__ == '__main__':
    main = Main()
    main()