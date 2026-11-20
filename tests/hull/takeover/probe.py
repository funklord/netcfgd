# probe.py HOST PORT [SOURCE] [INTERFACE]: "open" or "closed" after at most
# two seconds. A link-local HOST needs INTERFACE for its scope.
import socket, sys

host, port = sys.argv[1], int(sys.argv[2])
source = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != "-" else None
family = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(family, socket.SOCK_STREAM)
s.settimeout(2)
try:
	if source:
		s.bind((source, 0))
	if family == socket.AF_INET6:
		scope = socket.if_nametoindex(sys.argv[4]) if len(sys.argv) > 4 else 0
		s.connect((host, port, 0, scope))
	else:
		s.connect((host, port))
	print("open")
except OSError:
	print("closed")
finally:
	s.close()
