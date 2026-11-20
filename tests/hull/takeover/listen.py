# Dual-stack TCP listeners standing in for sshd, nfsd and UniFi: accept and
# close. The rig asks whether a port is reachable, not what answers on it.
import socket, sys, threading

def serve(port):
	s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
	s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("::", port))
	s.listen(64)
	while True:
		c, _ = s.accept()
		c.close()

for p in sys.argv[1:]:
	threading.Thread(target=serve, args=(int(p),), daemon=True).start()
threading.Event().wait(600)
