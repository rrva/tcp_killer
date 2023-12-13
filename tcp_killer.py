# Copyright 2017 Google Inc. All Rights Reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Shuts down a TCP connection on Linux or macOS.

Finds the process and socket file descriptor associated with a given TCP
connection. Then injects into that process a call to shutdown()
(http://man7.org/linux/man-pages/man2/shutdown.2.html) that file descriptor,
thereby shutting down the TCP connection.

  Typical usage example:

  tcp_kill("10.31.33.7", 50246 "93.184.216.34", 443)

Dependencies:
  lsof (https://en.wikipedia.org/wiki/Lsof)
  frida (https://www.frida.re/): sudo pip install frida
"""

__author__ = "geffner@google.com (Jason Geffner)"
__version__ = "1.0"


import argparse
import os
import platform
import re
import socket
import subprocess
import threading

import frida


_FRIDA_SCRIPT = """
  var resolver = new ApiResolver("module");
  var lib = Process.platform == "darwin" ? "libsystem" : "libc";
  var matches = resolver.enumerateMatchesSync("exports:*" + lib + "*!shutdown");
  if (matches.length == 0)
  {
    throw new Error("Could not find *" + lib + "*!shutdown in target process.");
  }
  else if (matches.length != 1)
  {
    // Sometimes Frida returns duplicates.
    var address = 0;
    var s = "";
    var duplicates_only = true;
    for (var i = 0; i < matches.length; i++)
    {
      if (s.length != 0)
      {
        s += ", ";
      }
      s += matches[i].name + "@" + matches[i].address;
      if (address == 0)
      {
        address = matches[i].address;
      }
      else if (!address.equals(matches[i].address))
      {
        duplicates_only = false;
      }
    }
    if (!duplicates_only)
    {
      throw new Error("More than one match found for *libc*!shutdown: " + s);
    }
  }
  var shutdown = new NativeFunction(matches[0].address, "int", ["int", "int"]);
  if (shutdown(%d, 0) != 0)
  {
    throw new Error("Call to shutdown() returned an error.");
  }
  send("");
  """


def canonicalize_ip_address(address):
  if ":" in address:
    family = socket.AF_INET6
  else:
    family = socket.AF_INET
  return socket.inet_ntop(family, socket.inet_pton(family, address))


class ConnectionInfo:
  def __init__(self, local_ip, local_port, remote_ip, remote_port, pid, fd, uid):
    self.local_ip = local_ip
    self.local_port = local_port
    self.remote_ip = remote_ip
    self.remote_port = remote_port
    self.pid = pid
    self.fd = fd
    self.uid = uid

  def __repr__(self):
    return f"{self.local_ip}:{self.local_port} -> {self.remote_ip}:{self.remote_port}, pid={self.pid}, fd={self.fd}, uid={self.uid}"

def _find_socket_fds(local_addr=None, local_port=None, remote_addr=None, remote_port=None):
  """
    Finds all socket file descriptors associated with TCP connections and filters them.

    Args:
        local_addr: (Optional) Local IP address of the connection.
        local_port: (Optional) Local port of the connection.
        remote_addr: (Optional) Remote IP address of the connection.
        remote_port: (Optional) Remote port of the connection.

    Returns:
        A list of ConnectionInfo objects that match both local and remote criteria.
    """

  lsof_command = "lsof -nP -iTCP -sTCP:ESTABLISHED -Fpfun"
  process = subprocess.Popen(lsof_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  output, error = process.communicate()

  if process.returncode != 0:
    print(f"lsof command exited with error: {error.strip()}")

  connections = []
  pid, fd, uid = None, None, None
  for line in output.splitlines():
    if line.startswith('p'):
      pid = int(line[1:])
    elif line.startswith('f'):
      fd = int(line[1:])
    elif line.startswith('u'):
      uid = int(line[1:])
    elif line.startswith('n'):
      connection_info = line[1:]
      local, remote = connection_info.split('->')
      local_ip, local_port_str = local.rsplit(':', 1)
      remote_ip, remote_port_str = remote.rsplit(':', 1)

      if ((local_addr is None or local_ip == local_addr) and
        (local_port is None or int(local_port_str) == local_port) and
        (remote_addr is None or remote_ip == remote_addr) and
        (remote_port is None or int(remote_port_str) == remote_port)):

        connection = ConnectionInfo(local_ip, int(local_port_str), remote_ip, int(remote_port_str), pid, fd, uid)

        connections.append(connection)

  return connections


def tcp_kill(local_addr, local_port, remote_addr, remote_port, verbose=False):
  """Shuts down a TCP connection on Linux or macOS.

  Finds the process and socket file descriptor associated with a given TCP
  connection. Then injects into that process a call to shutdown()
  (http://man7.org/linux/man-pages/man2/shutdown.2.html) that file descriptor,
  thereby shutting down the TCP connection.

  Args:
    local_addr: The IP address (as a string) associated with the local endpoint
      of the connection.
    local_port: The port (as an int) associated with the local endpoint of the
      connection.
    remote_addr: The IP address (as a string) associated with the remote
      endpoint of the connection.
    remote_port: The port (as an int) associated with the remote endpoint of the
      connection.
    verbose: If True, print verbose output to the console.

  Returns:
    No return value if successful. If unsuccessful, raises an exception.

  Raises:
    KeyError: Unexpected output from lsof command.
    NotImplementedError: Not running on a Linux or macOS system.
    OSError: TCP connection not found or socket file descriptor not found.
    RuntimeError: Error during execution of JavaScript injected into process.
  """

  if platform.system() not in ("Darwin", "Linux"):
    raise NotImplementedError("This function is only implemented for Linux and "
                              "macOS systems.")

  connections = _find_socket_fds(local_addr, local_port, remote_addr, remote_port)

  sockfd = None
  if(connections):
    pid = connections[0].pid
    sockfd = connections[0].fd

  if not sockfd:
    s = " Try running as root." if os.geteuid() != 0 else ""
    raise OSError(f"Socket not found for connection." + s)

  if verbose:
    print(f"Process ID of socket's process: {pid}")
    print(f"Socket file descriptor: {sockfd}")

  _shutdown_sockfd(pid, sockfd)


def _shutdown_sockfd(pid, sockfd):
  """Injects into a process a call to shutdown() a socket file descriptor.

  Injects into a process a call to shutdown()
  (http://man7.org/linux/man-pages/man2/shutdown.2.html) a socket file
  descriptor, thereby shutting down its associated TCP connection.

  Args:
    pid: The process ID (as an int) of the target process.
    sockfd: The socket file descriptor (as an int) in the context of the target
      process to be shutdown.

  Raises:
    RuntimeError: Error during execution of JavaScript injected into process.
  """

  js_error = {}  # Using dictionary since Python 2.7 doesn't support "nonlocal".
  event = threading.Event()

  def on_message(message, data):  # pylint: disable=unused-argument
    if message["type"] == "error":
      js_error["error"] = message["description"]
    event.set()

  session = frida.attach(pid)
  script = session.create_script(_FRIDA_SCRIPT % sockfd)
  script.on("message", on_message)
  closed = False

  try:
    script.load()
  except frida.TransportError as e:
    if str(e) != "the connection is closed":
      raise
    closed = True

  if not closed:
    event.wait()
    session.detach()
  if "error" in js_error:
    raise RuntimeError(js_error["error"])


if __name__ == "__main__":

  class ArgParser(argparse.ArgumentParser):

    def error(self, message):
      print("tcp_killer v" + __version__)
      print("by " + __author__)
      print()
      print("Error: " + message)
      print()
      print(self.format_help().replace("usage:", "Usage:"))
      self.exit(0)


  parser = ArgParser(
    add_help=False,
    description="Shuts down a TCP connection on Linux or macOS. Local and "
                "remote endpoint arguments can be copied from the output of 'netstat "
                "-lanW'.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=r"""
Examples:
  %(prog)s 10.31.33.7:50246 93.184.216.34:443
  %(prog)s 2001:db8:85a3::8a2e:370:7334.93 2606:2800:220:1:248:1893:25c8:1946.80
  %(prog)s -verbose [2001:4860:4860::8888]:46820 [2607:f8b0:4005:807::200e]:80
""")

  args = parser.add_argument_group("Arguments")
  args.add_argument("-verbose", required=False, action="store_const",
                    const=True, help="Show verbose output")
  args.add_argument("local", metavar="<local endpoint>",
                    help="Connection's local IP address and port")
  args.add_argument("remote", metavar="<remote endpoint>",
                    help="Connection's remote IP address and port")
  parsed = parser.parse_args()

  ep_format = re.compile(r"^(.+)[:\.]([0-9]{1,5})$")
  local = ep_format.match(parsed.local)
  remote = ep_format.match(parsed.remote)
  if not local or not remote:
    parser.error("Invalid command-line argument.")

  local_address = local.group(1)
  if local_address.startswith("[") and local_address.endswith("]"):
    local_address = local_address[1:-1]

  remote_address = remote.group(1)
  if remote_address.startswith("[") and remote_address.endswith("]"):
    remote_address = remote_address[1:-1]

  tcp_kill(local_address, int(local.group(2)), remote_address,
           int(remote.group(2)), parsed.verbose)

  print("TCP connection was successfully shutdown.")
