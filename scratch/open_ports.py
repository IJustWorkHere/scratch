#!/usr/bin/env python
from subprocess import PIPE, Popen
import logging
import os
import re
import shlex

logging.basicConfig(level=logging.INFO,
                    filename="/var/log/zabbix/ports.log",
                    format='%(asctime)s %(message)s')

logger = logging.getLogger(__name__)

proc_dir = '/proc'

def open_subprocess(arguments):
    try:
        return Popen(arguments, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    except OSError as e:
        return e.strerror

def run_command(arguments):
    logger.debug("Running command {0}".format(arguments))
    p = open_subprocess(shlex.split(arguments))
    if hasattr(p, 'communicate'):
        # Add a loop to allow an opportunity to send a kill signal to the process
        stdout, stderr = p.communicate()
        if len(stdout) > 0:
            [ logger.debug(command_stdout) for command_stdout in stdout.splitlines()]
        if len(stderr) > 0:
            [ logger.error(command_stderr) for command_stderr in stderr.splitlines() ]
        return stdout
    else:
        exit(1)

def check_match(regex, text):
    try:
        return re.search(regex, text).group(1)
    except AttributeError:
        return

def sock_type_to_name(sock_type):
    maps = { "SOCK_DGRAM": "UDP",
             "SOCK_STREAM": "TCP"}
    return maps.get(sock_type)

def format_pfile_return(pid, process_name, listening):
    out = {"PID": pid, "Process": process_name, "Ports": []}
    for port in listening:
        out["Ports"].append(
                {
                    "bind_address": port[0],
                    "bind_port": port[1],
                    "bind_protocol": port[2]
                }
        )
    return out

def parse_listening_text(text, line_number):
    start_regex = re.compile('^\s+{0}:\s+S_IFSOCK'.format(str(line_number)))
    end_regex = re.compile('^\s+{0}:\s+'.format(str(int(line_number) + 1)))
    in_match = False
    sock_type = None
    port = None
    address = None

    for line in text.splitlines():
        if start_regex.match(line):
            in_match = True
        if end_regex.match(line):
            if not sock_type or not port or not address:
                return
            elif int(port) == 0:
                return
            else:
                return address, port, sock_type_to_name(sock_type)
        if in_match:
            if not sock_type:
                sock_type = check_match('(SOCK_DGRAM|SOCK_STREAM)', line)
            if not port:
                port = check_match('port: (\d+)', line)
            if not address:
                address = check_match('AF_INET ((\d+\.){3}\d+|\*)', line)
            if check_match('(peername):', line) is not None:
                return

def parse_pfile_out(text):
    ifsock_regex = re.compile('^\s+(\d+):\s+S_IFSOCK')
    pid = None
    process_name = None
    listening = list()
    for line in text.splitlines():
        if not pid:
            pid = check_match('^(\d+):', line)
        if not process_name:
            process_name = check_match('^\d+:\s+(.*$)', line)
        if ifsock_regex.match(line):
            listen_info = parse_listening_text(text, ifsock_regex.match(line).group(1))
            if listen_info:
                listening.append(listen_info)
    return format_pfile_return(pid, process_name, listening)


def main():
    results = list()
    cmd = "pfiles"
    for proc in os.listdir(proc_dir):
        logger.debug("Examing process {0}".format(proc))
        result = parse_pfile_out(run_command("{0} {1}".format(cmd, proc)))
        if len(result["Ports"]) > 0:
            results.append(result)
    for result in results:
        ports = result.pop("Ports")
        for port in ports:
            result.update(port)
            logger.info(result)

main()