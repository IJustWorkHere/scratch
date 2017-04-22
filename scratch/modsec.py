#!/usr/bin/env python
# Will execute a scan against a file and check it's mime type to see if it
# is allowed
from subprocess import Popen, PIPE
import os, sys, re
import logging
import shlex
import magic
import threading
import random

log_filename = 'av.log'

# Setup Logging
tlocal = threading.local()
format = logging.Formatter('%(asctime)s [%(jid)s] %(message)s')

class JidFilter(logging.Filter):
    def filter(self, record):
        record.jid = tlocal.jid
        return True

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
jidFilter = JidFilter()
fileHandler = logging.FileHandler(log_filename)
fileHandler.addFilter(jidFilter)
fileHandler.setFormatter(format)
logger.addHandler(fileHandler)

allowed_file_strings = [
    "PLAIN"
]

denied_file_strings = [
    "XML"
]

def run_command(arguments):
    retcode = 1
    logger.debug("Running command {0}".format(arguments))
    p = open_subprocess(shlex.split(arguments))
    if hasattr(p, 'communicate'):
        stdout, stderr = p.communicate()
        retcode = p.returncode
        logger.info("{0} completed with exit code {1}".format(arguments, retcode))
        if len(stdout) > 0:
            [ logger.info(command_stdout) for command_stdout in stdout.splitlines()]
        if len(stderr) > 0:
            [ logger.error(command_stderr) for command_stderr in stderr.splitlines() ]
        return retcode
    else:
        return retcode

def open_subprocess(arguments):
    try:
        return Popen(arguments, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    except OSError as e:
        return e.strerror

def run_scan(file):
    uvscan      = "/path/to/av"
    uvscan_dat  = "/path/to/dat"
    uvscan_args = "--SECURE --SILENT --DAT {0}".format(uvscan_dat)
    cmd         = "{0} {1} '{2}'".format(uvscan, uvscan_args, file)
    return run_command(cmd)

def is_allowed_mime_type(mtype):
    internet_media_type = mtype.split('/')[1].upper()
    for explicit_denial_string in denied_file_strings:
        if re.search(explicit_denial_string, internet_media_type):
            logger.error("{0} appears to be an {1} and is therefore not allowed".format(mtype, explicit_denial_string))
            return False
    for explicit_allow_string in allowed_file_strings:
        if re.search(explicit_allow_string, internet_media_type):
            return True
    logger.error("{0} did not match an allowed file type".format(mtype))
    return False


def check_file_type(file):
    mime = magic.Magic(mime=True, uncompress=True)
    mtype = mime.from_file(file)
    logger.debug("Checking if {0} is an allowed Mime Type".format(mtype))
    return is_allowed_mime_type(mtype)

if __name__ == '__main__':
    tlocal.jid = random.randint(1,9999999999)
    msg = "0 Error"
    try:
        file = sys.argv[1]
        logger.info("Processing {0}".format(file))
        if check_file_type(file):
            retcode = run_scan(file)
            if retcode == 0:
                msg = "1 OK"
    except IndexError as exc:
        logger.error("Not enough arguments provided: {0}".format(exc))
    print msg