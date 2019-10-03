#!/usr/bin/python3

"""

< Description of script >

Author: Vincent Zhen < Email address >

"""

from __future__ import print_function

import os
import sys
import signal
import argparse
import logging

import subprocess as sp
from datetime import datetime # XREF: http://strftime.org/

if sys.version_info[0] < 3:
    import ConfigParser
else:
    import configparser

__version__ = 0.1


# Logging configuration
LOG = logging.getLogger(__name__)

def set_stdout_output(log_level=logging.INFO):
    OUT_HANDLER = logging.StreamHandler(sys.stdout)
    OUT_HANDLER.setLevel(log_level)
    OUT_HANDLER.setFormatter(logging.Formatter('%(asctime)s - [%(levelname)s] %(message)s'))
    LOG.addHandler(OUT_HANDLER)
def set_file_output(filename, log_level=logging.INFO):
    OUT_HANDLER = logging.FileHandler(filename)
    OUT_HANDLER.setLevel(log_level)
    OUT_HANDLER.setFormatter(logging.Formatter('%(asctime)s - [%(levelname)s] %(message)s'))
    LOG.addHandler(OUT_HANDLER)

# Default signal handler
def sig_handler(signal, frame):
    LOG.warn("SIGINT/SIGTERM caught. Exiting...")
    sys.exit(1)




"""
----------------------------------------

          Your codes go here!

----------------------------------------
"""

def load_conf():
    config = configparser.ConfigParser()
    config.read("cherrytree.conf")
    print(config.sections())
    s = config['CherryTree']
    return s

def check_newest(remote_f, local_f):
    src_output = sp.Popen("rclone lsl {}".format(remote_f), shell=True, stdout=sp.PIPE).communicate()[0]
    dst_output = sp.Popen("rclone lsl {}".format(local_f), shell=True, stdout=sp.PIPE).communicate()[0]
    LOG.debug("Remote output: {}".format(src_output))
    LOG.debug("Local output: {}".format(dst_output))
    src_timestamp = ' '.join(src_output.decode('utf-8').split()[1:3])[:-3]
    dst_timestamp = ' '.join(dst_output.decode('utf-8').split()[1:3])[:-3]
    src_timestamp = datetime.strptime(src_timestamp, "%Y-%m-%d %H:%M:%S.%f")
    dst_timestamp = datetime.strptime(dst_timestamp, "%Y-%m-%d %H:%M:%S.%f")
    newest = max(src_timestamp, dst_timestamp)
    LOG.info("Source (GDRIVE) timestamp: {}".format(src_timestamp))
    LOG.info("Destination (LOCAL) timestamp: {}".format(dst_timestamp))
    if newest == src_timestamp:
        return "src"
    if newest == dst_timestamp:
        return "dest"

def push(local_f, remote_p):
    sp.Popen("rclone copy {} {}".format(local_f, remote_p), shell=True)
    return "push"

def pull(remote_f, local_p):
    sp.Popen("rclone copy {} {}".format(remote_f, local_p), shell=True)
    return "pull"

def stash(local_f):
    sp.Popen("cp {} {}.backup".format(local_f, local_f), shell=True)
    return "stash"

def ct_open(local_f):
    proc = sp.call("cherrytree {}".format(local_f), shell=True)
    return "open"

# XREF: https://pymotw.com/3/argparse/
def set_arguments():
    parser = argparse.ArgumentParser("Push/pull CherryTree file from GDrive using rclone")

    parser.add_argument("action", type=str, choices=['push', 'pull', 'status', 'auto', 'stash', 'open'])

    # Argument grouping
    group_1 = parser.add_argument_group("default arguments")
    group_1.add_argument('-v', "--verbose", help="Set logging to debug", action="store_true", default=False)
    group_1.add_argument("--version", help="Get version of script", action="store_true", default=False)
    group_1.add_argument("--stdout", help="Log to stdout/terminal. Will not output to file unless requested with --output-file", action="store_true", default=False)
    group_1.add_argument("--output-file", help="Log to a specific file. Default: ./{}.log".format(os.path.splitext(__file__)[0]), metavar="OUTPUT-FILENAME", default=None, type=str, required=False)

    args = parser.parse_args()
    # Always run to stdout
    args.stdout = True
    """
    Basic argument logic
    """
    log_level = logging.DEBUG if args.verbose else logging.INFO
    # Set base level of logging
    LOG.setLevel(log_level)
    set_stdout_output(log_level) if args.stdout else set_stdout_output(logging.ERROR)
    set_file_output(args.output_file, log_level) if args.output_file else set_file_output("{}.log".format(os.path.splitext(__file__)[0]), log_level)

    if args.version:
        print(__version__)
        sys.exit(0)

    return args.action

def main():
    action = set_arguments()
    conf = load_conf()
    local_p = conf['CHERRYTREE_LOCAL_PATH']
    remote_p = conf["CHERRYTREE_REMOTE_PATH"]
    local_f = '{}{}'.format(local_p, conf["CHERRYTREE_FILE"])
    remote_f = '{}{}'.format(remote_p, conf["CHERRYTREE_FILE"])

    def auto():
        newest = check_newest(remote_f, local_f)
        if newest == "src":
            ret = pull(remote_f, local_p)
        if newest == "dest":
            ret = push(local_f, remote_p)
        return "auto/{}".format(ret)

    if action == "auto":
        ret = auto()
    elif action == "open":
        ret1 = auto()
        ct_open(local_f)
        ret2 = auto()
        ret = "open with '{}' then '{}'".format(ret1, ret2)
    elif action == 'push':
        ret = push(local_f, remote_p)
    elif action == 'pull':
        ret = pull(remote_f, local_p)
    elif action == 'status':
        ret = check_newest(remote_f, local_f)
    elif action == 'stash':
        ret = stash(local_f)

    if ret:
        LOG.info("Success: {}".format(ret))
    else:
        LOG.error("Failure! Something wrong happened.")
    pass


if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    main()
