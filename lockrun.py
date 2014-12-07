#!/bin/env python

import optparse
import threading
import time
import sys
import os
import re

from signal import SIGTERM
from syslog import syslog, LOG_WARNING, LOG_NOTICE


def compare_processes_cmd(process_cmd, pid):
    process_cmd = re.sub(" +", " ", process_cmd).strip()
    try:
        with open("/proc/%s/cmdline" % pid, "r") as f:
            cmdline = f.readline().replace("\x00", " ").rstrip('\n').strip()
            if process_cmd == cmdline:
                return True
            else:
                return False
    except IOError:
        return False


def find_process_pid(process_cmd, start_from_pid=300):
    """
    Min pid is 300 from kernel/pid.c, see RESERVED_PIDS
    """
    # Find all active processes
    all_processes = [d for d in os.listdir("/proc") if d.isdigit() and int(d) >= start_from_pid]

    # Find our process
    for p in all_processes:
        if compare_processes_cmd(process_cmd, p):
            return int(p)

    return False


def get_cmdline_by_pid(pid):
    try:
        with open("/proc/%s/cmdline" % pid, "r") as fh:
            return fh.readline().replace("\x00", " ").rstrip('\n').strip()
    except IOError:
        return False


def get_pid_from_lockfile(lockfile):
    try:
        with open(lockfile, "r") as f:
            pid = f.readline().rstrip('\n').strip()
            return int(pid) if pid.isdigit() else False
    except IOError:
        return False


def process_watcher(process_cmd, parent_pid):
    child_pid = find_process_pid(process_cmd, parent_pid)
    if child_pid:
        os.kill(child_pid, SIGTERM)
        syslog(LOG_WARNING,
               """Trying to kill process "%s"[%s] by timeout""" % (process_cmd, parent_pid))
    else:
        syslog(LOG_WARNING,
               """Can't find process "%s" pid to kill it by timeout""" % process_cmd)


def is_locked(process_cmd, lockfile):
    # No lockfile
    if not os.path.exists(lockfile):
        return False

    # lockfile exists, but no pid
    pid = get_pid_from_lockfile(lockfile)
    if not pid:
        return False

    # Check pid in proc
    if not os.path.exists("/proc/%s" % pid):
        return False

    # Process cmd in /proc mismatch with new task cmd
    if not compare_processes_cmd(process_cmd, pid):
        return False

    return True


def log_msg(log_level, msg):
    if log_level == LOG_NOTICE:
        out = sys.stdout
    else:
        out = sys.stderr

    out.write("%s\n" % msg)
    syslog(log_level, msg)


if __name__ == "__main__":

    op = optparse.OptionParser()
    op.set_usage("%s -t TASK -l LOCKFILE [-T TIMEOUT|-k|-v]" % sys.argv[0])

    op.add_option("-t", "--task", dest="task",
                  default=False, type="string",
                  help="Task command to run")
    op.add_option("-l", "--lockfile", dest="lockfile",
                  default=False, type="string",
                  help="Path to lockfile")
    op.add_option("-T", "--timeout", dest="timeout",
                  default=False, type="int",
                  help="Set timeout to kill task after timeout")
    op.add_option("-k", "--kill", dest="kill",
                  default=False, action="store_true",
                  help="Try to kill previous task before starting new task")
    op.add_option("-v", "--verbose", dest="verbose",
                  default=False, action="store_true",
                  help="Add more debug messages to syslog")

    opts, args = op.parse_args()

    if not opts.lockfile and not opts.task:
        op.print_help()
        sys.exit(1)

    if opts.verbose:
        log_msg("New lockrun task '%s' with options: lockfile = %s; timeout = %s; kill = %s" %
                (opts.task, opts.lockfile, opts.timeout, opts.kill))

    # Handle locks
    if opts.lockfile:
        self_pid = os.getpid()
        self_process_cmd = get_cmdline_by_pid(self_pid)

        if not self_process_cmd:
            log_msg("ERROR: Can't find pid %s in /proc for task '%s'" % (self_pid, opts.task))
            sys.exit(1)

        # Check for lock
        if is_locked(self_process_cmd, opts.lockfile):
            if opts.kill:
                pid = get_pid_from_lockfile(opts.lockfile)
                if pid:
                    log_msg(LOG_WARNING, "Try to kill previous task '%s' with pid %s!" %
                            (opts.task, pid))
                    os.kill(pid, SIGTERM)
            else:
                log_msg(LOG_WARNING, "Previous task '%s' is running. I'm done." % opts.task)
                sys.exit(1)
        else:
            if opts.verbose:
                log_msg("Can't find lock from previous task '%s'. Ready to start new task." % opts.task)

        # Set lock
        try:
            with open(opts.lockfile, "w") as f:
                f.write("%s\n" % self_pid)
        except IOError as e:
            log_msg(LOG_WARNING, "Can't set lockfile %s for task '%s': %s" %
                    (opts.lockfile, opts.task, e))
            sys.exit(1)

    if opts.timeout:
        watcher = threading.Timer(opts.timeout, process_watcher, [opts.task, os.getpid()])
        watcher.start()

    # Run program
    start_time = time.time()
    return_code = os.system(opts.task)
    total_time = time.time() - start_time

    if opts.timeout:
        watcher.cancel()

    if return_code != 0 or opts.verbose:
        log_msg(LOG_NOTICE,
                "Task '%s' is done with return code: %s. Execution time %.2fs"
                % (opts.task, return_code, total_time))

    if opts.lockfile:
        try:
            os.remove(opts.lockfile)
        except OSError as e:
            log_msg(LOG_WARNING, "Can't remove lockfile %s for task '%s': %s" %
                    (opts.lockfile, opts.task, e))