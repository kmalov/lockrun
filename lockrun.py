import optparse
import signal
import threading
import syslog
import time
import os
import re


def find_process(first_pid, process):
    # Find a process in /proc
    process = re.sub(" +", " ", process).strip()
    m = re.compile("^[0-9]+$")
    all_proc = [ x for x in os.listdir("/proc") if m.search(x)]
    for p in all_proc[all_proc.index(str(first_pid)):]:
        try:
            with open("/proc/%s/cmdline" % p, "r") as f:
                cmdline = f.readline().replace("\x00", " ").rstrip('\n').strip()
                if process == cmdline:
                    return int(p)
        except IOError:
            pass

    return False

def process_watcher(child_process, parent_pid, timeout):

    child_pid = find_process(parent_pid, child_process)

    if child_pid:
        syslog.syslog(syslog.LOG_WARNING,
                      """Trying to kill process "%s"[%s] by timeout(%ss)"""
                      % (child_process, child_pid, timeout))

        os.kill(child_pid, signal.SIGTERM)
    else:
        syslog.syslog(syslog.LOG_WARNING,
                      """Can't find task process "%s" in /proc""" % child_process)


if __name__ == "__main__":

    op = optparse.OptionParser()
    op.add_option("-P", "--program", dest="program", default=False, type="string")
    op.add_option("-p", "--lockfile", dest="lockfile", default=False, type="string")
    op.add_option("-t", "--timeout", dest="timeout", default=False, type="int")

    opts, args = op.parse_args()

    if opts.timeout:
        watcher = threading.Timer(opts.timeout, process_watcher, [opts.program, os.getpid(), opts.timeout])
        watcher.start()

    # Run program
    start_time = time.time()
    return_code = os.system(opts.program)
    total_tile = time.time() - start_time

    if opts.timeout:
        watcher.cancel()

    syslog.syslog(syslog.LOG_NOTICE,
                  """Command "%s" is done with return code: %s. Execution time %.2fs""" % (opts.program, return_code, total_tile))
