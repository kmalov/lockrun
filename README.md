lockrun
=======

A wrapper to lock cron jobs from start then previous job is still running.
Also it can kill cron job by timer or kill previous task before running new one.   

=======

lockrun.py -t TASK -l LOCKFILE [-T TIMEOUT] [-k] [-v]
