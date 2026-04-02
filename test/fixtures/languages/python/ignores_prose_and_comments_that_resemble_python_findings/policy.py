"""The model is only
consulted for the borderline judgment the rules deliberately leave open.
"""

if len(sys.argv) > 1:  # a transcript was passed on the command line
    run()
try:
    run()
except Exception as exc:  # importing is a hard failure
    report(exc)

if ready: run()
handle = open("report.txt", "r")
