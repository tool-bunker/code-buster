import os

if os.name == "nt":
    import ctypes
    configure_windows(ctypes)
    import codecs

configure()
import json
