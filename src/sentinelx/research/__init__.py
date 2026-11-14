"""Research Lab: static inspection, YARA testing and comparison of user-selected files.

Nothing here executes the analyzed file. PE parsing and signature inspection run in a
separate worker process (`research.worker`) with a time and memory limit.
"""
