"""
script to handle virus total scans of files in connection with SW requests

use cases:
Scan files in a directory
    given a path to a directory containing files to be scanned, get resulsts
    of scans for all files in the directory

    assumptions/questions:

        * look for files only in the directory provided - will not look into subdirectories
        * how to handle results, e.g. is any fail result a fail overall, etc.
        * file names does NOT start with a dot '.'

Others TBD
"""

import pprint as pp

import sw_review_lib as lib

args = lib.get_cli_args()
file_dir = args['path']
prev_scan_window = args['window']

# get list of files in directory
files_to_scan = lib.get_file_names_to_scan(file_dir)

queue = []  # files that will need to be scanned
vt_results = {}  # dict to hold vt findings for each file

lib.get_existing_results_and_queue(files_to_scan, prev_scan_window, queue, vt_results)

lib.scan_queued_files(queue, vt_results)

# write results to a file (CSV?)