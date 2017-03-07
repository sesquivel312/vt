"""
VTP API inf

json based, using POST

rate-limit: 4 requests/miniute

file-size limite 32MB

responses contain:

response code, verbose_msg

response codes:
1: item has been scanned, results avialble
0: not in dataset
-2: item queued for analysis

exceeding rate limit returns 204 status code

403 returned for actions not permitted

sending a file:
POST https://www.virustotal.com/vtapi/v2/file/scan

expects multi-part mime encoding

get api key by signing up for community, key available in profile

Environment Variables:
VT_API_KEY = one possible location script will pull api key from


"""

import argparse
import os
import os.path
import sys
import hashlib
import re
import time
import pprint as pp
import pdb

import requests

# todo read config items from file using std lib ini format parser (confparse?)
# todo parallelize this
# Endpoints
# todo build a class for handling the VT api calls and "session"
VT_EP_FILE_SCAN = 'https://www.virustotal.com/vtapi/v2/file/scan'  # virus total upload URL
VT_EP_FILE_RESCAN = 'https://www.virustotal.com/vtapi/v2/file/rescan'
VT_EP_FILE_REPORT = 'https://www.virustotal.com/vtapi/v2/file/report'

# Misc useful data
VT_MAX_FILE_SIZE_MB = 32
VT_MAX_REQ_RATE_PER_MIN = 4

# examples
# upload

# params = {'apikey': '-YOUR API KEY HERE-'}
# files = {'file': ('myfile.exe', open('myfile.exe', 'rb'))}
# response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
# json_response = response.json()

""" response:

{
  'permalink': 'https://www.virustotal.com/file/d140c...244ef892e5/analysis/1359112395/',
  'resource': u'd140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556',
  'response_code': 1,
  'scan_id': 'd140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556-1359112395',
  'verbose_msg': 'Scan request successfully queued, come back later for the report',
  'sha256': 'd140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556'
}
"""

#rescan
# params = {'apikey': '-YOUR API KEY HERE-', 'resource': '7657fcb7d772448a6d8504e4b20168b8'}
# headers = {
#   "Accept-Encoding": "gzip, deflate",
#   "User-Agent" : "gzip,  My Python requests library example client or username"
#   }
# response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan',
#  params=params)
# json_response = response.json()

"""
results:
{
  'response_code': 1,
  'scan_id': '54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71-1390472785'
  'permalink': 'https://www.virustotal.com/file/__sha256hash__/analysis/1390472785/',
  'sha256': '54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71',
  'resource': '7657fcb7d772448a6d8504e4b20168b8',
}
"""

#retrieve existing report/results
# params = {'apikey': '-YOUR API KEY HERE-', 'resource': '7657fcb7d772448a6d8504e4b20168b8'}
# headers = {
#   "Accept-Encoding": "gzip, deflate",
#   "User-Agent" : "gzip,  My Python requests library example client or username"
#   }
# response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
#   params=params, headers=headers)
# json_response = response.json()

"""
response:
{
 'response_code': 1,
 'verbose_msg': 'Scan finished, scan information embedded in this object',
 'resource': '99017f6eebbac24f351415dd410d522d',
 'scan_id': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724',
 'md5': '99017f6eebbac24f351415dd410d522d',
 'sha1': '4d1740485713a2ab3a4f5822a01f645fe8387f92',
 'sha256': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c',
 'scan_date': '2010-05-15 03:38:44',
 'positives': 40,
 'total': 40,
 'scans': {
    'nProtect': {'detected': true, 'version': '2010-05-14.01', 'result': 'Trojan.Generic.3611249', 'update': '20100514'},
    'CAT-QuickHeal': {'detected': true, 'version': '10.00', 'result': 'Trojan.VB.acgy', 'update': '20100514'},
    'McAfee': {'detected': true, 'version': '5.400.0.1158', 'result': 'Generic.dx!rkx', 'update': '20100515'},
    'TheHacker': {'detected': true, 'version': '6.5.2.0.280', 'result': 'Trojan/VB.gen', 'update': '20100514'},
    .
    .
    .
    'VirusBuster': {'detected': true, 'version': '5.0.27.0', 'result': 'Trojan.VB.JFDE', 'update': '20100514'},
    'NOD32': {'detected': true, 'version': '5115', 'result': 'a variant of Win32/Qhost.NTY', 'update': '20100514'},
    'F-Prot': {'detected': false, 'version': '4.5.1.85', 'result': null, 'update': '20100514'},
    'Symantec': {'detected': true, 'version': '20101.1.0.89', 'result': 'Trojan.KillAV', 'update': '20100515'},
    'Norman': {'detected': true, 'version': '6.04.12', 'result': 'W32/Smalltroj.YFHZ', 'update': '20100514'},
    'TrendMicro-HouseCall': {'detected': true, 'version': '9.120.0.1004', 'result': 'TROJ_VB.JVJ', 'update': '20100515'},
    'Avast': {'detected': true, 'version': '4.8.1351.0', 'result': 'Win32:Malware-gen', 'update': '20100514'},
    'eSafe': {'detected': true, 'version': '7.0.17.0', 'result': 'Win32.TRVB.Acgy', 'update': '20100513'}
  },
 'permalink': 'https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/'
}
"""


def get_cli_args():
    p = argparse.ArgumentParser()
    p.add_argument('path', help='Path to directory containing files to be scanned, e.g. /home/user/files')
    p.add_argument('-d', help='Time window, in days, within which to accept previous scan results, '
                              'given as an integer.  Example: if today is 2/5/2017 and the option is specified as '
                              '"-d 2", then results for files analyzed by VT between 2/3 and 2/5 will be accepted '
                              'Defaults to 0')

    arg_dict = {'window': 0, 'path': ''}

    args = p.parse_args()

    file_path = args.path  # todo add some exception handling here?
    file_path = os.path.expanduser(file_path)  # expand home dir shortcut if specified
    ndays = args.d

    # verify path exists & is a directory
    if os.path.exists(file_path) and os.path.isdir(file_path):
        arg_dict['path'] = file_path
    else:
        sys.exit('*** Path not exist or not a directory')

    # verify window is an integer
    try:
        arg_dict['window'] = int(ndays)
    except:
        sys.exit('*** Problem with window, was it an integer?')

    return arg_dict


def get_api_key(config_file=None):
    """
    get api key to use when accessing VT API

    looks in the following places, in priority order
    * file specified as argument
    * environment variable
    * file called ~/.vtkey

    :param config_file:
    :return: string representing API key
    """

    key = None

    key_from_env = os.environ.get('VT_API_KEY')  # will be None if it doesn't exist

    if config_file:  # if we got a config file path value
        os.path.expanduser(config_file)  # possibly expand home dir shortcut
        if os.path.exists(config_file):
            f = open(config_file)
            temp_key = f.readline()
            if re.match(r'[a-z0-9]{20,}', temp_key):
               key = temp_key
    elif key_from_env:  # if the env var is defined
        if re.match(r'[a-z0-9]{20,}', key_from_env):
            key = key_from_env
    else:
        default_key_file = os.path.expanduser('~/.vtkey')
        if os.path.exists(default_key_file):
            with open(default_key_file) as f:
                temp_key = f.readline()
                if re.match(r'[a-z0-9]{20,}', temp_key):
                    key = temp_key

    return key


def get_file_names_to_scan(path):
    path = os.path.expanduser(path)  # in case path have been given relative to user's home directory
    walk_results = os.walk(path)  # this returns a generator, so
    files_tuple = walk_results.next()  # only want first iteration, i.e. ignore subdirs if they exist
    path_prefx = files_tuple[0]  # walk returns tuples: (path, dirs, files), need path to make 'path + file'
    potential_files = files_tuple[2]  # files are in the 3rd position of the tuple

    files = []
    for f in potential_files:
        if not f.startswith('.'):  # ignore files starting with dot
            files.append(os.path.join(path_prefx, f))

    return files


def check_file_within_size_limit(file_path, exponent=6):
    """
    determine if file size is below VT max

    leverages global VT_MAX_FILE_SIZE_MB and exponent defaults to 6, i.e. MB

    NB: this function currently doesn't provide a valid return value if you specify
    an exponent other than 6, the default, maybe someday?

    :param file: path to file
    :param exponent: integer power of 10, defaults to 6, i.e. MBs
    :return:
    """

    fsize = os.path.getsize(file_path)
    fsize /= (10**exponent)  # convert to units specified
    if fsize < VT_MAX_FILE_SIZE_MB:
        return True
    else:
        return False


def get_file_hash(file_path, algorithm='sha256'):
    """
    return hex'ified hash of file using algorithm speicifed as parameter
    :param file_path: string providing path to file
    :param algorithm: string indicating one of a specific list of algorithms to use
    :return: string hex representation of hash
    """

    # /home/steve/Downloads/matplotlib-swreq/pyparsing-2.2.0-py2.py3-none-any.whl
    if algorithm == 'sha256':
        h = hashlib.sha256()
    file_path = os.path.expanduser(file_path)
    if os.path.exists(file_path):
        f = open(file_path,'rb')
    cont = True
    while cont:
        bin_data = f.read(1024)
        h.update(bin_data)
        if len(bin_data) < 1024:
            cont = False

    return h.hexdigest()


def check_previous_scan(file_path, window, apikey):
    """
    check for a previous scan of a file within the acceptable window

    calls the VT file/report endpoint

    if the file has been scanned previously w/in the acceptable window (days), return
    the interesting data from that scan.  otherwise return a string indicating a scan is required:

        scan:first << implies VT didn't have any info about a previous scan
        scan:stale << implies VT has prev. scan results but they're outside the acceptable window

    :param file_path:
    :param window:
    :param queue:
    :param vt_results:
    :param apikey:
    :return: 'scan:first' | 'scan:stale' | dict containing interesting data from prev results
    """

    hash_algo = 'sha256'
    fhash = get_file_hash(file_path, hash_algo)

    # get previous results for file
    params = {'apikey': apikey, 'resource': fhash}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip,  My Python requests library example client or username"
    }

    # pdb.set_trace()
    time.sleep(16)  # fix this to send requests in a burst, but track rate
    response = requests.get(VT_EP_FILE_REPORT, params=params, headers=headers)  # todo handle response codes

    response_dict = response.json()

    # if previous scan w/in acceptable window
    if response_dict.get('response_code') == 1:  # file prev. scanned, NB not checking window yet
        # todo add window check
        interesting_keys = ['permalink', 'scan_date', 'positives', 'verbose_msg']

        result = {k: response_dict[k] for k in interesting_keys}

        result[hash_algo] = fhash

        # return relevant previous scan results
        return result

    else:
        return 'scan:first'  # adjust when acceptable window checking is added


def map_vt_results(vt_result_dict, local_result_dict):

    """
    map values from vt results data to key names defined in this script
    :param vt_result_dict:  dict of data gathered from a vt scan report
    :param local_result_dict: dict of values using "local" key names, i.e. different than vt's key names
    :return: n/a
    """

    local_result_dict['sha256'] = vt_result_dict['sha256']
    local_result_dict['last_scan'] = vt_result_dict['scan_date']
    local_result_dict['permalink'] = vt_result_dict['permalink']
    local_result_dict['positives'] = vt_result_dict['positives']
    local_result_dict['info'] = vt_result_dict['verbose_msg']


def get_existing_results_and_queue(files_to_scan, prev_scan_window, queue, vt_results):
    """
    get virustotal results for a list files

    if a file has been scanned within the given window then get the results.

    If not, then add to queue to later upload to VT for scan

    :param files_to_scan: list of files to scan
    :param prev_scan_window: size of acceptable previous scan window in days
    :param queue: dict of files that haven't already been scanned in the specified window
    :param vt_results: dict to hold scan results
    :return:
    """

    api_key = get_api_key()  # todo move this outside, where it can be used by all func that need it

    #  for each file in the directory
    print 'checking for existing reports'  # implement via logs?
    print '{} files to check'.format(len(files_to_scan))
    for f in files_to_scan:
        print os.path.split(f)[1]
        temp_results = {'sha256': '', 'last_scan': '', 'permalink': '', 'positives': -1, 'info': ''}

        # is this file w/in the size limit?
        if check_file_within_size_limit(f):

            if api_key:
                scan_results = check_previous_scan(f, prev_scan_window, api_key)

                if isinstance(scan_results, dict):  # got prev scan data back
                    map_vt_results(scan_results, temp_results)

                else:  # no data available
                    queue.append(f)  # add to a 'queue' for scanning
                    # todo add code to handle reason for no data - i.e. stale vs. non-existent results

        else:
            temp_results['info'] = 'File too big to scan: > {}'.format(VT_MAX_FILE_SIZE_MB)

        file_name = os.path.split(f)[1]
        vt_results[file_name] = temp_results


def scan_queued_files(queue_list, result_dict):
    # determine how many uploads per group based on rate
    queue_len = len(queue_list)
    num_groups = queue_len/VT_MAX_REQ_RATE_PER_MIN  # todo need to get division correct
    if num_groups < 1:
        num_groups = 1

    api_key = get_api_key()

    print 'requesting scans for queued files'  # handle via logs?
    print '{} files to be scanned'.format(queue_len)
    for f in queue_list:
        print os.path.split(f)[1]
        params = {'apikey': api_key}  # todo add check to verify good api_key value
        files = {'file': (f, open(f, 'rb'))}

        response = requests.post(VT_EP_FILE_SCAN, files=files, params=params)  # request scan
        # todo handle problem response codes, etc.

        response_dict = response.json()

        # record necessary returned data - .e.g. scan ID and ?? << where to record
        print 'status: ', response.status_code
        print response_dict
        time.sleep(15)

    done = False
    remaining = queue_len
    # while not done:
    #     for f in queue:
    #         pass
    #         # get result
    #         # if status = "done"
    #             # get data
    #             # remaining -= 1
    #         # sleep x sec
    #     if remaining < 1:
    #         done = True


    # for each group
        # submit file scan requests, monitor status and collect results
        #     for each file in the queue
        #         get status
        #         if scan complete:
        #             gather results
        #              remove from queue
        #         else continue to next file in queue
        # for each file in results set:
        #     print result