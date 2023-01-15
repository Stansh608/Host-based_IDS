# Host-based IDS developed for scanning presence of any intrusion in a given directory.


import os
import hashlib
import tkinter as tk


def find_subdirs(directory):

    sub_dirs = []
    paths = os.listdir(directory)
    # listing all the files in the folder
    for path in paths:
        fullpath = directory + '/' + path  # acquiring the absolute path to use

        if os.path.isdir(fullpath):  # the full path

            sub_dirs.append(fullpath)
            # to subfolders
            sub_dirs += find_subdirs(fullpath)  # open subfolders and including them to the list.

    return sub_dirs


def dir_structure(directory, subdir_lst):
    # Returns all files in a folder and subfolders as a dictionary

    dir_dict = {}

    current_dir = os.listdir(directory)  # full list
    dir_dict[directory] = current_dir  # add the directory that i start to scan

    for path in subdir_lst:
        dir_dict[path] = os.listdir(path)  # subfolder is the key and the value is it's content
    return dir_dict


def absolute_and_relative_lst(dir_dict):
    # A Relative and absolute paths for all the files wil be returned.

    absolute_paths = []
    relative_paths = []

    for i in dir_dict:  # i for directories and j for the filename.
        for j in dir_dict[i]:
            if not os.path.isdir(i + '/' + j):  # only files are added to the list
                relative_paths.append(j)
                absolute_paths.append(i + '/' + j)  # the list of all absolute paths

    return absolute_paths, relative_paths


def hash_files_lst(absolute_lst):
    # No hashing directories, only the files

    # Sha1

    hashed_lst = []

    for files in absolute_lst:
        infile = open(f'{files}', 'rb')  # opening the files and hashing them
        infile_read = infile.read()
        infile.close

        infile_hash = hashlib.sha1(infile_read)
        hashed_lst.append(infile_hash.hexdigest())

    return hashed_lst  # a list of all hashed files will be returned


def merge_relative_hash(hash_lst, relative_paths_lst):
    # Two merged as key:value pairs.

    relative_paths = relative_paths_lst
    merged_dict = {}

    for i in range(0, len(hash_lst)):
        merged_dict[relative_paths[i]] = hash_lst[i]

    return merged_dict  # hashed list and relative paths
    #  relative file path becomes the key to the dictionary and the hash sum is the value


def write_first_log(merged_dict):
    # Writing a first log file.

    outfile = open('HIDS_Log_File.txt', 'x')

    outfile.write(f'{merged_dict}')
    outfile.close()


def compare_log(merged_dict):
    # Comparing the old log file with current scanned directories.
    # returns a list of any intrusion: added, changed or deleted file

    infile = open('HIDS_log_File.txt', 'r')
    old_log_file = infile.read()
    infile.close()

    old_log = eval(old_log_file)
    new_log = merged_dict

    changes = []
    new_added = []
    removed = []

    if new_log == old_log:  # then no changes
        return changes, new_added, removed

    else:  # changes occurred, hence we iterate to check for the changed files
        for filename in new_log:
            if filename not in old_log:
                new_added.append(filename)

        for filename in old_log:
            if filename not in new_log:
                removed.append(filename)

        for hashsum in old_log:
            if hashsum in new_log:
                if old_log[hashsum] != new_log[hashsum]:
                    changes.append(hashsum)

    # lists are converted to strings separated by commas,and spaces
    changes_str = ', '.join([str(elem) for elem in changes])
    new_added_str = ', '.join([str(elem) for elem in new_added])
    removed_str = ', '.join([str(elem) for elem in removed])

    return changes_str, new_added_str, removed_str


def main():
    os.system('cls')
    usr_inp_isdir = False

    while not usr_inp_isdir:

        print('Enter the absolute path to a directory to scan')
        user_input = input('Absolute path: ')
        absolute_path = f'{user_input}'

        try:
            sub_dirs = find_subdirs(absolute_path)
            print(" ")
            print("Checking ...")
            print("")
            print("")
            print("Result:")
            print("")
        except FileNotFoundError:
            print('The directory does not exist, please try again!\n')
            return -1
        except NotADirectoryError:
            print('The file path is not a directory, please try again!\n')
            return -2
        except:
            print('Incorrect input, please try again!\n')
            return -3
        else:
            if len(absolute_path) == absolute_path.count('/'):
                print('\nIncorrect input, please try again!\n')
                return -4
            elif len(absolute_path) == absolute_path.count('.'):
                print('\nIncorrect input, please try again!\n')
                return -5
            else:
                usr_inp_isdir = True

    sub_dirs_dict = dir_structure(absolute_path, sub_dirs)
    absolute_lst, relative_lst = absolute_and_relative_lst(sub_dirs_dict)
    hashed_lst = hash_files_lst(absolute_lst)
    merged_dict = merge_relative_hash(hashed_lst, relative_lst)

    try:
        write_first_log(merged_dict)
        print('-----------------------------------------------')
        print('A log file has successfully been created.\n')
        print('To identify whether an Intrusion has occurred,Re-run the code again.')
        print('------------------------------------------------')
    except FileExistsError:
        changes, new_added, removed = compare_log(merged_dict)

        if len(changes) + len(new_added) + len(removed) == 0:
            print('There is no Intrusion detected since the last run. You are Safe😍')
        else:
            print('Analysis of the directory since the last run:\n')
            print('_' * 50)
            print('\tFiles that have changed:\n' + changes)
            print('_' * 50)
            print('\tFiles that have been newly added:\n' + new_added)
            print('_' * 50)
            print('\tFiles that have been removed:\n' + removed)
            print('_' * 50)


main()
