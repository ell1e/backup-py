#!/usr/bin/python3

'''
Copyright (c) 2016-2024  Ellie/@ellie on Github and Codeberg

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
'''

"""
A simple rsnapshot wrapper to help server admins.

Uses a very simple config file to do backups (please note that ssh key
login without password is assumed to be possible for any remote targets):

```
backups:
  my-random-backup:
    source: myuser@my-remote-server.com:/srv/
    target: /home/myuser/mybackup-folder/
    interval: 1d
    snapshots: 7
```

After this, simply schedule this script to run with anacron in roughly
twice the interval you specified to ensure regular backups.

"""

import argparse
import copy
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time

if os.getuid() != 0:
    print("backup.py: not running as root, ABORTING.", file=sys.stderr,
        flush=True)
    sys.exit(1)

parser = argparse.ArgumentParser(description="Simple backup script")
parser.add_argument("-c",
    default=os.path.join(os.path.abspath(
        os.path.dirname(__file__)), "backup-py-config.yml"),
    help="The path for the backup config",
    dest="config")
parser.add_argument("--ignore-last-timestamp",
    help=("Ignore the timestamp of the last snapshot, and create " +
        "a new snapshot even if the old one is considered new enough " +
        "for the given interval. This is useful for manually " +
        "obtaining a snapshot of your current state outside of the " +
        "usual interval triggers"),
    dest="ignore_last_timestamp",
    default=False, action="store_true")
parser.add_argument("--print-config-only",
    help="Print the rsnapshot config that would be used and " +
    "quit, WITHOUT actually doing any backup work",
    dest="print_config_only", default=False, action="store_true")
parser.add_argument("-v", "-V", "--version",
    default=False, action="store_true",
    help="Show program version an exit",
    dest="show_version")
args = parser.parse_args()

# Install YAML and rsnapshot:
if args.show_version:
    print("backup.py V1")
    sys.exit(0)
try:
    import yaml
except ImportError:
    print("[install] yaml missing, installing...")
    subprocess.check_output([sys.executable, "-m", "pip",
        "install", "PyYAML"])
    import PyYAML
def install():
    try:
        subprocess.check_output(["rsnapshot", "--version"])
        return
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    print("[install] rsnapshot missing, installing...")
    have_dnf = True
    try:
        subprocess.check_output(["dnf", "--version"])
    except (subprocess.CalledProcessError, FileNotFoundError):
        have_dnf = False
    if have_dnf:
        print("dnf detected. executing: dnf install -y rsnapshot")
        subprocess.check_output(["dnf", "install", "-y", "rsnapshot"])
    else:
        print("executing: apt-get install -y rsnapshot")
        subprocess.check_output([
            "apt-get", "install", "-y", "rsnapshot"])
install()

# Read config:
if not os.path.exists(args.config):
    print("backup.py: error: no such config file found: " +
        args.config, file=sys.stderr)
    sys.exit(1)
config_data = {}
with open(args.config, "r") as f:
    config_data = yaml.safe_load(f.read())

# Process all backup entries in config:
errors_occured = False
for backup_name in config_data["backups"]:
    backup = config_data["backups"][backup_name]
    target_dir = backup["target"]
    if target_dir.find("@") >= 0:
        print("backup.py: error: backup target cannot be a remote " +
            "location: " + target_dir, file=sys.stderr, flush=True)
        errors_occured = True
        continue
    if not os.path.exists(target_dir):
        try:
            os.mkdir(target_dir)
        except Exception as e:
            print("backup.py: error: failed to create backup target " +
                "directory: " + str(target_dir), file=sys.stderr, flush=True)
            errors_occured = True
            continue
    snapshot_amount = 7
    if "snapshots" in backup:
        snapshot_amount = int(backup["snapshots"])
    snapshot_interval = "1d"
    if "interval" in backup:
        snapshot_interval = backup["interval"]
    exclude_list = []
    if "exclude" in backup:
        exclude_list = backup["exclude"]
        if type(exclude_list) != str and type(exclude_list) != list:
            print("backup.py: error: 'exclude' parameter must be " +
                "list or single entry", file=sys.stderr, flush=True)

    # Split up all interval parts:
    interval_parts = []
    current_interval_part = [""]
    i = 0
    split_on_next_digit = False
    while i < len(snapshot_interval):
        c = snapshot_interval[i]
        if ord(c) >= ord("0") and ord(c) <= ord("9"):
            if split_on_next_digit:
                interval_parts.append(current_interval_part)
                current_interval_part = [""]
                split_on_next_digit = False
                continue
        else:
            current_interval_part.append("")
            split_on_next_digit = True
        current_interval_part[-1] += c
        i += 1
    if len(current_interval_part) > 0:
        interval_parts.append(current_interval_part)
    if len(interval_parts) == 0:
        print("backup.py: error: invalid interval specification: " +
            snapshot_interval, file=sys.stderr, flush=True)
        errors_occured = True
        continue
    interval_length = 0
    invalid_part = False
    for part in interval_parts:
        if len(part) != 2:
            invalid_part = True
            break
        if part[1] == "s":
            interval_length += int(part[0])
        elif part[1] == "m":
            interval_length += int(part[0]) * 60
        elif part[1] == "d":
            interval_length += int(part[0]) * 60 * 60 * 24
        elif part[1] == "w":
            interval_length += int(part[0]) * 60 * 60 * 24 * 7
        elif part[1] == "M":
            interval_length += int(part[0]) * 60 * 60 * 24 * 30
        elif part[1] == "y" or part[1] == "Y":
            interval_length += int(int(part[0]) * 60 * 60 * 24 * 365.25)
        else:
            invalid_part = True
            break
    if invalid_part:
        print("backup.py: error: invalid interval specification: " +
            snapshot_interval, file=sys.stderr, flush=True)
        errors_occured = True
        continue

    # Write rsnapshot config:
    config_str = textwrap.dedent("""\
    #################################################
    # rsnapshot.conf - rsnapshot configuration file #
    #################################################
    #                                               #
    # PLEASE BE AWARE OF THE FOLLOWING RULE:        #
    #                                               #
    # This file requires tabs between elements      #
    #                                               #
    #################################################

    #######################
    # CONFIG FILE VERSION #
    #######################

    config_version\t1.2

    ###########################
    # SNAPSHOT ROOT DIRECTORY #
    ###########################

    # All snapshots will be stored under this root directory.
    #
    snapshot_root\t${BACKUP_TARGET}

    # If no_create_root is enabled, rsnapshot will not automatically create the
    # snapshot_root directory. This is particularly useful if you are backing
    # up to removable media, such as a FireWire or USB drive.
    #
    #no_create_root	1

    #################################
    # EXTERNAL PROGRAM DEPENDENCIES #
    #################################

    # LINUX USERS:   Be sure to uncomment "cmd_cp".
    #                This gives you extra features.
    # EVERYONE ELSE: Leave "cmd_cp" commented out for compatibility.
    #
    # See the README file or the man page for more details.
    #
    #cmd_cp	    /usr/bin/cp

    # uncomment this to use the rm program instead of the built-in perl routine.
    #
    #cmd_rm\t/usr/bin/rm

    # rsync must be enabled for anything to work. This is the only command that
    # must be enabled.
    #
    cmd_rsync\t/usr/bin/rsync

    # Uncomment this to enable remote ssh backups over rsync.
    #
    cmd_ssh\t/usr/bin/ssh

    # Comment this out to disable syslog support.
    #
    #cmd_logger\t/usr/bin/logger

    # Uncomment this to specify the path to "du" for disk usage checks.
    # If you have an older version of "du", you may also want to check the
    # "du_args" parameter below.
    #
    cmd_du\t/usr/bin/du

    # Uncomment this to specify the path to rsnapshot-diff.
    #
    #cmd_rsnapshot_diff /usr/local/bin/rsnapshot-diff

    # Specify the path to a script (and any optional arguments) to run right
    # before rsnapshot syncs files
    #
    #cmd_preexec	/path/to/preexec/script

    # Specify the path to a script (and any optional arguments) to run right
    # after rsnapshot syncs files
    #
    #cmd_postexec	/path/to/postexec/script

    # Paths to lvcreate, lvremove, mount and umount commands, for use with
    # Linux LVMs.
    #
    #linux_lvm_cmd_lvcreate	/usr/sbin/lvcreate
    #linux_lvm_cmd_lvremove	/usr/sbin/lvremove
    #linux_lvm_cmd_mount	/usr/bin/mount
    #linux_lvm_cmd_umount	/usr/bin/umount

    #########################################
    #     BACKUP LEVELS / INTERVALS         #
    # Must be unique and in ascending order #
    # e.g. alpha, beta, gamma, etc.         #
    #########################################

    retain\tsnapshot\t${SNAPSHOT_COUNT}
    #retain	delta	3

    ############################################
    #              GLOBAL OPTIONS              #
    # All are optional, with sensible defaults #
    ############################################

    # Verbose level, 1 through 5.
    # 1     Quiet           Print fatal errors only
    # 2     Default         Print errors and warnings only
    # 3     Verbose         Show equivalent shell commands being executed
    # 4     Extra Verbose   Show extra verbose information
    # 5     Debug mode      Everything
    #
    verbose\t3

    # Same as "verbose" above, but controls the amount of data sent to the
    # logfile, if one is being used. The default is 3.
    #
    loglevel\t3

    # If you enable this, data will be written to the file you specify. The
    # amount of data written is controlled by the "loglevel" parameter.
    #
    #logfile    /var/log/rsnapshot

    # If enabled, rsnapshot will write a lockfile to prevent two instances
    # from running simultaneously (and messing up the snapshot_root).
    # If you enable this, make sure the lockfile directory is not world
    # writable. Otherwise anyone can prevent the program from running.
    #
    lockfile\t/var/run/rsnapshot.pid

    # By default, rsnapshot check lockfile, check if PID is running
    # and if not, consider lockfile as stale, then start
    # Enabling this stop rsnapshot if PID in lockfile is not running
    #
    #stop_on_stale_lockfile	    0

    # Default rsync args. All rsync commands have at least these options set.
    #
    #rsync_short_args   -a
    #rsync_long_args    --delete --numeric-ids --relative --delete-excluded

    # ssh has no args passed by default, but you can specify some here.
    #
    #ssh_args   -p 22

    # Default arguments for the "du" program (for disk space reporting).
    # The GNU version of "du" is preferred. See the man page for more details.
    # If your version of "du" doesn't support the -h flag, try -k flag instead.
    #
    #du_args    -csh

    # If this is enabled, rsync won't span filesystem partitions within a
    # backup point. This essentially passes the -x option to rsync.
    # The default is 0 (off).
    #
    #one_fs	    0

    # The include and exclude parameters, if enabled, simply get passed directly
    # to rsync. If you have multiple include/exclude patterns, put each one on a
    # separate line. Please look up the --include and --exclude options in the
    # rsync man page for more details on how to specify file name patterns. 
    # 
    #include    ???
    #include    ???
    #exclude    ???
    #exclude    ???
    ${EXCLUDE_ENTRIES}

    # The include_file and exclude_file parameters, if enabled, simply get
    # passed directly to rsync. Please look up the --include-from and
    # --exclude-from options in the rsync man page for more details.
    #
    #include_file	/path/to/include/file
    #exclude_file	/path/to/exclude/file

    # If your version of rsync supports --link-dest, consider enabling this.
    # This is the best way to support special files (FIFOs, etc) cross-platform.
    # The default is 0 (off).
    #
    link_dest\t1

    # When sync_first is enabled, it changes the default behaviour of rsnapshot.
    # Normally, when rsnapshot is called with its lowest interval
    # (i.e.: "rsnapshot alpha"), it will sync files AND rotate the lowest
    # intervals. With sync_first enabled, "rsnapshot sync" handles the file sync,
    # and all interval calls simply rotate files. See the man page for more
    # details. The default is 0 (off).
    #
    sync_first\t1

    # If enabled, rsnapshot will move the oldest directory for each interval
    # to [interval_name].delete, then it will remove the lockfile and delete
    # that directory just before it exits. The default is 0 (off).
    #
    use_lazy_deletes\t1

    # Number of rsync re-tries. If you experience any network problems or
    # network card issues that tend to cause ssh to fail with errors like
    # "Corrupted MAC on input", for example, set this to a non-zero value
    # to have the rsync operation re-tried.
    #
    rsync_numtries\t3

    # LVM parameters. Used to backup with creating lvm snapshot before backup
    # and removing it after. This should ensure consistency of data in some special
    # cases
    #
    # LVM snapshot(s) size (lvcreate --size option).
    #
    #linux_lvm_snapshotsize	100M

    # Name to be used when creating the LVM logical volume snapshot(s).
    #
    #linux_lvm_snapshotname	rsnapshot

    # Path to the LVM Volume Groups.
    #
    #linux_lvm_vgpath   /dev

    # Mount point to use to temporarily mount the snapshot(s).
    #
    #linux_lvm_mountpath	/path/to/mount/lvm/snapshot/during/backup

    ###############################
    ### BACKUP POINTS / SCRIPTS ###
    ###############################

    # LOCALHOST
    backup\t${BACKUP_SOURCE}\t${BACKUP_NAME}/
    #backup	/var/log/rsnapshot	localhost/
    #backup	/etc/passwd localhost/
    #backup	/home/foo/My Documents/	    localhost/
    #backup	/foo/bar/   localhost/	one_fs=1, rsync_short_args=-urltvpog
    #backup_script	/usr/local/bin/backup_pgsql.sh	localhost/postgres/
    # You must set linux_lvm_* parameters below before using lvm snapshots
    #backup	lvm://vg0/xen-home/ lvm-vg0/xen-home/

    # EXAMPLE.COM
    #backup_exec	/bin/date "+ backup of example.com started at %c"
    #backup	root@example.com:/home/	example.com/	+rsync_long_args=--bwlimit=16,exclude=core
    #backup	root@example.com:/etc/	example.com/	exclude=mtab,exclude=core
    #backup_exec	ssh root@example.com "mysqldump -A > /var/db/dump/mysql.sql"
    #backup	root@example.com:/var/db/dump/	example.com/
    #backup_exec	/bin/date "+ backup of example.com ended at %c"

    # CVS.SOURCEFORGE.NET
    #backup_script	/usr/local/bin/backup_rsnapshot_cvsroot.sh  rsnapshot.cvs.sourceforge.net/

    # RSYNC.SAMBA.ORG
    #backup	rsync://rsync.samba.org/rsyncftp/   rsync.samba.org/rsyncftp/

    """)
    print("backup.py: info: " +
          "backup source: " + str(backup["source"]))
    print("backup.py: info: " +
          "backup target: " + os.path.abspath(
          target_dir))
    config_str = config_str.replace("${BACKUP_TARGET}", os.path.abspath(
        target_dir))
    config_str = config_str.replace("${BACKUP_SOURCE}", backup["source"])
    config_str = config_str.replace("${EXCLUDE_ENTRIES}",
        "\n".join(["exclude\t" + e for e in exclude_list]))
    backup_target_name = \
        backup["source"].replace("@", "_").replace(".", "_").replace(
        ":", "_").replace("/", "_").replace("__", "_")
    if backup_target_name.startswith("_"):
        backup_target_name = backup_target_name[1:]
    if backup_target_name.endswith("_"):
        backup_target_name = backup_target_name[:-1]
    config_str = config_str.replace("${BACKUP_NAME}",
        backup_target_name)    
    config_str = config_str.replace("${SNAPSHOT_COUNT}",
        str(snapshot_amount))
    snapshot_info_file_path = os.path.join(target_dir,
        ".backup_py_snapshot_info.yml")

    if args.print_config_only:
        print(config_str)
        continue

    def update_symlink_folders():
        """ Helper function to update all the symlinks to the snapshot
            folders with proper visible dates in the name.
        """
        # Get currently written snapshot_info:
        snapshot_info = {}
        with open(snapshot_info_file_path, "r") as f:
            try:
                snapshot_info = yaml.safe_load(f.read())
            except yaml.YAMLError:
                return
        if not "snapshot-folder-dates" in snapshot_info:
            return

        # Remove old links:
        for f in os.listdir(target_dir):
            fpath = os.path.join(target_dir, f)
            if not os.path.isdir(fpath):
                continue
            if os.path.islink(fpath) and f.startswith(
                    "snapshot-at-"):
                os.remove(fpath)

        # Get snapshot target folders in order:
        snapshot_folders = sorted([
            f for f in os.listdir(target_dir) \
            if os.path.isdir(os.path.join(target_dir, f)) and \
            f.startswith("snapshot.")])
        print("backup.py: debug: symlink folder listing: " +
              str(snapshot_folders))

        # Re-create symlinks:
        snapshot_dates = copy.copy(
            snapshot_info["snapshot-folder-dates"])
        snapshot_dates.reverse()
        i = -1
        for snapshot_date in snapshot_dates:
            i += 1
            if i < len(snapshot_folders):
                full_path = os.path.join(os.path.abspath(target_dir),
                        snapshot_folders[i])
                dt = datetime.datetime.fromtimestamp(snapshot_date)
                link_name = os.path.join(target_dir,
                    "snapshot-at-" + dt.strftime("%Y-%m-%d-%H-%M-%S-UTC+0"))
                if not os.path.exists(link_name):
                    try:
                        os.symlink(full_path, link_name)
                        print("backup.py: debug: adding symlink " +
                              str((full_path, link_name)))
                    except FileExistsError:
                        # Symlink is there, but points at something
                        # that doesn't exist. -> Recreate
                        os.remove(link_name)
                        os.symlink(full_path, link_name)
                        print("backup.py: debug: recreating symlink " +
                              str((full_path, link_name)))
            else:
                print("backup.py: warning: bogus symlink folder: " +
                      str(snapshot_folders[i]))

    # Read snapshot_info which has the dates mapped to each snapshot, and
    # create it with the initial default data if not present:
    if not os.path.exists(snapshot_info_file_path):
        with open(snapshot_info_file_path, "w") as f:
            f.write(yaml.safe_dump({
                "last-snapshot-time" : 0,
                "snapshot-folder-dates" : [],
            }))
    snapshot_info = {}
    with open(snapshot_info_file_path, "r") as f:
        try:
            snapshot_info = yaml.safe_load(f.read())
        except yaml.YAMLError:
            snapshot_info = {
                "last-snapshot-time" : 0,
                "snapshot-folder-dates" : [],
            }
    if not "snapshot-folder-dates" in snapshot_info:
        snapshot_info["snapshot-folder-dates"] = []

    transaction_file_path = os.path.join(target_dir, "_backup_py_transaction")
    def transaction_rollback(explicit_rollback=False):
        if os.path.exists(transaction_file_path):
            if not explicit_rollback:
                print("backup.py: warning: previous unfinished transaction " +
                    "found, rolling back...", file=sys.stderr, flush=True)
            with open(transaction_file_path, "r") as f:
                contents_str = f.read()
            try:
                contents = yaml.safe_load(contents_str)
            except yaml.YAMLError as e:
                print("backup.py: warning: transaction rollback: " +
                    "invalid transaction file " +
                    "contents which cannot be parsed, got YAML error: " +
                    str(e), file=sys.stderr, flush=True)
                print("backup.py: warning: transaction rollback: " +
                    " deleting transaction file " +
                    "and ignoring old transaction",
                    file=sys.stderr, flush=True)
                os.remove(transaction_file_path)
                return
            to_be_deleted_folders = \
                [f for f in os.listdir(target_dir) \
                    if f.startswith("_delete") and os.path.isdir(
                    os.path.join(target_dir, f))]

            # Detect if an unfinished rotation has occured:
            definite_rotation = False
            if len(to_be_deleted_folders) > \
                    len(contents["rotation_detection_ignore_folders"]):
                definite_rotation = True

            # If expected rotation but it appears finished and/or unrotated,
            # there is nothing to do:
            if contents["predicted_rotation_requirement"] and\
                    not definite_rotation:
                print("backup.py: info: transaction rollback: " +
                    "a predicted rotation did not occur or was finished, " +
                    "so a clean snapshot state is assumed", flush=True)
            else:
                full_path = os.path.join(target_dir,
                    contents["predicted_new_snapshot"]) 
                if os.path.exists(full_path):
                    print("backup.py: info: transaction rollback: " +
                        "deleting unfinished snapshot '" +
                        contents["predicted_new_snapshot"] + "'...")
                    print("backup.py: transaction rollback: " +
                        "DEL: " + full_path)
                    shutil.rmtree(full_path)
                else:
                    print("backup.py: info: transaction rollback: " +
                        "expected unfinished snapshot '" +
                        contents["predicted_new_snapshot"] +
                        "' not present, so nothing to clean up")

            # Remove all _delete folders that weren't taken care of:
            for f in to_be_deleted_folders:
                full_path = os.path.join(target_dir, f)
                print("backup.py: info: transaction rollback: " +
                    "removing stale '" + str(f) + "' folder...")
                print("backup.py: transaction rollback: " +
                    "DEL: " + full_path)
                shutil.rmtree(full_path)

            # Rollback snapshot info:
            with open(snapshot_info_file_path, "w") as f:
                f.write(contents["old_snapshot_info_contents"])

            # Remove transaction info:
            os.remove(transaction_file_path)
            print("backup.py: info: transaction rollback complete",
                flush=True)
        elif explicit_rollback:
            print("backup.py: info: transaction rollback: " +
                "no unfinished transaction file present, nothing to do",
                flush=True)

    # Make sure we are in a clean state:
    transaction_rollback()
    update_symlink_folders()

    # Check if there is anything we need to do at all:
    if snapshot_info["last-snapshot-time"] + interval_length >= \
            time.mktime(time.gmtime(time.time())):
        if not args.ignore_last_timestamp:
            print("backup.py: info: backup SKIP: last snapshot new enough: " +
                backup_target_name + " (less than " + snapshot_interval +
                " old, timestamp of last backup is: " +
                str(time.strftime(
                    "%Y-%m-%d %H:%M:%S UTC+0", time.gmtime(
                    snapshot_info["last-snapshot-time"])))
                + ")"
                , flush=True)
            continue
        else:
            print("backup.py: warning: last snapshot of backup " +
                str(backup_target_name) + " would be new enough " +
                "for the specified interval, " +
                "but creating new snapshot anyway due to " +
                "--ignore-previous-timestamp", flush=True)

    print("backup.py: info: starting backup: " + backup_target_name)
    (fd, tmp_cfg) = tempfile.mkstemp(prefix="backup-py-cfg-")
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        with open(tmp_cfg, "w") as f:
            f.write(config_str)
        print("backup.py: debug: config written to: " + tmp_cfg)
        print("backup.py: info: transferring...")
        exit_code = 0
        output = None
        try:
            output = subprocess.check_output(["rsnapshot", "-c", 
                tmp_cfg, "sync"], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            output = e.output
            exit_code = e.returncode
        try:
            output = output.decode("utf-8", "replace")
        except AttributeError:
            pass
        if exit_code != 0:
            if exit_code != 2:
                # Synchronization failed, print error and skip:
                errors_occured = True
                print("backup.py: error: rsnapshot sync returned " +
                    "non-zero exit code: " + str(exit_code),
                    file=sys.stderr, flush=True)
                print("backup.py: error: rsnapshot error output:\n" +
                    output, file=sys.stderr, flush=True)
                print("backup.py: error: backup FAILED: " +
                    backup_target_name,
                    file=sys.stderr, flush=True)
                continue
            else:
                print("backup.py: warning: rsnapshot sync " +
                    "returned non-zero warning code: " + str(exit_code))
                print("backup.py: warning: rsnapshot warning output:\n" +
                    output, file=sys.stderr, flush=True)
        snapshot_info["last-snapshot-time"] = \
            time.mktime(time.gmtime(time.time()))
        print("backup.py: info: creating snapshot folder...")

        # Write transaction info so we can undo this on failure and/or
        # unexpected interruption:
        existing = os.listdir(target_dir)
        highest_seen_entry = -1
        for entry in existing:
            if entry.startswith("snapshot."):
                remains = entry[len("snapshot."):]
                try:
                    remains_int = int(remains)
                except (TypeError, ValueError):
                    continue
                highest_seen_entry = max(highest_seen_entry, remains_int)
        predicted_new_snapshot = "snapshot." +\
            str(highest_seen_entry + 1)
        predicted_rotation_requirement = False
        rotation_detection_ignore_folders = []
        if highest_seen_entry + 1 >= snapshot_amount:
            predicted_new_snapshot = "snapshot." + str(
                highest_seen_entry)
            predicted_rotation_requirement = True
            rotation_detection_ignore_folders = [f for f in existing\
                if f.startswith("_delete") and os.path.isdir(
                os.path.join(target_dir, f))]
        transaction_info = {
            "predicted_new_snapshot" :
                predicted_new_snapshot,
            "predicted_rotation_requirement" :
                predicted_rotation_requirement,
            "rotation_detection_ignore_folders" :
                rotation_detection_ignore_folders,
            "old_snapshot_info_contents" :
                yaml.safe_dump(snapshot_info),
        }
        with open(transaction_file_path, "w") as f:
            f.write(yaml.safe_dump(transaction_info))
        print("backup.py: debug: transaction info: " +
              str(json.dumps(transaction_info)))

        # Turn the .sync folder into an actual snapshot:
        try:
            output = subprocess.check_output(["rsnapshot",
                "-v", "-c", tmp_cfg, "snapshot"],
                stderr=subprocess.STDOUT)
            exit_code = 0
        except subprocess.CalledProcessError as e:
            output = e.output
            exit_code = 1

        # Convert output to utf-8/unicode if required:
        try:
            output = output.decode("utf-8")
        except AttributeError:
            pass
        output = "backup.py: >> " + output.replace(
            "\n", "\nbackup.py: >> ")

        # Deal with final exit code and rollback on failure:
        if exit_code != 0:
            print("backup.py: error: rsnapshot snapshot creation " +
                "returned non-zero exit code", file=sys.stderr,
                flush=True)
            print("backup.py: error: error details are: ")
            print(str(output))
            print("backup.py: warning: rolling back transaction " +
                "after error...")
            transaction_rollback(explicit_rollback=True)
            print("backup.py: error: backup FAILED: " +
                backup_target_name,
                file=sys.stderr, flush=True)
        else:
            # Update snapshots date info:
            snapshot_info["snapshot-folder-dates"].append(
                int(time.mktime(time.gmtime(time.time()))))
            snapshot_info["snapshot-folder-dates"] = \
                snapshot_info["snapshot-folder-dates"][-snapshot_amount:]
            with open(snapshot_info_file_path, "w") as f:
                f.write(yaml.safe_dump(snapshot_info))
            update_symlink_folders()

            # Remove rollback info:
            os.remove(transaction_file_path)
            print("backup.py: debug: rsnapshot snapshot creation " +
                "returned success", file=sys.stderr,
                flush=True)
            print("backup.py: debug: output details are: ")
            print(str(output))
            print("backup.py: backup COMPLETED: " +
                backup_target_name, flush=True)
    finally:
        os.remove(tmp_cfg)
if not errors_occured and not args.print_config_only:
    print("backup.py: info: completed", flush=True)
    sys.exit(0)
elif not args.print_config_only:
    print("backup.py: error: completed, but errors ocurred",
        file=sys.stderr, flush=True)
    sys.exit(1)

