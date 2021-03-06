#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Create round robind database files form MQTT messages."""
from argparse import ArgumentParser
from traceback import format_exc
from configparser import ConfigParser
from re import match
from os import access, R_OK, W_OK, makedirs, kill, geteuid
from os.path import isdir, dirname, basename, join, exists
from time import sleep
from grp import getgrnam
from pwd import getpwnam
from signal import Signals, SIGTERM

from logging.handlers import SysLogHandler, WatchedFileHandler
import logging
import sys

from paho.mqtt.client import Client
from daemon import DaemonContext
from lockfile.pidlockfile import PIDLockFile
from rrdtool import (create as create_rrd, update as update_rrd,
                     ProgrammingError, OperationalError)

__author__ = "Ondřej Tůma"
__version__ = "0.1.1"
__copyright__ = "Copyright 2018"
__license__ = "BSD"
__email__ = "mcbig@zeropage.cz"

LOG_HANDLERS = ("syslog", "file")
LOG_FORMAT = "%(asctime)s %(levelname)s: %(name)s: %(message)s "\
             "{%(funcName)s():%(lineno)d}"
SYSLOG_FORMAT = "%(name)s[%(levelname)s]: %(message)s "\
             "{%(funcName)s():%(lineno)d}"


DS = "DS:{topic}:GAUGE:120:U:U"
RRA = "RRA:AVERAGE:0.5:1:60,"\
      "RRA:AVERAGE:0.5:5:288,"\
      "RRA:AVERAGE:0.5:15:672,"\
      "RRA:AVERAGE:0.5:60:744,"\
      "RRA:AVERAGE:0.5:720:732,"\
      "RRA:AVERAGE:0.5:14400:732"

logger = logging.getLogger('MQTToRRD')

# pylint: disable=too-many-branches
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-statements


class Config(ConfigParser):
    """Config object."""
    # pylint: disable=too-many-ancestors
    # pylint: disable=too-many-instance-attributes
    def __init__(self, args):
        super().__init__()
        self.optionxform = str  # case insensitive
        if args.config:
            self.read(args.config)

        # [daemon]
        self.data_dir = self.get(
            "daemon", "data_dir", fallback="/var/lib/mqttorrd")
        self.pid_file = self.get(
            "daemon", "pid_file", fallback="/var/run/mqttorrd.pid")
        user = self.get("daemon", "user", fallback="nobody")
        group = self.get("daemon", "group", fallback="nogroup")
        self.uid = getpwnam(user).pw_uid
        self.gid = getgrnam(group).gr_gid

        # [logging]
        self.log_handler = self.get("logging", "handler", fallback="syslog")
        self.log_file = self.get(
            "logging", "file", fallback="/var/log/mqttorrd.log")
        self.log_syslog = self.get("logging", "syslog", fallback="/dev/log")
        if args.debug:
            self.log_level = "DEBUG"
        elif args.info:
            self.log_level = "INFO"
        else:
            self.log_level = self.get("logging", "level", fallback="WARNING")

        syslog = self.log_handler == "syslog"
        self.log_format = self.get(
            "logging", "format",
            fallback=SYSLOG_FORMAT if syslog else LOG_FORMAT)

        # [mqtt]
        self.client_id = self.get("mqtt", "client_id", fallback=None)
        self.hostname = self.get("mqtt", "hostname", fallback="localhost")
        self.port = int(self.get("mqtt", "port", fallback="1883"))
        self.keepalive = int(self.get("mqtt", "keepalive", fallback="60"))
        self.tls = self.getboolean("mqtt", "tls", fallback=False)
        self.ca_certs = self.get("mqtt", "ca_certs", fallback=None)
        self.certfile = self.get("mqtt", "certfile", fallback=None)
        self.keyfile = self.get("mqtt", "keyfile", fallback=None)

        self.username = self.get("mqtt", "username", fallback=None)
        self.password = self.get("mqtt", "password", fallback=None)

        subscriptions = self.get("mqtt", "subscriptions", fallback="/#")
        self.subscriptions = list(sub.strip()
                                  for sub in subscriptions.split(','))

    def get_topic(self, topic):
        """Get topic configuration"""
        step = int(self.get(topic, "step", fallback="60"))
        rra = list(rra.strip()
                   for rra in self.get(topic, "RRA", fallback=RRA).split(','))
        ds = self.get(topic, "DS", fallback=DS)  # pylint: disable=invalid-name
        return (step, ds, rra)

    def find_topic(self, topic):
        """Find configuration, which could be match to topic.

        Find first definition in configuration and use it. So write more global
        definition on end of config.
        """
        for section in self.sections():
            regexp = section.replace('$', r'\$').replace('+', r'\w+')
            regexp = regexp.replace('#', r'[\w/]+')
            if match(regexp, topic):
                return self.get_topic(section)
        return self.get_topic(topic)   # default values


class Daemon():
    """MQTTToRDD Daemon."""
    def __init__(self, config, foreground=False):
        self.cfg = config
        self.logger = logging.getLogger('MQTToRRD')
        self.logger.setLevel(self.cfg.log_level)
        formatter = logging.Formatter(self.cfg.log_format)
        self.client = None

        if foreground:
            self.handler = logging.StreamHandler()
            self.cfg.log_handler = "stderr"
        elif self.cfg.log_handler == "file":
            if sys.platform == 'windows':
                self.handler = logging.FileHandler(
                    self.cfg.log_file, encoding="utf-8")
            else:
                self.handler = WatchedFileHandler(
                    self.cfg.log_file, encoding="utf-8")
        else:
            self.handler = SysLogHandler(
                self.cfg.log_syslog, SysLogHandler.LOG_DAEMON)

        for hdlr in logger.root.handlers:  # reset root logger handlers
            logger.root.removeHandler(hdlr)

        logger.root.addHandler(self.handler)
        self.handler.setFormatter(formatter)

    def check(self):
        """Check configuration."""
        for section in self.cfg.sections():
            # this check configuration values
            if section.startswith("/"):
                self.cfg.get_topic(section)     # read from config
            elif section.startswith("$SYS/"):
                self.cfg.get_topic(section)     # read from config
        self.logger.info("Configuration looks OK")

        if not isdir(self.cfg.data_dir):
            raise RuntimeError("Data dir `%s' does not exist." %
                               self.cfg.data_dir)
        if not access(self.cfg.data_dir, R_OK | W_OK):
            raise RuntimeError("Data dir `%s' is not readable and writable" %
                               self.cfg.data_dir)
        if self.cfg.log_handler == "file" and \
                access(self.cfg.log_file, R_OK | W_OK) and \
                isdir(dirname(self.cfg.log_file)) and \
                access(dirname(self.cfg.log_file), R_OK | W_OK):
            raise RuntimeError("Could not write to log")

    @staticmethod
    def on_connect(client, daemon, flags, res):
        """connect mqtt handler."""
        # pylint: disable=unused-argument
        daemon.logger.info("Connected to server")
        for sub in daemon.cfg.subscriptions:
            daemon.logger.info("Subscribing to topic: %s", sub)
            client.subscribe(sub)

    @staticmethod
    def on_message(client, daemon, msg):
        # pylint: disable=unused-argument
        """message mqtt handler."""
        daemon.logger.info(
            "Message received on topic %s with QoS %s and payload `%s'",
            msg.topic, msg.qos, msg.payload)
        try:
            value = float(msg.payload)
        except ValueError:
            daemon.logger.warning(
                "Unable to get float from topic %s and payload %s",
                msg.topic, msg.payload)
            return
        topic = msg.topic.replace('.', '_')
        topic = topic[1:] if topic.startswith('/') else topic
        rrd_path = join(daemon.cfg.data_dir,
                        dirname(topic), "%s.rrd" % basename(topic))
        daemon.rrd(rrd_path, msg.topic, value)

    def rrd(self, rrd_path, topic, value):
        """Create or update RRD file."""
        dir_path = dirname(rrd_path)
        if not isdir(dir_path):
            self.logger.debug("Creating topic directory %s", dir_path)
            makedirs(dir_path)
        if not exists(rrd_path):
            self.logger.debug("Creatting RRD file %s", rrd_path)
            # pylint: disable=invalid-name
            step, ds, rra = self.cfg.find_topic(topic)
            ds = ds.format(topic=basename(topic))
            try:
                create_rrd(rrd_path, "--step", str(step), "--start", "0", ds,
                           *rra)
            except (ProgrammingError, OperationalError) as exc:
                self.logger.error("Could not create RRD for topic %s: %s",
                                  topic, str(exc))
        self.logger.info("Updating %s with value %f", topic, value)
        try:
            update_rrd(rrd_path, "N:%f" % value)
        except (ProgrammingError, OperationalError) as exc:
            self.logger.error(
                "Could not log value %f to RRD for topic %s: %s",
                value, topic, str(exc))

    def run(self, daemon=True):
        """Run daemon."""
        self.check()
        while True:
            try:
                self.client = Client(client_id=self.cfg.client_id,
                                     userdata=self)
                self.client.on_connect = Daemon.on_connect
                self.client.on_message = Daemon.on_message
                if self.cfg.tls:
                    self.client.tls_set(ca_certs=self.cfg.ca_certs,
                                        certfile=self.cfg.certfile,
                                        keyfile=self.cfg.keyfile)
                self.logger.debug(
                    "Attempting to connect to server %s:%s",
                    self.cfg.hostname, self.cfg.port)
                self.client.connect(
                    self.cfg.hostname, self.cfg.port, self.cfg.keepalive)
                self.logger.info(
                    "Connected to %s:%s", self.cfg.hostname, self.cfg.port)
                self.client.loop_forever()
                return 0
            except Exception as exc:  # pylint: disable=broad-except
                logging.debug("%s", format_exc())
                self.logger.debug("%s", format_exc())
                self.logger.fatal("%s", exc)
                if not daemon:
                    return 1
            sleep(30)

    def shutdown(self, signum, frame):
        """Signal handler for termination."""
        # pylint: disable=unused-argument
        self.logger.info("Shutting down with signal %s", Signals(signum).name)
        self.client.disconnect()
        sys.exit(1)


def check_process(pid):
    """Check if process with pid is alive."""
    try:
        kill(pid, 0)
        return True
    except OSError:
        return False


def main():
    """Standard main function."""
    parser = ArgumentParser(
        description=__doc__,
        usage="$(prog)s [options] command")
    parser.add_argument(
        "command", nargs='?', default="start", type=str,
        help="Daemon action (start|stop|restart|status)")
    parser.add_argument(
        "-c", "--config", default="/etc/mqttorrd.ini", type=str,
        help="Path to config file.", metavar="<file>")
    parser.add_argument(
        "-i", "--info", action="store_true",
        help="more verbose logging level INFO is set")
    parser.add_argument(
        "-d", "--debug", action="store_true",
        help="DEBUG logging level is set")
    parser.add_argument(
        "-f", "--foreground", action="store_true",
        help="Run as script on foreground")

    args = parser.parse_args()
    try:
        config = Config(args)
        daemon = Daemon(config, args.foreground)
        if args.foreground:
            print("Starting process ...")
            return daemon.run(False)

        pid_file = PIDLockFile(config.pid_file)
        pid = pid_file.read_pid() if pid_file.is_locked() else None

        if args.command == "stop":
            if pid and check_process(pid):
                print("Stopping service with pid", pid)
                kill(pid, SIGTERM)
            else:
                print("Service not running")
            return 0

        if args.command == "status":
            if pid and check_process(pid):
                print("Service running with pid", pid)
                return 0
            print("Service not running")
            return 1

        if args.command == "restart":
            if pid and check_process(pid):
                print("Restarting service with pid", pid)
                kill(pid, SIGTERM)

        if pid:
            if not check_process(pid):
                pid_file.break_lock()
            else:
                print("Service is already running")
                return 1

        context = DaemonContext(
            working_directory=config.data_dir,
            pidfile=pid_file,
            signal_map={SIGTERM: daemon.shutdown})
        if geteuid() == 0:
            context.uid = config.uid
            context.gid = config.gid
        if config.log_handler == "file":
            context.files_preserve = [daemon.handler.stream]
        else:  # SysLogHandler
            context.files_preserve = [daemon.handler.socket]

        print("Starting service ...")
        with context:
            daemon.logger.info(
                "Starting service with pid %d", pid_file.read_pid())
            retval = daemon.run()
            daemon.logger.info("Shutdown")
            return retval
    except Exception as exc:  # pylint: disable=broad-except
        logger.info("%s", args)
        logger.debug("%s", format_exc())
        logger.fatal("%s", exc)
        parser.error("%s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
