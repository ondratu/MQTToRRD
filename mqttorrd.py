#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Create round robind database files form MQTT messages."""
from argparse import ArgumentParser
from traceback import format_exc
from configparser import ConfigParser
from re import match
from sys import platform
from os import access, R_OK, W_OK, makedirs, kill, geteuid
from os.path import isdir, dirname, basename, join, exists
from time import sleep
from grp import getgrnam
from pwd import getpwnam
from signal import Signals, SIGTERM

from logging.handlers import SysLogHandler, WatchedFileHandler
import logging

from paho.mqtt.client import Client
from daemon import DaemonContext
from lockfile.pidlockfile import PIDLockFile
from rrdtool import (create as create_rrd, update as update_rrd,
                     ProgrammingError, OperationalError)

__author__ = "Ondřej Tůma"
__version__ = "0.1.0"
__copyright__ = "Copyright 2018"
__license__ = "BSD"
__email__ = "mcbig@zeropage.cz"

LOG_HANDLERS = ("syslog", "file")
LOG_FORMAT = "%(asctime)s %(levelname)s: %(name)s: %(message)s "\
             "{%(funcName)s():%(lineno)d}"

DS = "DS:{topic}:GAUGE:120:U:U"
RRA = "RRA:AVERAGE:0.5:2:30,"\
      "RRA:AVERAGE:0.5:5:288,"\
      "RRA:AVERAGE:0.5:30:336,"\
      "RRA:AVERAGE:0.5:60:1488,"\
      "RRA:AVERAGE:0.5:720:744,"\
      "RRA:AVERAGE:0.5:1440:265"


class Config(ConfigParser):
    """Config object."""
    def __init__(self, args):
        super(Config, self).__init__()
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
        self.log_level = self.get("logging", "level", fallback="WARNING")
        self.log_format = self.get("logging", "format", fallback=LOG_FORMAT)

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
        ds = self.get(topic, "DS", fallback=DS)
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
            if platform == 'windows':
                self.handler = logging.FileHandler(
                    self.cfg.log_file, encoding="utf-8")
            else:
                self.handler = WatchedFileHandler(
                    self.cfg.log_file, encoding="utf-8")
        else:
            self.handler = SysLogHandler(
                self.cfg.log_syslog, SysLogHandler.LOG_DAEMON)

        self.handler.setFormatter(formatter)
        self.logger.addHandler(self.handler)

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
    def on_connect(client, daemon, flags, rc):
        """connect mqtt handler."""
        daemon.logger.info("Connected to server")
        for sub in daemon.cfg.subscriptions:
            daemon.logger.info("Subscribing to topic: %s", sub)
            client.subscribe(sub)

    @staticmethod
    def on_message(client, daemon, msg):
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
            except Exception as exc:
                logging.debug("%s", format_exc())
                self.logger.debug("%s", format_exc())
                self.logger.fatal("%s", exc)
                if not daemon:
                    return 1
            sleep(30)

    def shutdown(self, signum, frame):
        """Signal handler for termination."""
        self.logger.info("Shutting down with signal %s", Signals(signum).name)
        self.client.disconnect()
        exit(1)


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
        "-f", "--foreground", action="store_true",
        help="Run as script on foreground")

    args = parser.parse_args()
    try:
        config = Config(args)
        daemon = Daemon(config, args.foreground)
        if args.foreground:
            return daemon.run(False)

        pid_file = PIDLockFile(config.pid_file)

        if args.command == "stop":
            if pid_file.is_locked():
                daemon.logger.info(
                    "Stoping service with pid %d", pid_file.read_pid())
                kill(pid_file.read_pid(), SIGTERM)
            return 0
        elif args.command == "status":
            if pid_file.is_locked():
                daemon.logger.info(
                    "Service running with pid %d", pid_file.read_pid())
                return 0
            daemon.logger.info("Service not running")
            return 1
        elif args.command == "restart":
            if pid_file.is_locked():
                daemon.logger.info(
                    "Restarting service with pid %d", pid_file.read_pid())
                kill(pid_file.read_pid(), SIGTERM)

        context = DaemonContext(
            working_directory=config.data_dir,
            pidfile=pid_file,
            signal_map={SIGTERM: daemon.shutdown})
        if geteuid() == 0:
            context.uid = config.uid
            context.gid = config.gid
        if config.log_handler == "file":
            context.files_preserve = [daemon.handler.stream]
        with context:
            daemon.logger.info(
                "Starting service with pid %d", pid_file.read_pid())
            daemon.run()
        return 0
    except Exception as exc:
        logging.info("%s", args)
        logging.debug("%s", format_exc())
        logging.fatal("%s", exc)
        parser.error("%s" % exc)
        return 1


if __name__ == "__main__":
    exit(main())
