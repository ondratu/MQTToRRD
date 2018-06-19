MQTToRRD
========

Like as `MQTT2RRD <https://github.com/irvined1982/MQTT2RRD>`_ and it's forks,
MQTToRRD create round robin database files from MQTT messages.

Tool daemon is based on ``poho-mqtt`` and ``python-daemon`` packages. All
dependencies are listed in ``requirements.txt`` file. As Python 2.x
is deprecated, tool is write for Python 3.5 or more only. For example
``signal.Signals`` class is use.

Usage
-----

.. code::

    usage: $(prog)s [options] command

    Create round robind database files form MQTT.

    positional arguments:
      command               Daemon action (start|stop|restart|status)

    optional arguments:
      -h, --help            show this help message and exit
      -c <file>, --config <file>
                            Path to config file.
      -f, --foreground      Run as script on foreground

Install
-------

.. code:: bash

    ~# pip3 install mqttorrd

Configuration
-------------

[daemon]
~~~~~~~~
:data_dir:  Directory to store round robin database files. Default value is
            ``/var/lib/mqttorrd``.
:pid_file:  Path of file with pid. Default value is ``/var/run/mqttorrd.pid``.
:user:      Daemon user, default ``nobody``.
:group:     Daemon group, default ``nogroup``.

Data directory must be writer with user or group as pid file. Each value from
MQTT broker is store to it's rrd file with path from topic. For example:
``/var/lib/mqttorrd/garden/pool/temperature.rrd``.

[logging]
~~~~~~~~~
:handler:   Python logging handler. Possible values are ``file`` or ``syslog``.
            When tool is run at foreground, ``stderr`` handler is use. On UNIX
            like systems, `WatchedFileHandler
            <https://docs.python.org/3/library/logging.handlers.html#watchedfilehandler>`_
            is used. Defaults to ``syslog``.
:syslog:    Syslog connection, ``/dev/log`` by default. ``LOG_DAEMON`` facility
            is used.
:file:      Path to log file if ``file`` handler is used. Defaults to
            ``/var/log/mqttorrd.log``.
:level:     One of Python logging level: ``DEBUG, INFO, WARNING, ERROR,
            CRITICAL``. Default value is ``ERROR``.
:format:    Logging format. Default value is
            ``%(asctime)s %(levelname)s: %(name)s: %(message)s "{%(funcName)s():%(lineno)d}``.

[mqtt]
~~~~~~
:client_id: MQTT client id. If is not defined, it is generate automatically.
:hostname:  Broker hostname, ``localhost`` by default.
:port:      Broker port, ``1883`` is **allways** default.
:keepalive: The keepalive timeout value for the client. Defaults to ``60``
            seconds.
:tls:       TLS connection, default ``False``.
:ca_certs:  Path to the Certificate Authority certificate. If is not set, system
            certs path is use.
:certfile:  Client public certificate file.
:keyfile:   Client primary key file.
:username:  Client username
:password:  Client password
:subscriptions: Coma separated topics to subscribe. Default value is ``/#``.

[/#]
~~~~
For any topics could be defined own RRD parameters. MQTT characters like ``#``
and ``+`` could be use. If new topic message was received,first definition,
which is matched is used. If database file is exist yet, only value are update.
For more information see https://oss.oetiker.ch/rrdtool/doc/rrdcreate.en.html.

:step:      Round Robin Database step. Defaults to ``60`` seconds.
:DS:        Data source definition. Default value is
            ``DS:{topic}:GAUGE:120:U:U``, where ``{topic}`` is replaced with
            file name as last topics part.
:RRA:       Value archive definition. Default value is

.. code::

        RRA:AVERAGE:0.5:2:30,
        RRA:AVERAGE:0.5:5:288,
        RRA:AVERAGE:0.5:30:336,
        RRA:AVERAGE:0.5:60:1488,
        RRA:AVERAGE:0.5:720:744,
        RRA:AVERAGE:0.5:1440:265
