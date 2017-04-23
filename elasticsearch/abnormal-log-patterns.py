#!/usr/bin/env python
# coding: utf-8
# vim: tabstop=2 noexpandtab
from __future__ import division

import requests
import logging
import argparse
import inspect
import ssl
import socket
import json
from datetime import datetime, timedelta

log_filename = "es_query_test.log"
host = 'logstash.receiver.fqdn'
port = 514 # Logstash receiver port

# setup root logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler(log_filename)
handler.setLevel(logging.ERROR)
logger.addHandler(handler)


class LogstashFormatter(logging.Formatter):
    def __init__(self, msg_type='http-query-validation', msg_path='logstash', environment='docker'):
        self.msg_path = msg_path
        self.msg_type = msg_type
        self.environment = environment
        # Python 2.6.6 it appears that logging.Formatter is an old style class
        logging.Formatter.__init__(self, fmt=None, datefmt=None)
        # Uncomment this if using a newer version of Python logger
        # super(LogstashFormatter, self).__init__(fmt=None, datefmt=None)

    def formatTime(self, record, datefmt=None):
        return datetime.utcfromtimestamp(record.created).isoformat()[:-3] + 'Z'

    def format(self, record):
        message_dict = {
            '@version': 1,
            '@timestamp': self.formatTime(record),
            'host': socket.getfqdn(),
            'levelname': record.levelname,
            'logger': record.name,
            'lineno': record.lineno,
            'pathname': record.pathname,
            'process': record.process,
            'threadName': record.threadName,
            'funcName': record.funcName,
            'processName': record.processName,
            'message': record.getMessage(),
            'tags': ['httpd-query'],
            'environment': self.environment,
            'type': self.msg_type
        }
        if record.exc_info:
            message_dict['exc_info'] = self.formatException(
                    record.exc_info
            )

        # Add any extra attributes to the message field
        for key, value in record.__dict__.iteritems():
            if key in ('args', 'asctime', 'created', 'exc_info', 'exc_text',
                       'filename', 'funcName', 'id', 'levelname', 'levelno',
                       'lineno', 'module', 'msecs', 'msecs', 'message', 'msg',
                       'name', 'pathname', 'process', 'processName',
                       'relativeCreated', 'thread', 'threadName'):
                # These are already handled above or not handled at all
                continue
            if value is None:
                message_dict[key] = value
                continue
            if isinstance(value, (str, bool, dict, float, int, list)):
                message_dict[key] = value
                continue
            message_dict[key] = repr(value)

        return json.dumps(message_dict)


class TCPLogstashHandler(logging.handlers.SocketHandler):
    """
    Sends output to an optionally encrypted streaming logstash TCP listener.
    """

    # TODO Force Authentication of logstash server to avoid MITM
    def __init__(self, host, port, keyfile=None, certfile=None, ca_certs=None, ssl=False):
        logging.handlers.SocketHandler.__init__(self, host, port)
        self.keyfile = keyfile
        self.certfile = certfile
        self.ca_certs = ca_certs
        self.ssl = ssl

    def makeSocket(self, timeout=1):
        socket = logging.handlers.SocketHandler.makeSocket(self, timeout)
        if self.ssl:
            return ssl.wrap_socket(socket,
                                   keyfile=self.keyfile,
                                   certfile=self.certfile,
                                   ca_certs=self.ca_certs)
        return socket

    def makePickle(self, record):
        return self.format(record) + "\n"


class Checks(object):

    def __totimestamp(self, dt, epoch=datetime(1970,1,1)):
        td = dt - epoch
        # return td.total_seconds()
        epoch = (td.microseconds + (td.seconds + td.days * 86400) * 10**6) / 10**6
        return int(epoch)

    def __avg(self, values):
        sum = 0
        count = len(values)
        for value in values:
            sum += value
        return sum / count

    def __stdev(self, values):
        mean = self.__avg(values)
        squared_values = [ (x - mean)**2 for x in values ]
        squared_mean = self.__avg(squared_values)
        return squared_mean**(.5)

    def __oldest_document(self):
        url = 'http://localhost:9200/logstash-*/_search'
        query = {
            "query": {
                "match_all": {}
            },
            "size": 1,
            "sort": [
                {
                    "_timestamp": {
                        "order": "desc"
                    }
                }
            ]
        }
        es_query = json.dumps(query)
        resp = requests.post(url, data=es_query)
        if resp.status_code == 200:
            resp_data = json.loads(resp.text)
        else:
            return self.__totimestamp(datetime.utcnow())
        for hit in resp_data['hits']['hits']:
            if hit.has_key('_source'):
                key = hit['_source']['@timestamp']
                return self.__totimestamp(datetime.strptime(key, '%Y-%m-%dT%H:%M:%S.%fZ'))

    def http_status_codes(self, environment):
        '''
        status_code_info = { '401': {'last_hour':5, 'last_30_days':[1,2,3], 'stdev': 10, 'avg': 5} }
        '''
        # String constants
        last_30_days = 'last_30_days'
        last_hour = 'last_hour'
        stdev = 'stdev'
        avg = 'avg'
        url = 'http://localhost:9200/_search'

        # Status Code Constants
        status_codes = [
            200, 201, 202, 204,
            301, 302, 304,
            400, 401, 403, 404, 405, 406, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 422,
            500, 501, 502, 503, 504, 505
        ]

        # Time constants
        current_hour = datetime.utcnow().hour
        last_one_hour = self.__totimestamp(datetime.utcnow() + timedelta(hours=-1))
        gte = self.__totimestamp(datetime.utcnow() + timedelta(-30)) * 1000
        lte = self.__totimestamp(datetime.utcnow()) * 1000

        status_code_info = {}

        query = { "size": 0,
                  "query": {
                      "filtered": {
                          "query": {
                              "query_string": {
                                  "query": "type:httpd-access AND status:[200 TO *] AND environment:{0}".format(environment),
                                  "analyze_wildcard": 'true'
                              }
                          },
                          "filter": {
                              "bool": {
                                  "must": [
                                      {
                                          "range": {
                                              "@timestamp": {
                                                  "gte": gte,
                                                  "lte": lte,
                                                  "format": "epoch_millis"
                                              }
                                          }
                                      }
                                  ],
                                  "must_not": []
                              }
                          }
                      }
                  },
                  "aggs": {
                      "2": {
                          "date_histogram": {
                              "field": "@timestamp",
                              "interval": "1h",
                              "min_doc_count": 0,
                              "extended_bounds": {
                                  "min": gte,
                                  "max": lte
                              }
                          },
                          "aggs": {
                              "3": {
                                  "terms": {
                                      "field": "status",
                                      "size": 20,
                                      "order": {
                                          "_count": "desc"
                                      }
                                  }
                              }
                          }
                      }
                  }
                  }

        for code in status_codes:
            status_code_info[code] = {last_30_days: [], last_hour: 0, stdev: 0, avg: 0}

        es_query = json.dumps(query)
        resp = requests.post(url, data=es_query)

        if resp.status_code == 200:
            resp_data = json.loads(resp.text)
            buckets = resp_data['aggregations']['2']['buckets']

            for bucket in buckets:
                key_timestamp = int(bucket['key'] / 1000)
                hour = datetime.utcfromtimestamp(key_timestamp).hour
                if hour == current_hour or key_timestamp >= last_one_hour:
                    if len(bucket['3']['buckets']) == 0:
                        for code in status_codes:
                            status_code_info[code][last_30_days].append(0)
                    else:
                        sub_list = []
                        for sbucket in bucket['3']['buckets']:
                            status_code = sbucket['key']
                            count = sbucket['doc_count']
                            sub_list.append(status_code)
                            # All counts over the last n days for the given hour
                            if hour == current_hour:
                                if status_code_info.has_key(status_code):
                                    status_code_info[status_code][last_30_days].append(count)
                                else:
                                    status_code_info[status_code] = {last_30_days: [count], last_hour: 0, stdev: 0, avg: 0}
                            # All counts over the last 1 hour
                            if key_timestamp >= last_one_hour:
                                status_code_info[status_code][last_hour] = count
                        for code in status_codes:
                            if not code in sub_list:
                                status_code_info[code][last_30_days].append(0)

            for code, values in status_code_info.iteritems():
                recalc_deviation_average = False
                if len(status_code_info[code][last_30_days]) > 0:
                    average = self.__avg(status_code_info[code][last_30_days])
                    deviation = self.__stdev(status_code_info[code][last_30_days])
                    # We don't want an alert for a single change
                    if deviation < 1:
                        deviation = 1
                    if average < 1:
                        average = 1
                    for count_value in status_code_info[code][last_30_days]:
                        if count_value > (average + 5*deviation):
                            recalc_deviation_average = True
                            status_code_info[code][last_30_days].remove(count_value)
                    if recalc_deviation_average:
                        average = self.__avg(status_code_info[code][last_30_days])
                        deviation =  self.__stdev(status_code_info[code][last_30_days])
                        average = 1 if average < 1 else average
                        deviation = 1 if deviation < 1 else deviation
                else:
                    average = 0
                    deviation = 0

                status_code_info[code][avg] = average
                status_code_info[code][stdev] = deviation

            for code, values in status_code_info.iteritems():
                alarm = False

                max = (values[avg] + 2 * values[stdev])
                min = (values[avg] - 2 * values[stdev])

                if values[last_hour] > max or values[last_hour] < min:
                    alarm = True

                if alarm:
                    print 'HTTP code: {0}, Stdev: {1}, Avg: {2}, Last Hour: {3}'.format(code,
                                                                                        values[stdev],
                                                                                        values[avg],
                                                                                        values[last_hour])

                    logger.info('Log Entries Per Host By Type',
                                extra = {
                                    'node': node,
                                    'source': source,
                                    'last_30_days': last_30_values,
                                    'standard_deviation': values[stdev],
                                    'last_hour': values[last_hour],
                                    'average': values[avg],
                                    'will_alarm': alarm
                                })

    def source_per_host_count(self):
        '''
        source_per_host_info = {
                                'host1': {
                                                    'syslog-audit': {'last_hour': 2830, 'last_30_days': [2830, 2835, 2838], 'stdev': 5, 'avg': 2836},
                                                    'syslog-standard': {'last_hour': 21, 'last_30_days': [21, 22, 23], 'stdev': 1, 'avg': 22},
                                                    'anti-virus': {'last_hour': 2, 'last_30_days':[1, 2, 3], 'stdev': 1, 'avg': 2}
                                               },
                                'host2': {
                                                    'syslog-audit': {'last_hour': 2830, 'last_30_days': [2830, 2835, 2838], 'stdev': 5, 'avg': 2836},
                                                    'syslog-standard': {'last_hour': 21, 'last_30_days': [21, 22, 23], 'stdev': 1, 'avg': 22},
                                                    'anti-virus': {'last_hour': 2, 'last_30_days':[1, 2, 3], 'stdev': 1, 'avg': 2}
                                               }
                                }
        '''
        # String constants
        last_30_days = 'last_30_days'
        last_hour = 'last_hour'
        stdev = 'stdev'
        avg = 'avg'
        url = 'http://localhost:9200/_search'

        # Time constants
        oldest_document = self.__oldest_document()
        now = datetime.utcnow()
        current_hour = now.hour
        last_one_hour = self.__totimestamp(now + timedelta(hours=-1))
        gte = self.__totimestamp(now + timedelta(-30)) * 1000
        lte = self.__totimestamp(now) * 1000

        source_per_host_info = {}

        query = {
            "size": 0,
            "query": {
                "filtered": {
                    "query": {
                        "query_string": {
                            "query": "*",
                            "analyze_wildcard": 'true'
                        }
                    },
                    "filter": {
                        "bool": {
                            "must": [
                                {
                                    "range": {
                                        "@timestamp": {
                                            "gte": gte,
                                            "lte": lte,
                                            "format": "epoch_millis"
                                        }
                                    }
                                }
                            ],
                            "must_not": []
                        }
                    }
                }
            },
            "aggs": {
                "2": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "interval": "1h",
                        "min_doc_count": 0,
                        "extended_bounds": {
                            "min": gte,
                            "max": lte
                        }
                    },
                    "aggs": {
                        "3": {
                            "terms": {
                                "field": "host.raw",
                                "size": 100,
                                "order": {
                                    "_count": "desc"
                                }
                            },
                            "aggs": {
                                "4": {
                                    "terms": {
                                        "field": "type.raw",
                                        "size": 100,
                                        "order": {
                                            "_count": "desc"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        es_query = json.dumps(query)
        resp = requests.post(url, data=es_query)

        if resp.status_code == 200:
            resp_data = json.loads(resp.text)
            buckets = resp_data['aggregations']['2']['buckets']

            for bucket in buckets:
                key_timestamp = int(bucket['key'] / 1000)
                hour = datetime.utcfromtimestamp(key_timestamp).hour
                if hour == current_hour or key_timestamp >= last_one_hour:
                    for sbucket in bucket['3']['buckets']:
                        host = sbucket['key']
                        for ssbucket in sbucket['4']['buckets']:
                            type = ssbucket['key']
                            count = ssbucket['doc_count']
                            if source_per_host_info.has_key(host):
                                if source_per_host_info[host].has_key(type):
                                    source_per_host_info[host][type][last_30_days].append(count)
                                else:
                                    source_per_host_info[host][type] = {last_hour: 0, last_30_days: [count], stdev: 0, avg: 0}
                            else:
                                source_per_host_info[host] = {}
                                source_per_host_info[host][type] = {last_hour: 0, last_30_days: [count], stdev: 0, avg: 0}
                            if key_timestamp >= last_one_hour:
                                source_per_host_info[host][type][last_hour] = count

            delta = now - datetime.utcfromtimestamp(oldest_document)

            for node in source_per_host_info.iterkeys():
                for source, values in source_per_host_info[node].iteritems():
                    recalc_deviation_average = False
                    last_30_values = values[last_30_days]

                    if len(last_30_values) > 0:
                        if len(last_30_values) < delta.days:
                            for missing in range(delta.days - len(last_30_values)):
                                last_30_values.append(0)

                        average = self.__avg(last_30_values)
                        deviation = self.__stdev(last_30_values)
                        if deviation < 1:
                            deviation = 1
                        if average < 1:
                            average = 1

                        for single_value in last_30_values:
                            if single_value > (average + 5*deviation):
                                recalc_deviation_average = True
                                last_30_values.remove(single_value)
                        if recalc_deviation_average:
                            average = self.__avg(last_30_values)
                            deviation = self.__stdev(last_30_values)
                            average = 1 if average < 1 else average
                            deviation = 1 if deviation < 1 else deviation

                        values[avg] = average
                        values[stdev] = deviation

                        max = (average + 5 * deviation)
                        min = (average - 2 * deviation)

                        if values[last_hour] > max or values[last_hour] < min:
                            alarm = True
                        else:
                            alarm = False

                        if alarm:
                            print 'Node: {0}, Type: {1}, Stdev: {2}, Avg: {3}, Last Hour: {4}'.format(node,
                                                                                                      source,
                                                                                                      values[stdev],
                                                                                                      values[avg],
                                                                                                      values[last_hour])

                        logger.info('Log Entries Per Host By Type',
                                    extra = {
                                        'node': node,
                                        'source': source,
                                        'last_30_days': last_30_values,
                                        'standard_deviation': values[stdev],
                                        'last_hour': values[last_hour],
                                        'average': values[avg],
                                        'will_alarm': alarm
                                    })


class Main(Checks):

    def __init__(self):
        parser = argparse.ArgumentParser()

        subparsers = parser.add_subparsers()

        for name in dir(self):
            if not name.startswith("_"):
                p = subparsers.add_parser(name)
                method = getattr(self, name)
                argnames = inspect.getargspec(method).args[1:]
                for argname in argnames:
                    p.add_argument(argname)
                p.set_defaults(func=method, argnames=argnames)
        self.args = parser.parse_args()

    def __setup_logging__(self):
        a = self.args
        env = getattr(a, 'environment') if 'environment' in a.argnames else 'ALL'

        # Logstash logging... Set this up here to pass in the env
        logstashFormatter = LogstashFormatter(environment=env)
        logstashHandler = TCPLogstashHandler(host, port, ssl=True)
        logstashHandler.setFormatter(logstashFormatter)
        logger.addHandler(logstashHandler)

    def __call__(self):
        try:
            self.__setup_logging__()
            a = self.args
            callargs = [getattr(a, name) for name in a.argnames]
            return self.args.func(*callargs)
        except Exception, err:
            print str(err)


if __name__ == "__main__":
    main = Main()
    main()