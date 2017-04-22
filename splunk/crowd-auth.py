#!/usr/bin/env python

# This is a Splunk scripted auth implementation that delegates
# the users and group lookups to an Atlassian Crowd server.
# Will only pull in groups that begin with 'splunk_'
# Splunk users must be a member of the Crowd group 'splunk_user'
import argparse
import sys
import logging
import crowd
import getopt
from copy import copy

# Log actions to the crowd-auth log
logging.basicConfig(level=logging.INFO,
                    filename="crowd-auth.log",
                    format='%(asctime)s - %(levelname)s - %(message)s')


class Main(object):
    _SUCCESS  = "--status=success"
    _FAILED   = "--status=fail"

    def __init__(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        for name in dir(self):
            if not name.startswith("_"):
                p = subparsers.add_parser(name)
                method = getattr(self, name)
                p.set_defaults(func=method, argnames=[])
        self.args = parser.parse_args()

    def _authenticate_splunk_app(self):
        app_url   = 'crowd-url-here'
        app_user  = 'splunk-user-in-crowd-here'
        app_pass  = 'splunk-pass-in-crowd-here'
        self.cs = crowd.CrowdServer(app_url, app_user, app_pass)

    def _read_input(self):
        results = { 'username': '',
                    'password': '' }
        opts, args = getopt.getopt(sys.stdin.readlines(), '', ['username=', 'password='])
        for opt, arg in opts:
            results[opt.lstrip('--')] = arg.strip()
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            log_results = copy(results)
            log_results['password'] = 'REDACTED'
            logger.debug("_read_input: {0}".format(log_results))
        return results

    def _get_splunk_groups(self, username):
        groups = self.cs.get_nested_groups(username)
        precursor = 'splunk_'
        result = []
        if isinstance(groups, list):
            result = [ group[len(precursor):] for group in groups if group.startswith(precursor) ]
        logger.info("_get_splunk_groups: {0}".format(result))
        return result

    def _authenticate_crowd_user(self, username, password):
        result = self.cs.auth_user(username, password)
        logger.info("_authenticate_crowd_user: {0}".format(result))
        return result

    def _authorize_crowd_user(self, username):
        required_group = 'user'
        result = False
        if required_group in self._get_splunk_groups(username):
            result = True
        logger.info("_authorize_crowd_user: {0}".format(result))
        return result

    def userLogin(self, username, password):
        result = self._FAILED
        if self._authenticate_crowd_user(username, password) and self._authorize_crowd_user(username):
            result = self._SUCCESS
        logger.info("userLogin: {0}".format(result))
        print result

    def getUserInfo(self, username, **kw):
        user_splunk_groups = self._get_splunk_groups(username)
        result = self._FAILED
        if isinstance(user_splunk_groups, list):
            result = self._SUCCESS + ' --userInfo=' + username + ';' + username + ';' + username + ';' + ':'.join(user_splunk_groups)
        logger.info("getUserInfo: {0}".format(result))
        print result

    def getUsers(self, **kw):
        splunk_user_group = 'splunk_user'
        splunk_users = self.cs.get_nested_group_users(splunk_user_group)
        if splunk_users:
            result = self._SUCCESS
            for user in splunk_users:
                user_splunk_groups = self._get_splunk_groups(user)
                result += ' --userInfo=' + user + ';' + user + ';' + user + ';' + ':'.join(user_splunk_groups)
        else:
            result = self._FAILED
        logger.info("getUsers: {0}".format(result))
        print result

    def __call__(self):
        try:
            self._authenticate_splunk_app()
            callkwargs = self._read_input()
            return self.args.func(**callkwargs)
        except Exception as err:
            logger.error(str(err))

if __name__ == "__main__":
    main = Main()
    main()