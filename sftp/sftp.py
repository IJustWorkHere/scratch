#!/usr/bin/env python

# Python Imports
from __future__ import division
import os
import logging
import time
import paramiko
import traceback
from logging import DEBUG, INFO

# Custom Imports
from config import Config

logger = logging.getLogger(__name__)

class SFTP(object):

    def __init__(self, server, port, username, identity_file):
        self.server               = server
        self.port                 = port
        self.username             = username
        self.identity_file        = identity_file
        self.transport            = None
        self.sftp                 = None
        self.connect_attempts     = 0
        self.max_connect_attempts = 5
        self.upload_attempts      = 0
        self.max_upload_attempts  = 5
        self.paramiko_log_file    = '/var/log/paramiko.log'
        self.paramiko_log_level   = INFO
        self.bytes_sent           = 0
        self.put_attempted        = False

    def __repr__(self):
        return "SFTP Object that can be used to upload files to a remote host"

    def cleanup(self):
        """
        A convenience function that is used to cleanup transport and sftp objects
        :return: None
        """
        if self.sftp:
            self.sftp.close()
        if self.transport:
            self.transport.close()

    def connect(self):
        """
        Create an SFTP connection that can be used to upload/download a file from a remote server
        :return: None
        """
        server               = self.server
        port                 = self.port
        username             = self.username
        identity_file        = self.identity_file
        connect_attempts     = self.connect_attempts
        max_connect_attempts = self.max_connect_attempts
        paramiko_log_file    = self.paramiko_log_file
        paramiko_log_level   = self.paramiko_log_level
        backoff_timer        = connect_attempts * 10

        # Increase the count of attempts
        self.connect_attempts += 1

        # Wait backoff_timer seconds before attempting to connect
        time.sleep(backoff_timer)
        self.cleanup()

        try:
            paramiko.util.log_to_file(paramiko_log_file, paramiko_log_level)
            key                 = paramiko.RSAKey.from_private_key_file(identity_file)
            self.transport      = paramiko.Transport((server, port))
            self.transport.connect(username=username, pkey=key)
            self.sftp = paramiko.SFTPClient.from_transport(self.transport)
            logger.info("Successfully connected to {0}".format(server))
        except paramiko.BadAuthenticationType:
            logger.error("Server refused our authentication method")
            raise
        except paramiko.AuthenticationException:
            logger.error("Unable to login to {0} using {1}".format(server, identity_file))
            raise
        except paramiko.BadHostKeyException:
            logger.error("Valid host key not found for {0}".format(server))
            raise
        except paramiko.SSHException as exc:
            logger.error(exc)
            if connect_attempts < max_connect_attempts:
                return self.connect()
            else:
                raise

    def remote_mkdirs(self, dst):
        """
        If SFTP destination doesn't exist create it
        :param dst: Absolute path of the remote dir/file
        :return: None
        """
        sftp = self.sftp

        if dst == '/':
            sftp.chdir('/')
            return
        if dst == '':
            return
        try:
            sftp.lstat(dst)
        except IOError:
            dirname, basename = os.path.split(dst.rstrip('/'))
            self.remote_mkdirs(dirname)
            sftp.chdir(dirname)
            sftp.mkdir(basename)

    def remote_delete(self, dst):
        """
        Delete a remote file
        :param dst: Absolute path of the remote file
        :return: None
        """
        server = self.server
        sftp   = self.sftp

        try:
            logger.debug("Attempting to delete {0}:{1}".format(server, dst))
            sftp.remove(dst)
            logger.info("Deleted {0}:{1}".format(server, dst))
        except IOError as exc:
            logger.debug("Unable to delete {0}.  Error: {1}".format(dst, str(exc)))

    def transfer(self, reader, writer, total_bytes_to_transfer):
        """
        Provides a method for writing data to a file on a remote server
        :param reader: File like object for the local file
        :param writer: File like object for the remote file
        :param total_bytes_to_transfer: Size of the local file in bytes
        :return: None
        """
        while True:
            data = reader.read(32768)
            writer.write(data)
            self.bytes_sent += len(data)
            if len(data) == 0:
                break
            if logger.isEnabledFor(DEBUG):
                percentage = (self.bytes_sent / total_bytes_to_transfer) * 100
                logger.debug("Bytes transfered: {0:n}  Total Bytes: {1:n}  Percentage: {2:.2f} %".format(self.bytes_sent,
                                                                                                         total_bytes_to_transfer,
                                                                                                         percentage))

    def put(self, localpath, remotepath):
        """
        A put method that will allow us to attempt restarting when a put fails
        :param localpath: The local file to copy
        :param remotepath: The remote file to be copied to
        :return: None
        """
        sftp = self.sftp
        remote_file_mode = 'ab' if self.put_attempted else 'wb'
        self.put_attempted = True

        file_size = os.stat(localpath).st_size
        with sftp.file(remotepath, remote_file_mode) as fr:
            start_block = fr.tell()
            with open(localpath, 'rb') as fl:
                fl.seek(start_block)
                self.transfer(reader=fl, writer=fr, total_bytes_to_transfer=file_size)
        st = sftp.stat(remotepath)
        if st.st_size != file_size:
            raise AssertionError('size mismatch in put!  %d != %d' % (st.st_size, file_size))

    def upload(self, src, dst):
        """
        Upload a file from the local system to the remote system
        :param src: Absolute path of the local file
        :param dst: Absolute path of the remote file
        :return: None
        """
        max_upload_attempts = self.max_upload_attempts
        upload_attempts     = self.upload_attempts
        self.upload_attempts += 1

        try:
            logger.info("Starting upload of {0} to {1}:{2}".format(src, self.server, dst))
            dirname = os.path.dirname(dst)
            self.remote_mkdirs(dirname)
            self.put(src, dst)
            logger.info("Successfully uploaded {0} to {1}:{2}".format(src, self.server, dst))
        except AssertionError:
            msg = traceback.format_exc()
            logger.error(msg)
            self.remote_delete(dst)
            logger.error("Failed to upload {0} to {1}:{2}".format(src, self.server, dst))
        except Exception:
            msg = traceback.format_exc()
            logger.error(msg)
            if upload_attempts < max_upload_attempts:
                self.connect()
                self.upload(src, dst)
            else:
                logger.error("Failed to upload {0} to {1}:{2}".format(src, self.server, dst))

    @classmethod
    def sftp_file(cls, src, dst):
        """
        Provides a simple alternate constructor that can be used to upload a file
        :param src: Absolute path of the local file
        :param dst: Absolute path of the remote file
        :return: None
        """
        server        = Config.pegasys_server_name
        port          = Config.pegasys_server_port
        user          = Config.pegasys_server_username
        identity_file = Config.pegasys_server_identity_file

        try:
            sftp_client = cls(server, port, user, identity_file)
            sftp_client.connect()
            sftp_client.upload(src, dst)
        finally:
            sftp_client.cleanup()