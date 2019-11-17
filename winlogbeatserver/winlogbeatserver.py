# Requries python 2.7 with custom Werkzeug for '<' parsing in url
from flask import request
from flask import Flask
from flask_restful import Resource, Api
import parse
from multiprocessing import Process, Queue
import responses
import logging
import os
import argparse
import signal
import sys
import time
import pylzma
import struct
from cStringIO import StringIO
from werkzeug.serving import make_server
import requests

log = logging.getLogger(__name__)


class WinlogbeatServer(Resource):
    def get(self):
        return responses.root


class XPack(Resource):
    def get(self):
        return responses.xpack


class Policy(Resource):
    def get(self):
        return responses.policy, 404

    def put(self):
        return responses.ack


filename_thread = 'thread.csv'
filename_process = 'process.csv'
filename_syscall = 'syscall.csv'
filename_status = 'status.csv'


def write_log(queue_data, base_path):
    log.info(' * Write log process started')
    log.info(' * Writing to {}'.format(base_path))
    if not os.path.exists(base_path):
        raise ValueError('Save directory does not exist: {}'.format(base_path))

    with open(os.path.join(base_path, filename_thread), 'w') as thread_f, \
            open(os.path.join(base_path, filename_process), 'w') as process_f, \
            open(os.path.join(base_path, filename_syscall), 'w') as syscall_f, \
            open(os.path.join(base_path, filename_status), 'w', buffering=0) as status_f:

        started_waiting = time.time()
        while True:
            if not queue_data.empty():
                started_waiting = time.time()
                d = queue_data.get_nowait()
                # log.info('Processing Winlogbeat queue element, queue size: {}'.format(queue_data.qsize()))
                type, p = parse.parse_csv(d)
                if type == parse.EventTypes.UNKNOWN:
                    continue
                elif type == parse.EventTypes.THREAD:
                    thread_f.write(p)
                elif type == parse.EventTypes.PROCESS:
                    process_f.write(p)
                elif type == parse.EventTypes.SYSCALL:
                    syscall_f.write(p)
                elif type == parse.EventTypes.STATUS:
                    logging.info('Found status')
                    status_f.write(p)
            if time.time() - started_waiting > 60:
                log.info('Wineventlog timeout waiting for data')
                return



class Bulk(Resource):
    def __init__(self, queue_data):
        self.queue_data = queue_data

    def post(self):
        data = request.get_data().decode('utf-8').rstrip().split('\n')
        for d in data:
            # Do use the document 'header'
            if len(d) > 100:
                self.queue_data.put(d)


class Template(Resource):
    def put(self):
        return {"acknowledged": True}

    def head(self):
        return 404


class WinlogbeatNow(Resource):
    def get(self):
        return responses.now

    def put(self):
        return responses.now


class Shutdown(Resource):
    def get(self):
        self.shutdown_server()
        return 'Server shutting down...'

    def shutdown_server(self):
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()


def start_flask(queue, kwargs):
    app = Flask('Winlogbeatserver')
    api = Api(app)

    api.add_resource(WinlogbeatServer, '/')
    api.add_resource(XPack, '/_xpack')
    api.add_resource(Policy, '/_ilm/policy/winlogbeat-7.4.2')
    api.add_resource(Template, '/_template/winlogbeat-7.4.2')
    api.add_resource(WinlogbeatNow, '/<winlogbeat-7.4.2-{now/d}-000001>')
    api.add_resource(Bulk, '/_bulk', resource_class_kwargs=queue)
    api.add_resource(Shutdown, '/shutdown')

    return app.run(**kwargs)


class WinlogBeat:

    def __init__(self, output_dir, debug=True, port=5000):
        """
        :param output_dir: Directory to write the csv files to.
        """
        self.main_process = None
        self.parse_process = None
        self.output_dir = output_dir
        self.debug = debug
        self.port = port
        self.queue = Queue()

    def start(self):
        while not self.queue.empty():
            # Make sure queue is empty.
            self.queue.get_nowait()

        kwargs = {
            'debug': self.debug,
            'use_reloader': False,
            'host': '0.0.0.0',
            'port': self.port
        }

        self.main_process = Process(target=start_flask, args=({'queue_data': self.queue}, kwargs))

        self.main_process.start()
        log.info('Main process pid {}'.format(self.main_process.pid))

        self.parse_process = Process(target=write_log, args=(self.queue, self.output_dir))

        self.parse_process.start()
        log.info('Parse process pid {}'.format(self.parse_process.pid))

    def queue_size(self):
        return self.queue.qsize()

    def stop(self):
        # 1337
        requests.get('http://localhost:{}/shutdown'.format(self.port))

        if not self.main_process or not self.parse_process:
            raise RuntimeError('Winlogbeatserver: Processes not started')
        try:
            self.main_process.join()
            self.parse_process.join()

            time.sleep(5)
        except Exception as e:
            log.error('Error occurred while joining Winlogbeat child processes: {}'.format(e))

        if self.main_process.is_alive():
            try:
                log.info('Winlogbeat main process still alive... Killing again...')
                os.kill(self.main_process.pid, signal.SIGKILL)
            except OSError:
                log.warning('Winlogbeat main process PID does not exist')

        if self.parse_process.is_alive():
            try:
                log.info('Winlogbeat parse process still alive... Killing again...')
                os.kill(self.parse_process.pid, signal.SIGKILL)
            except OSError:
                log.warning('Winlogbeat parse process PID does not exist')

    @staticmethod
    def compress_compatible(data):
        c = pylzma.compressfile(StringIO(data))
        # LZMA header
        result = c.read(5)
        # size of uncompressed data
        result += struct.pack('<Q', len(data))
        # compressed data
        return result + c.read()

    @staticmethod
    def _pid_exists(pid):
        """ Check For the existence of a unix pid. """
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        else:
            return True


def parse_args():
    parser = argparse.ArgumentParser(description='Server for capturing specific winlogbeat output')
    parser.add_argument('out', type=str,
                        help='Output directory')
    parser.add_argument('--logfile', type=str,
                        help='Enable debug')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug')
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    if args.logfile:
        logging.basicConfig(filename=args.logfile, level=logging.DEBUG)
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    wlb = WinlogBeat(args.out, debug=args.debug)

    try:
        wlb.start()
        log.info('waiting')
        time.sleep(5)
        # wlb.stop()

    except Exception as e:
        log.info(e)
        log.info('Stopping server')
        wlb.stop()
        exit(0)


if __name__ == '__main__':
    main()
