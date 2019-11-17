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


PARSE = True
queue = Queue()


def write_log(queue_data, base_path):
    log.info(' * Write log process started')
    if not os.path.exists(base_path):
        raise ValueError('Save directory does not exist: {}'.format(base_path))

    with open(os.path.join(base_path, 'thread.csv'), 'w') as thread_f, \
            open(os.path.join(base_path, 'process.csv'), 'w') as process_f, \
            open(os.path.join(base_path, 'syscall.csv'), 'w') as syscall_f, \
            open(os.path.join(base_path, 'status.csv'), 'w') as status_f:
        for d in iter(queue_data.get, None):
            # log.info('Processing Winlogbeat queue element, queue size: {}'.format(queue.qsize()))
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



class Bulk(Resource):
    def post(self):
        data = request.get_data().decode('utf-8').rstrip().split('\n')
        for d in data:
            # Do use the document 'header'
            if len(d) > 100:
                queue.put(d)


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


def start_flask():
    app = Flask(__name__)
    api = Api(app)

    api.add_resource(WinlogbeatServer, '/')
    api.add_resource(XPack, '/_xpack')
    api.add_resource(Policy, '/_ilm/policy/winlogbeat-7.4.2')
    api.add_resource(Template, '/_template/winlogbeat-7.4.2')
    api.add_resource(WinlogbeatNow, '/<winlogbeat-7.4.2-{now/d}-000001>')
    api.add_resource(Bulk, '/_bulk')
    return app


class WinlogBeat:

    def __init__(self, output_dir, debug=True, port=5000):
        """
        :param output_dir: Directory to write the csv files to.
        """
        self.main_process = None
        self.parse_process = None
        self.main_process_pid = None
        self.parse_process_pid = None
        self.output_dir = output_dir
        self.debug = debug
        self.port = port

    def start(self):
        app = start_flask()
        kwargs = {
            'debug': self.debug,
            'use_reloader': False,
            'host': '0.0.0.0',
            'port': self.port
        }

        self.main_process = Process(target=app.run, kwargs=kwargs)
        self.main_process.start()
        self.main_process_pid = self.main_process.pid

        self.parse_process = Process(target=write_log, args=(queue, self.output_dir))
        self.parse_process.start()
        self.parse_process_pid = self.main_process.pid

    def queue_size(self):
        return queue.qsize()

    def stop(self):
        if not self.main_process or not self.parse_process:
            raise RuntimeError('Winlogbeatserver: Processes not started')
        try:
            self.main_process.terminate()
            self.parse_process.terminate()
        except Exception as e:
            log.error('Error occurred while terminating Winlogbeat child processes: {}'.format(e))

        if self._pid_exists(self.main_process_pid):
            try:
                log.info('Winlogbeat main process still alive... Killing again...')
                os.kill(self.main_process_pid, signal.SIGTERM)
            except OSError:
                log.warning('Winlogbeat main process PID does not exist')

        if self._pid_exists(self.parse_process_pid):
            try:
                log.info('Winlogbeat parse process still alive... Killing again...')
                os.kill(self.parse_process_pid, signal.SIGTERM)
            except OSError:
                log.warning('Winlogbeat parse process PID does not exist')

        self.main_process_pid = None
        self.parse_process_pid = None

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
    wlb.start()


if __name__ == '__main__':
    main()
