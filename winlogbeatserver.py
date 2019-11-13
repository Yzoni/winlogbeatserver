# Requries python 2.7 with custom Werkzeug for '<' parsing in url

from flask import request
from flask import Flask
from flask_restful import Resource, Api
import parse
from multiprocessing import Process, Queue
import responses
import logging

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


def write_log(queue_data):
    log.info(' * Write log process started')
    for d in iter(queue_data.get, None):
        log.info('Processing Winlogbeat queue element, queue size: {}'.format(queue.qsize()))
        if PARSE:
            with open('thread.csv', 'a') as thread_f, \
                    open('syscall.csv', 'a') as syscall_f, \
                    open('status.csv', 'a') as status_f:
                if len(d) > 100:
                    type, p = parse.parse_csv(d)
                    if type == parse.EventTypes.UNKNOWN:
                        continue
                    if type == parse.EventTypes.THREAD:
                        thread_f.write(p)
                    elif type == parse.EventTypes.SYSCALL:
                        syscall_f.write(p)
                    elif type == parse.EventTypes.STATUS:
                        status_f.write(p)
        else:
            with open('out.jsonlines', 'a') as f:
                if len(d) > 100:
                    f.write('\n'.format(d))
            return responses.bulk


class Bulk(Resource):
    def post(self):
        data = request.get_data().decode().rstrip().split('\n')
        for d in data:
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

    def __init__(self):
        self.main_process = None
        self.parse_process = None

    def start(self):
        app = start_flask()
        kwargs = {
            'debug': 'debug',
            'use_reloader': False,
            'host': '0.0.0.0',
            'port': 5000
        }

        self.main_process = Process(target=app.run, kwargs=kwargs)
        self.main_process.start()

        self.parse_process = Process(target=write_log, args=(queue,))
        self.parse_process.start()

    def queue_count(self):
        return queue.qsize()

    def stop(self):
        if not self.main_process or not self.parse_process:
            raise RuntimeError('Winlogbeatserver: Processes not started')

        self.main_process.terminate()
        self.parse_process.terminate()


def main():
    wlb = WinlogBeat()
    wlb.start()


if __name__ == '__main__':
    main()
