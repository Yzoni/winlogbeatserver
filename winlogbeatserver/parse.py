import json
import logging

log = logging.getLogger(__name__)


class EventTypes:
    STATUS = 0
    SYSCALL = 1
    THREAD = 2
    PROCESS = 3
    UNKNOWN = -1


def parse_csv(data):
    try:
        j = json.loads(data)
        winlog = j['winlog']
        if not winlog['provider_name'] == 'Call Logger':
            return EventTypes.UNKNOWN, None

        datatime = j['@timestamp']
        event_data = winlog['event_data']

        csv_row = u'{}'.format(datatime)
        if int(event_data['opcode']) == EventTypes.SYSCALL:
            pid = event_data.get('pid')
            tid = event_data.get('tid')
            syscall = event_data.get('syscall')
            csv_row += u',{},{},{}\n'.format(pid, tid, syscall)
            return EventTypes.SYSCALL, csv_row
        if int(event_data['opcode']) == EventTypes.THREAD:
            name = event_data.get('name')
            ppid = event_data.get('ppid')
            pid = event_data.get('pid')
            tid = event_data.get('tid')
            newtid = event_data.get('newtid')
            created = event_data.get('created')
            csv_row += u',"{}",{},{},{},{},{}\n'.format(name, ppid, pid, tid, newtid, created)
            return EventTypes.THREAD, csv_row
        if int(event_data['opcode']) == EventTypes.PROCESS:
            name = event_data.get('name')
            ppid = event_data.get('ppid')
            pid = event_data.get('pid')
            tid = event_data.get('tid')
            created = event_data.get('created')
            csv_row += u',"{}",{},{},{},{}\n'.format(name, ppid, pid, tid, created)
            return EventTypes.THREAD, csv_row
        if int(event_data['opcode']) == EventTypes.STATUS:
            status = event_data.get('logging_started')
            csv_row += u',{}\n'.format(status)
            return EventTypes.STATUS, csv_row
        else:
            return EventTypes.UNKNOWN, None
    except Exception as e:
        log.error(u'Failed to parse {}: {}'.format(data, e))
