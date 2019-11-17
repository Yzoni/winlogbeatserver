import parse
import sys

if __name__ == '__main__':
    with open('../test/test_thread.json') as f:
        for l in f:
            print(parse.parse_csv(l))

    with open('../test/test_process.json') as f:
        for l in f:
            print(parse.parse_csv(l))

def test_start_subprocess():
    import subprocess
    import time
    pargs = [sys.executable,
             "/home/y/Documents/Thesis/winlogbeatserver/winlogbeatserver/winlogbeatserver.py",
             'a',
             '--debug']
    proc = subprocess.Popen(
        pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
    )

    time.sleep(5)

    if proc.poll():
        out, err = proc.communicate()
        log.info(out)
        log.info(err)

    try:
        proc.terminate()
        time.sleep(2)
    except:
        try:
            if not proc.poll():
                log.debug("Killing Wineventlog")
                proc.kill()
        except OSError as e:
            log.debug("Error killing Wineventlog: %s. Continue", e)
        except Exception as e:
            log.exception("Unable to stop the Wineventlog with pid %d: %s",
                          proc.pid, e)

