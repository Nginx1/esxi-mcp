"""Local optional-backend integration: ephemeral SSH server, no ESXi or production credentials."""
import hashlib
import json
import socket
import tempfile
import threading
import time
from pathlib import Path
import paramiko
from esxi_mcp import admin
from esxi_mcp.config import Config
from mcp.server.fastmcp.exceptions import ToolError

KEY = paramiko.RSAKey.generate(2048)
SECRET = 'LOCAL_SSH_TEST_SECRET'

class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event=threading.Event()
        self.command=None
    def check_auth_password(self,username,password):
        return paramiko.AUTH_SUCCESSFUL if username=='local-test' and password==SECRET else paramiko.AUTH_FAILED
    def get_allowed_auths(self,username):
        return 'password'
    def check_channel_request(self,kind,chanid):
        return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_exec_request(self,channel,command):
        self.command=command.decode()
        self.event.set()
        return True

def serve(listener, done):
    transports=[]
    def connection(client):
        transport=paramiko.Transport(client)
        transports.append(transport)
        transport.add_server_key(KEY)
        handler=Server()
        try:
            transport.start_server(server=handler)
            channel=transport.accept(3)
            if channel is None or not handler.event.wait(3):
                return
            if handler.command=='slow-test':
                time.sleep(2)
            elif handler.command=='large-output':
                for _ in range(8):
                    channel.sendall(b'x'*8192)
                    channel.sendall_stderr(b'y'*8192)
            else:
                channel.sendall((handler.command+' '+SECRET).encode())
                channel.sendall_stderr(b'local stderr')
            if not channel.closed:
                channel.send_exit_status(0)
                channel.close()
        except (EOFError,OSError,paramiko.SSHException):
            pass
        finally:
            transport.close()
    listener.settimeout(0.2)
    while not done.is_set():
        try:
            client,_=listener.accept()
        except socket.timeout:
            continue
        threading.Thread(target=connection,args=(client,),daemon=True).start()
    for transport in transports:
        transport.close()

def main():
    checks=[]
    with tempfile.TemporaryDirectory(prefix='esxi-mcp-ssh-test-') as directory:
        root=Path(directory)
        cfg=Config(host='127.0.0.1',user='local-test',password='API_TEST_PASSWORD',connect_timeout=3,
                   ssh_credentials_file=str(root/'ssh.json'),state_dir=str(root/'state'))
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0))
            listener.listen()
            doc={'host':cfg.host,'port':listener.getsockname()[1],'user':cfg.user,'password':SECRET,
                 'host_key_sha256':hashlib.sha256(KEY.asbytes()).hexdigest()}
            Path(cfg.ssh_credentials_file).write_text(json.dumps(doc))
            done=threading.Event()
            thread=threading.Thread(target=serve,args=(listener,done),daemon=True)
            thread.start()
            try:
                command=admin.arguments_command(['system','version','get'])
                value=admin.run(cfg,command,3,4096)
                assert value['exit_code']==0 and value['stdout']==command+' [REDACTED]' and value['stderr']=='local stderr'
                checks.append({'check':'pinned_key_password_auth_command_and_secret_redaction','status':'PASS'})
                value=admin.run(cfg,'large-output',3,4096)
                assert value['output_truncated'] and len(value['stdout'])==4096 and len(value['stderr'])==4096
                checks.append({'check':'concurrent_stdout_stderr_drain_and_bounded_output','status':'PASS'})
                try:
                    admin.run(cfg,'slow-test',1,4096)
                    raise AssertionError('Expected command timeout')
                except ToolError as error:
                    assert 'uncertain' in str(error)
                checks.append({'check':'timeout_reports_uncertain_state','status':'PASS'})
                doc['host_key_sha256']='0'*64
                Path(cfg.ssh_credentials_file).write_text(json.dumps(doc))
                try:
                    admin.run(cfg,command,3,4096)
                    raise AssertionError('Expected host identity rejection')
                except paramiko.SSHException as error:
                    assert 'identity' in str(error)
                checks.append({'check':'mismatched_host_key_refused','status':'PASS'})
            finally:
                done.set()
                thread.join(2)
    return {'status':'PASS','backend':'ephemeral_loopback_ssh','production_connections':0,'checks':checks}

if __name__=='__main__':
    print(json.dumps(main(),indent=2))
