const knownvulnerabilities = [
    'vsftpd 2.3.4',
    'OpenSSH 4.7',
    'telnet',
    'Apache 2.2.8',
    'bindshell',
    'proftpd 1.3.5'
]

class Target{
    constructor(ip,os){
        this.ip=ip;
        this.os=os;
        this.ports=[];
    }
addPort(number,service){
    this.ports.push({number, service,vulnerable:false})
}
autocheck(){
    this.ports.forEach(p=>{
        if (knownvulnerabilities.includes(p.service)) p.vulnerable=true;
    })
}
report(){
    let report= `\n=== TARGET: ${this.ip} (${this.os}) ===\n`
    this.ports.forEach(p=>{let status=p.vulnerable ? 'vulnerable' : 'ok'
        report +=` port ${p.number} - ${p.service} [${status}]\n`
    })
    return report
}
}
let metasploitable=new Target('192.168.56.104','metasploitable 2')
metasploitable.addPort(21,'vsftpd 2.3.4')
metasploitable.addPort(22,'OpenSSH 4.7')
metasploitable.addPort(23,'telnet')
metasploitable.addPort(80,'Apache 2.2.8')
metasploitable.autocheck()
console.log(metasploitable.report())
