
const knownVulnerable = [
    { service: 'vsftpd 2.3.4', cve: 'CVE-2011-2523' },
    { service: 'UnrealIRCd', cve: 'CVE-2010-2075' },
    { service: 'OpenSSH 4.7', cve: 'CVE-2008-5161' },
    { service: 'Apache 2.2.8', cve: 'CVE-2009-1890' },
    { service: 'bindshell', cve: null },
    { service: 'MySQL 5.0.51', cve: 'CVE-2008-0226' },
    { service: 'telnet', cve: null },
    { service: 'PostgreSQL 8.3', cve: 'CVE-2007-3278' },
    { service: 'Apache Tomcat', cve: 'CVE-2019-0232' }
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
        let match= knownVulnerable.find(v=>p.service.includes(v.service))
        if (match){
            p.vulnerable=true
            p.cve=match.cve
        }})
}
report(){
    let report= `\n=== TARGET: ${this.ip} (${this.os}) ===\n`
    this.ports.forEach(p=>{let status=p.vulnerable ? 'vulnerable' : 'ok'
    let cve =p.cve ? ` [${p.cve}]` : ''
        report +=` port ${p.number} - ${p.service} [${status}]${cve}\n`
    })
    return report
}
}
let metasploitable=new Target('192.168.56.104','metasploitable 2')
metasploitable.addPort(21,'vsftpd 2.3.4')
metasploitable.addPort(22,'OpenSSH 4.7')
metasploitable.addPort(23,'telnet')
metasploitable.addPort(80,'Apache 2.2.8')
metasploitable.addPort(1524, 'bindshell')
metasploitable.addPort(3306, 'MySQL 5.0.51')
metasploitable.addPort(6667, 'UnrealIRCd')
metasploitable.addPort(5432, 'PostgreSQL 8.3')
metasploitable.addPort(8180, 'Apache Tomcat')
metasploitable.autocheck()
console.log(metasploitable.report())
