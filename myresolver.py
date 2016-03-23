import argparse
import time
import dns.resolver
import dns.message
import dns.query
import dns.name
import dns.rdatatype
from collections import defaultdict


class Resolver:
    def __init__(self):
        self.referral_cache = defaultdict(dict)
        root_name = dns.name.from_text('.')
        root_nameservers = dns.resolver.query(root_name, dns.rdatatype.NS)
        self.referral_cache[root_name][dns.rdatatype.NS] = root_nameservers.rrset
        for nameServer in root_nameservers.rrset:
            nameserver_ips = dns.resolver.query(nameServer.target, dns.rdatatype.A)
            self.referral_cache[nameServer.target][dns.rdatatype.A] = nameserver_ips.rrset
        self.answer_cache = defaultdict(dict)

    def resolve(self, domain, record):
        record_type = dns.rdatatype.from_text(record)
        nameservers = None
        response = None
        domain_tokens = domain.split('.')
        for index in range(len(domain_tokens)):
            domain_name = dns.name.from_text('.'.join(domain_tokens[index:]))
            if index is 0 and domain_name in self.answer_cache and record_type in self.answer_cache[domain_name]:
                print('*** QUERY ' + domain + ' for RRType ' + record)
                print('*** Answer found in Cache')
                start = time.time()
                response = self.answer_cache[domain_name][record_type]
                end = time.time()
                print('*** FINAL RESPONSE found with latency  ' + str(end - start), end='\n\n')
                print(response, end='\n\n')
                return
            else:
                if domain_name in self.referral_cache and dns.rdatatype.NS in self.referral_cache[domain_name]:
                    nameservers = self.referral_cache[domain_name][dns.rdatatype.NS]
                    break;
        if nameservers is None:
            nameservers = self.referral_cache[dns.name.from_text('.')][dns.rdatatype.NS]
        print('*** NS records fetched from cache: [' + ', '.join("'" + ns.to_text() + "'" for ns in nameservers) + ']')
        response = self._resolve(domain, record, nameservers, False)
        print(response, end='\n\n')
        prev_response = None
        while not response.answer and prev_response != response:
            prev_response = response
            for authority in response.authority:
                self.referral_cache[authority.name][authority.rdtype] = authority
            for additional in response.additional:
                self.referral_cache[additional.name][additional.rdtype] = additional
            for authority in response.authority:
                if authority.rdtype is dns.rdatatype.NS:
                    nameservers = authority.items
                    print("*** Start next iteration with domain '" + authority.name.to_text() + "' nameservers " + '[' + ', '.join("'" + ns.to_text() + "'" for ns in nameservers) + ']')
                    response = self._resolve(domain, record, authority.items, False)
                    if not response is None:
                        print(response, end='\n\n')
                        break;
        for answer in response.answer:
            if answer.rdtype is dns.rdatatype.CNAME:
                print('*** Chase CNAME')
                for item in answer:
                    self.resolve(item.target.to_text(), record)
                    return
        print('_____________________________________________________', end='\n\n')
        print('*** QUERY ' + domain + ' for RRType ' + record)
        response = self._resolve(domain, record, nameservers, True)
        if not response is None:
            domain_name = dns.name.from_text(domain)
            self.referral_cache[domain_name][dns.rdatatype.NS] = nameservers
            self.answer_cache[domain_name][record_type] = response
            print(response, end='\n\n')

    def _resolve(self, domain, record, nameservers, final):
        for ns in nameservers:
            response = None
            try:
                ns = self.referral_cache[ns.target][dns.rdatatype.A]
                ns_name = ns.name.to_text()
                ns_address = ns.items[0].address
                if not final:
                    print("*** Nameserver '" + ns_name + "' has IP addresses ['" + ns_address + "']:")
                    print("*** QUERY name server '" + ns_name + "' at " + ns_address + " for '" + domain + "' '" + record + "'")
                start = time.time()
                response = self.query(domain, record, ns)
                end = time.time()
                if not final:
                    print('*** Response received with latency:  ' + str(end - start))
                else:
                    print('*** FINAL RESPONSE found with latency  ' + str(end - start), end='\n\n')
            except dns.exception.Timeout:
                response = None
                continue
            return response

    def query(self, domain, record, nameserver):
        domain_name = dns.name.from_text(domain)
        record_type = dns.rdatatype.from_text(record)
        query = dns.message.make_query(domain_name, record_type, want_dnssec=True)
        response = dns.query.udp(query, nameserver.items[0].address)
        return response

    def _printcache(self, cache):
        for name, values in cache.items():
            print(name.to_text() + ' :')
            for type, data in values.items():
                print(dns.rdatatype.to_text(type), end=' :  ')
                print('[' + ', '.join("'" + r.to_text() + "'" for r in data) + ']\n')

    def printcache(self):
        print('Answer Cache Contents:\n')
        self._printcache(self.answer_cache)
        print('Referral Cache Contents:\n')
        self._printcache(self.referral_cache)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('commandfile', metavar='c', type=str, help='Command file')
    args = parser.parse_args()

    resolver = Resolver()
    with open(args.commandfile, 'r') as f:
        for line in f:
            print('COMMAND:  ' + line)
            line = line.split(sep=' ')
            cmd = line[0]
            if cmd != 'quit':
                arg1 = line[1]
                if cmd == 'print' and arg1 == 'cache\n':
                    resolver.printcache()
                elif cmd == 'resolve':
                    domain = arg1
                    record = line[2].replace('\n', '')
                    resolver.resolve(domain, record)
                else:
                    print('Unknown command.\n')
                print('***************************************************\n')
            else:
                print('Program terminated\n')
                exit(0)

main()