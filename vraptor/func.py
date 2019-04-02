from libs import *



def log_info(msg):
    print('INFO', msg)
    sys.stdout.flush()



def log_err(msg = ''):
    print('WARN', msg, traceback.format_exc().replace('\n', ' | '))
    sys.stdout.flush()



def es_exists(_index, _id):
    return es.exists(index = _index, doc_type = 'doc', id = _id, request_timeout = 30)



def es_index(_index, _id, _body):
    return es.index(index = _index, doc_type = 'doc', id = _id, body = _body, request_timeout = 30)



def is_open(ip, port):
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.settimeout(2)
   try:
      s.connect( (ip, port) )
      s.shutdown(2)
      return True
   except:
      return False



def is_reverse(hostname):
        return tldextract.extract(hostname).suffix in [ 'ip6.arpa', 'in-addr.arpa' ]



def digits_(string):
    return re.sub( '[^0-9]' , '', string )



def public_ip(ip_adress):
    try:
        return IP(ip_adress).iptype() == 'PUBLIC'
    except:
        return False



def asteriscos(password, percent = 60):
    limit = int(round(len(password) * percent / 100.))
    return password[:limit] + '*' * (len(password) - limit)



def verify_bcypt(username, password, users):
    try:
        hashed = users[username]
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except:
        return False



def validate_jira_user(username, password):
    try:
        url = 'https://portal.axur.com/rest/auth/1/session'
        r = requests.head(url, auth = (username, password))
        return r.status_code == 200
    except:
        log_err()        
        return False



def ip_address(host):
    try:
        answer = resolver.query(host, "A")
        return [ i.address for i in answer ]
    except:
        return []



def is_up_and_open(host):
    try:
        ip = socket.gethostbyname(host)
        return is_open(ip, 80) or is_open(ip, 443)
    except:
        return False



def remove_brackets(line):
    return line.replace(']', '').replace('[', '')



def get_domain(hostname):
    return tldextract.extract(hostname).registered_domain



def valid_host(hostname):
    try:
        return get_domain(hostname) and '.'.join(tldextract.extract(hostname)).lstrip('.') == hostname.rstrip('.')
    except:
        return False



def is_domain(hostname):
    return hostname == tldextract.extract(hostname).registered_domain



def soa_responsible(domain):
    try:
        resolver.query(domain, 'SOA')
        return True
    except:
        return False    



def is_up(host):
    try:
        return socket.gethostbyname(host)
    except:
        return False



def get_all_s3_keys(bucket, prefix):
    keys = []
    kwargs = {'Bucket': bucket, 'Prefix': prefix}
    while True:
        resp = s3_client.list_objects_v2(**kwargs)
        for obj in resp['Contents']:
            keys.append(obj['Key'])
        try:
            kwargs['ContinuationToken'] = resp['NextContinuationToken']
        except KeyError:
            break
    return keys



def get_s3_keys_as_generator(bucket):
    kwargs = {'Bucket': bucket}
    while True:
        resp = s3_client.list_objects_v2(**kwargs)
        for obj in resp['Contents']:
            yield obj['Key']
        try:
            kwargs['ContinuationToken'] = resp['NextContinuationToken']
        except KeyError:
            break



def get_matching_s3_objects(bucket, prefix='', suffix=''):
    s3 = boto3.client('s3')
    kwargs = {'Bucket': bucket}
    if isinstance(prefix, str):
        kwargs['Prefix'] = prefix
    while True:
        resp = s3.list_objects_v2(**kwargs)
        try:
            contents = resp['Contents']
        except KeyError:
            return
        for obj in contents:
            key = obj['Key']
            if key.startswith(prefix) and key.endswith(suffix):
                yield obj
        try:
            kwargs['ContinuationToken'] = resp['NextContinuationToken']
        except KeyError:
            break



def get_matching_s3_keys(bucket, prefix='', suffix=''):
    for obj in get_matching_s3_objects(bucket, prefix, suffix):
        yield obj['Key']



# def is_older_host(hostname, timestamp):
#     if int(es.get(index = 'hosts_', doc_type = 'doc', id = hostname)['_source']['created']) > timestamp:
#         send_to_es_hosts(hostname, timestamp)



# def is_older_domain(domain, timestamp):
#     if int(es.get(index = 'domains_', doc_type = 'doc', id = domain)['_source']['created']) > timestamp:
#         send_to_es_domains(domain, timestamp)



# def proc_domain(domain, timestamp):
#     if es.exists(index = 'domains_', doc_type = 'doc', id = domain):
#         is_older_domain(domain, timestamp)
#     elif soa_responsible(domain):
#         send_to_es_domains(domain, timestamp)



# def proc_host(hostname, timestamp):
#     if es.exists(index = 'hosts_', doc_type = 'doc', id = hostname):
#         is_older_host(hostname, timestamp)
#     elif is_up(hostname):
#         send_to_es_hosts(hostname, timestamp)


