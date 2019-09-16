from vraptor_libs import *



one_minute = 60
one_hour = one_minute * 60
one_day = one_hour * 24
one_week = one_day * 7
one_month = one_day * 30



def get_mx(host):
    try:
        mx_record = resolver.query(host, 'MX')
        return [exchange.to_text().split() for exchange in mx_record]
    except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers):
        return []



def base64_decode(bytestring):
    try:
        return base64.decodebytes(bytestring)
    except:
        return False



def gen_token_jwt(payload, secret):
    return jwt.encode(payload, secret, algorithm = 'HS256').decode()



def get_env(s3_resource, bucket, key):
    env_file = s3_resource.Object(bucket, key).get()['Body'].read()
    return json.loads(env_file)



def log_info(msg):
    print('INFO', msg)
    sys.stdout.flush()



def log_err(msg = ''):
    print('WARN', msg, traceback.format_exc().replace('\n', ' | '))
    sys.stdout.flush()



def es_exists(_conn, _index, _id):
    return _conn.exists(index = _index, doc_type = 'doc', id = _id, request_timeout = 30)



def es_get(_conn, _index, _id):
    return _conn.get(index = _index, doc_type = 'doc', id = _id, request_timeout = 30)



def es_search(conn, index, query):
    res = conn.search(index = index, body = query, scroll = '12h', request_timeout = 30, size = 1000)
    while res['hits']['hits']:
        for doc in res['hits']['hits']:
            yield doc
        res = conn.scroll(scroll_id = res['_scroll_id'], scroll = '12h')



def es_index(_conn, _index, _id, _body):
    return _conn.index(index = _index, doc_type = 'doc', id = _id, body = _body, request_timeout = 30)



def es_update(_conn, _index, _id, _body):
    return _conn.update(index = _index, doc_type = 'doc', id = _id, body = _body, request_timeout = 30)



def es_create_index(_conn, _index, _mapping):
    setup = { 'settings' : { 'number_of_replicas': 0 } }
    _conn.indices.create(index = _index, body = setup)
    _conn.indices.put_mapping(index = _index, doc_type = 'doc', body = _mapping)



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
        return ipaddress.ip_address(ip_adress).is_global
    except:
        return False



def asteriscos(password, percent = 60):
    limit = int(round(len(password) * percent / 100.))
    return password[:limit] + '*' * len(password[limit:])



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



def get_domain(host):
    return tldextract.extract(host).registered_domain



def valid_host(host):
    try:
        return tldextract.extract(host).registered_domain
    except:
        return False



email_exp = re.compile(r'^[a-z0-9_+.-]+@[a-z0-9.-]+\.[a-z]{2,63}$', re.I)
def valid_email(email):
    if re.match(email_exp, email):
        return valid_host(email.split('@')[1])
    return False



def is_domain(host):
    return host == tldextract.extract(host).registered_domain



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



def send_email_ses(ses_client, source, dest, reply_to, subject, body_html):
    return ses_client.send_email(
        Source = source,
        Destination = { 'ToAddresses': dest },
        ReplyToAddresses = reply_to,
        Message = {
            'Body': {
                'Html': {
                    'Charset': "UTF-8",
                    'Data': body_html,
                },
                'Text': {
                    'Charset': "UTF-8",
                    'Data': subject,
                },
            },
            'Subject': {
                'Charset': "UTF-8",
                'Data': subject,
            },
        },
    )



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

