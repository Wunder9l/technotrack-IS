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
    'user-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0)'
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

class InputFieldsSelector(HTMLParser):
    inputs = {}
    order = []

    def handle_starttag(self, tag, attrs):
        if tag == 'input':
            temp_dict = {key: value for key, value in attrs if key in ('name', 'value')}
            self.inputs[temp_dict['name']] = temp_dict['value'] if 'value' in temp_dict else None
            self.order.append(temp_dict['name'])

    def set_credentials(self, username, password):
        self.inputs['username'] = username
        self.inputs['password'] = password

    def set_input (self, key, value):
        if key not in self.order:
            self.inputs[key] = value
            self.order.append(key)

    def remove_key(self, key):
        del self.inputs[key]
        self.order.remove(key)

    def get_inputs(self):
        return '&'.join(['{}={}'.format(key, self.inputs[key]) for key in self.order])
        # return '&'.join(['{}={}'.format(key, value) for key, value in self.inputs.items()])


# SETUP #
response = requests.get(setup_url, headers=headers)
print response.status_code, response.headers,
parser = InputFieldsSelector()
parser.feed(response.text)
update_cookies(headers, response)
# cookies = make_cookie(response.headers)
# if cookies:
#     headers['Cookie'] = cookies
headers['Referer'] = setup_url
headers['Content-Type']= 'application/x-www-form-urlencoded'
headers['Connection']= 'close'
# parser.set_input('create_db', 'Create+%2F+Reset+Database')
# response = requests.post(setup_url, 'create_db=Create+%2F+Reset+Database&user_token=83c7e31adfc0c5cbd4fe69221566c378', headers=headers)
sleep(0.2)
response = requests.post(setup_url, parser.get_inputs(), headers=headers)
update_cookies(headers, response)
print response.status_code, response.headers  # , response.text

# LOGIN #
sleep(0.2)
response = requests.get(login_url, headers=headers)
update_cookies(headers, response)
# print response.status_code, response.headers, response.text
parser = InputFieldsSelector()
parser.feed(response.text)
parser.remove_key('create_db')
parser.set_credentials('admin', 'password')
headers['Referer'] = login_url
print parser.inputs
sleep(0.2)
response = requests.post(login_url, parser.get_inputs(), headers=headers)
update_cookies(headers, response)
# print response.status_code, response.headers, response.text

# SET SECURITY LEVEL #
headers['Referer'] = base_url + '/index.php'
sleep(0.2)
response = requests.get(security_url, headers=headers)
update_cookies(headers, response)
parser = InputFieldsSelector()
parser.feed(response.text)
parser.set_input('security', 'low')
print parser.inputs
sleep(0.2)
response = requests.post(security_url, parser.get_inputs(), headers=headers)
update_cookies(headers, response)
# print response.status_code, response.headers, response.text
