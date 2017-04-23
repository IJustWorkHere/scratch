# -*- coding: utf-8 -*-
#!/usr/bin/env python

import os
import re
import json
import stat
import requests
import socket
import random
import base64
from jinja2 import Template
from Crypto.Cipher import AES

# Confluence Variables
BASE_URL = "http://confluence/rest/api/content"
VIEW_URL = "http://confluence/pages/viewpage.action?pageId="
PAGE_ID  = 1234 # Put page id here

# Comman Variables
hostname = socket.getfqdn()
sudoer_files = ['/etc/sudoers']
sudoers_d = '/etc/sudoers.d'

# Iterate sudoers.d looking for additional conf files.  Move on if the directory doesn't exist
try:
    [sudoer_files.append(os.path.join(sudoers_d, file)) for file in os.listdir(sudoers_d)]
except OSError:
    pass

# Secret Variables
marker = 'SALT_'
ivfile   = "/path/to/iv"
keyfile  = "/path/to/key"
passfile = "/path/to/pass"



### HANDLE SECRETS ###
def get_mode_uid_gid(file):
    '''
    Get the mode, uid, gid of a file
    '''
    uid = -1
    gid = -1
    mode = 0000
    if os.path.exists(file):
        st = os.lstat(file)
        uid = st.st_uid
        gid = st.st_gid
        mode = stat.S_IMODE(st.st_mode)
    return uid, gid, mode

def set_mode_uid_gid(file, uid=None, gid=None, mode=None):
    '''
    Set the mode, uid, gid of a file
    '''
    if os.path.exists(file):
        if uid or gid:
            if uid is None:
                uid = -1
            if gid is None:
                gid = -1
            os.chown(file, uid, gid)
        if mode:
            os.chmod(file, mode)

def validate_and_correct_file_perms():
    '''
    Validate that protected files are root:root 400.  If not correct it
    '''
    files  = [ ivfile, keyfile, passfile ]
    for file in files:
        uid, gid, mode = get_mode_uid_gid(file)
        if mode > 400:
            set_mode_uid_gid(file, mode=400)
        if uid != 0 or gid != 0:
            set_mode_uid_gid(file, uid=0, gid=0)

def generate_random(rng):
    '''
    Does just what you would expect... it generates a random array of characters rng long
    '''
    return ''.join(chr(random.randint(0, 0xFF)) for i in range(rng))

def write_file(file, contents):
    '''
    Writes contents to file as binary
    '''
    with open(file, 'wb') as f:
        f.write(contents)

def read_file(file):
    '''
    Reads contents from file as binary
    '''
    with open(file, 'rb') as f:
        contents = f.read()
    return contents

def encrypt_password(key, iv, plaintext):
    '''
    AES encrypt a given string
    '''
    obj = AES.new(key, AES.MODE_CBC, iv)
    if len(plaintext) % 16 != 0:
        plaintext += ' ' * (16 - len(plaintext) % 16)
    ciphertext = obj.encrypt(plaintext)
    return ciphertext

def create_encrypted_value(value):
    '''
    Creates the necessary iv, key, ciphertext and saves them to file
    '''
    iv = generate_random(16)
    key = generate_random(32)
    ciphertext = encrypt_password(key, iv, value)
    b64enctext = base64.b64encode(marker + ciphertext)
    write_file(ivfile, iv)
    write_file(keyfile, key)
    write_file(passfile, b64enctext)

def get_password():
    '''
    Get the value of a password if it's already encrypted.  If it's not encrypted do so and return the plaintext value
    '''
    text = read_file(passfile).rstrip()
    b64dectext = base64.b64decode(text)
    if b64dectext.startswith(marker):
        iv = read_file(ivfile)
        key = read_file(keyfile)
        ciphertext = b64dectext.lstrip(marker)
        obj = AES.new(key, AES.MODE_CBC, iv)
        plaintext = obj.decrypt(ciphertext).rstrip()
    else:
        create_encrypted_value(text)
        plaintext = text
    validate_and_correct_file_perms()
    return plaintext

### CREATE RETURN HTML ###
def generate_html_block(host, roles):
    '''
    Returns a block of HTML representing the roles and permissions available on a given host
    '''
    template = Template("""<div class="hidden">START {{ hostname }}</div>\
<div class="table-wrap">\
<div class="table-wrap">\
<div class="table-wrap">\
<table class="confluenceTable">\
<tbody>\
<tr>\
<th class="confluenceTh" colspan="2"><br/>{{ hostname }}</th>\
</tr>\
<tr>\
<th class="confluenceTh">ROLE</th>\
<th class="confluenceTh">AVAILABLE COMMANDS</th>\
</tr>\
 {% for role, commands in roles.iteritems() %}\
<tr>\
<td class="confluenceTd">{{ role }}</td>\
<td class="confluenceTd">{% for command in commands %}{{ command }}{{ '' if loop.last else ',' }}{% endfor %}</td>\
</tr>\
 {% endfor %}\
</tbody>\
</table>\
</div>\
</div>\
</div>\
<div class="hidden">END {{ hostname }}</div>""")
    result = template.render(hostname=host, roles=roles)
    return str(result)

def generate_generic_html_block():
    block = """<div class="table-wrap">\
<div class="table-wrap">\
</div>\
</div>"""
    return block

def remove_text(text, start_remove, end_remove):
    '''
    Return a new string with the selected text removed
    '''
    return text[:start_remove] + text[end_remove:]

def insert_text(original_text, position, additional_text):
    """
    Returns a new string with the additional_text inserted at position of original_text
    """
    return original_text[:position] + additional_text + original_text[position:]

def get_text_position(text, string_to_find):
    '''
    Returns the start of a found string.  If the string is not found will raise a ValueError: substring not found
    '''
    return text.index(string_to_find)

def get_end_blocks(text):
    '''
    Returns a list of all matches
    '''
    pattern = '<div class="hidden">END [\w\d\.]+</div>'
    return re.findall(pattern, text)

def get_new_location(text, host):
    '''
    If a host does not already exist on the page determine where to place it
    '''
    host_string = '<div class="hidden">END {0}</div>'.format(host)
    end_blocks = get_end_blocks(text)
    end_blocks.append(host_string)
    end_blocks.sort()
    previous = end_blocks.index(host_string) - 1
    if previous >= 0:
        return re.search(end_blocks[previous], text).end()
    else:
        # This is the first host on a page
        return 48

def contains_host(host, text):
    '''
    Validate a host exists on the page
    '''
    if re.search(host, text):
        return True

def remove_existing_host_html(html, host):
    '''
    Removes a block of text from the div start marker to the end of the div end marker for a host
    '''
    start = '<div class="hidden">START {0}</div>'.format(host)
    end   = '<div class="hidden">END {0}</div>'.format(host)
    start_location = get_text_position(html, start)
    end_location   = get_text_position(html, end) + len(end)
    return remove_text(html, start_location, end_location)

def update_existing_host(html, host, roles):
    '''
    Removes the existing hosts HTML block and recreates it
    '''
    start_block = '<div class="hidden">START {0}</div>'.format(host)
    position = get_text_position(html, start_block)
    html = remove_existing_host_html(html, host)
    additional_html = generate_html_block(host, roles)
    return insert_text(html, position, additional_html)

def create_new_host(html, host, roles):
    '''
    Create a new host HTML block from the generic template or from the existing page
    '''
    end_blocks = get_end_blocks(html)
    if len(end_blocks) == 0:
        html = generate_generic_html_block()
        position = 48
    else:
        position = get_new_location(html, host)

    additional_html = generate_html_block(host, roles)
    return insert_text(html, position, additional_html)

def update_html_host_block(html, host, roles):
    '''
    Determine if a host is new or exists and call appropriate function
    '''
    if contains_host(host, html):
        return update_existing_host(html, host, roles)
    else:
        return create_new_host(html, host, roles)

### PARSE SUDOERS FILES ###
def _command_generator(line):
    '''
    Generator that will return the commands allowed for a role
    '''
    text = re.match('.*=(.*)', line).group(1).lstrip('NOPASSWD:').lstrip('NOPASSWD:').lstrip('(ALL)')
    for _ in text.split(','):
        yield _.lstrip().rstrip()

def _get_role(line):
    '''
    Return a string containing a NITC role from a line
    '''
    return re.match('%([^\s]+)', line).group(1)

def _get_commands(line):
    '''
    Returns a list of available commands from a given line
    '''
    commands = list()
    if line.upper().rstrip().endswith('ALL'):
        return ['ALL']
    for command in _command_generator(line):
        commands.append(command)
    return commands

def _remove_comments_and_blank_lines(file):
    '''
    Clean the file up a little before processing
    '''
    cleaned = list()
    previous_line = ""
    with open(file, 'r+') as f:
        sudoers = f.read()
    for line in sudoers.splitlines():
        if re.match('^#|^$', line):
            continue
        elif re.match('.*\\\\$', line.rstrip()):
            previous_line += line.lstrip().rstrip('\\')
        elif previous_line != "":
            previous_line += line.lstrip()
            cleaned.append(previous_line)
            previous_line = ""
        else:
            cleaned.append(line.lstrip().rstrip())
    return cleaned

def _remove_non_roles(cleaned):
    '''
    Removes non roles and returns a dict of roles to commands
    '''
    role_to_caps = dict()
    for line in cleaned:
        if line.startswith('%'):
            role = _get_role(line)
            commands = _get_commands(line)
            role_to_caps[role] = commands
    return role_to_caps

def get_page_content(auth, pageid):
    '''
    Get the contents from a Confluence page
    '''
    url = '{0}/{1}?expand=body.view'.format(BASE_URL, pageid)
    r = requests.get(url, auth = auth)
    r.raise_for_status()
    return r.json()['body']['view']['value'].encode('utf8')

def get_page_ancestors(auth, pageid):
    '''
    Get page ancestors.
    '''
    url = '{base}/{pageid}?expand=ancestors'.format(
            base = BASE_URL,
            pageid = pageid)

    r = requests.get(url, auth = auth)
    r.raise_for_status()
    return r.json()['ancestors']


def get_page_info(auth, pageid):
    '''
    Get information about the page and return it as json
    '''
    url = '{base}/{pageid}'.format(
            base = BASE_URL,
            pageid = pageid)

    r = requests.get(url, auth = auth)
    r.raise_for_status()
    return r.json()


def write_data(auth, html):
    '''
    Write the new content to the Confluence page
    '''
    pageid = PAGE_ID
    info = get_page_info(auth, pageid)
    ver = int(info['version']['number']) + 1
    ancestors = get_page_ancestors(auth, pageid)
    anc = ancestors[-1]
    del anc['_links']
    del anc['_expandable']
    del anc['extensions']

    data = {
        'id' : str(pageid),
        'type' : 'page',
        'title' : info['title'],
        'version' : {'number' : ver},
        'ancestors' : [anc],
        'body'  : {
            'storage' :
                {
                    'representation' : 'storage',
                    'value' : str(html),
                }
        }
    }

    data = json.dumps(data)
    url = '{base}/{pageid}'.format(base = BASE_URL, pageid = pageid)

    r = requests.put(
            url,
            data = data,
            auth = auth,
            headers = { 'Content-Type' : 'application/json' }
    )
    r.raise_for_status()

def get_login():
    '''
    Returns username/password as a tuple
    '''
    username = 'user'
    passwd = get_password()
    return (username, passwd)


def main():
    roles = dict()
    for file in sudoer_files:
        cleaned = _remove_comments_and_blank_lines(file)
        roles.update(_remove_non_roles(cleaned))

    auth = get_login()
    current_html_document = get_page_content(auth, PAGE_ID)
    html = update_html_host_block(current_html_document, hostname, roles)
    write_data(auth, html)


if __name__ == "__main__" :
    main()
