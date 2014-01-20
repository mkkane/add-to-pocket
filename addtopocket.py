# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os, re
import urllib, urlparse
import logging

from flask import Flask, request, session, g, redirect, url_for
import requests

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)
_logger = logging.getLogger()


###### Config ######

def load_dotenv_as_environ_defaults(path):
    '''Hepler to export any locally defined .env file as environment vars.'''
    try:
        with open(path) as f:
            content = f.read()
            _logger.info("loading local .env file => %s" % path)
    except IOError:
        content = ''
    for line in content.splitlines():
        m1 = re.match(r'\A([A-Za-z_0-9]+)=(.*)\Z', line)
        if m1:
            key, val = m1.group(1), m1.group(2)
            m2 = re.match(r"\A'(.*)'\Z", val)
            if m2:
                val = m2.group(1)
            m3 = re.match(r'\A"(.*)"\Z', val)
            if m3:
                val = re.sub(r'\\(.)', r'\1', m3.group(1))
            _logger.debug("Setting env default: %s = %s" % (key, val))
            os.environ.setdefault(key, val)

load_dotenv_as_environ_defaults(os.path.join(os.path.dirname(__file__), '.env'))

# Read environ vars (for use with heroku)
app.config.setdefault('SECRET_KEY', os.environ.get('SECRET_KEY'))
app.config.setdefault('SQLALCHEMY_DATABASE_URI', os.environ.get('SQLALCHEMY_DATABASE_URI'))
app.config.setdefault('POCKET_APP_CONSUMER_KEY', os.environ.get('POCKET_APP_CONSUMER_KEY'))


###### Basic Setup ######

# @bp.teardown_request
# def shutdown_session(exception=None):
#     '''Ensure the database connection is released'''
#     db_session.remove()

# @bp.before_request
# def set_current_user(user=None):
#     g.user = None

#     if user:
#         session['user_id'] = user.id
#         g.user = user

#     if 'user_id' in session:
#         g.user = Person.query.get(session['user_id'])


###### Helpers ######

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('.login'))
        return f(*args, **kwargs)
    return decorated_function

POCKET_API_BASE = 'https://getpocket.com/v3/'

def pocket_request(path, data=None):
    '''Make a request to the pocket API.

    We only need to consider POST as Pocket only takes POST.  And we want to
    always get a json respose so let's set appropriate headers for that.
    '''
    url = urlparse.urljoin(POCKET_API_BASE, path)
    headers = {'X-ACCEPT': 'application/json'}

    return requests.post(url, data, headers=headers)


###### Login / Logout / Signup ######

@app.route('/login')
def login():
    callback_url = url_for('.oauth_login_callback', _external=True)

    # Get an oauth request token from pocket
    request_token_response = pocket_request('oauth/request', data={
            'consumer_key': app.config['POCKET_APP_CONSUMER_KEY'],
            'redirect_uri': callback_url
    })
    request_token = request_token_response.json()['code']

    # Save the request token in user session
    session['request_token'] = request_token

    # Redirect the user to the authorization url
    authentication_url = 'https://getpocket.com/auth/authorize' \
        + '?request_token=%s' % urllib.quote_plus(request_token) \
        + '&redirect_uri=%s' % urllib.quote_plus(callback_url)

    return redirect(authentication_url)

@app.route('/oauth-login-callback')
def oauth_login_callback():
    # When we get here, there should be a request token in the users session for
    # us to exchange with an access token.

    # Get an oauth access token from pocket
    access_token_response = pocket_request('oauth/authorize', data={
            'consumer_key': app.config['POCKET_APP_CONSUMER_KEY'],
            'code': session.pop('request_token')
    })
    response_data = request_token_response.json()

    access_token = response_data['access_token']
    username = response_data['username']

    _logger.debug(response_data)
    
    return redirect(url_for('.home'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.clear()
    return redirect(url_for('.home'))


###### Pages ######

@app.route('/')
def home():
    return 'Hi there!' #render_template('home.html')



###### Run Dev ######
if __name__ == "__main__":
    app.run(debug=True)

