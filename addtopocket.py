# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os, re
import urllib, urlparse
import logging
from datetime import datetime

from flask import (
    Flask, request, session, g, redirect, url_for, render_template, flash
)
from flask.ext.sqlalchemy import SQLAlchemy
import requests
from bs4 import BeautifulSoup
from dateutil import parser as date_parser

###### Logging ######

logging.basicConfig(level=logging.DEBUG)
_logger = logging.getLogger()

###### Config ######

def _load_dotenv_as_environ_defaults(path):
    '''Hepler to export any locally defined .env file as environment vars.

    This allows compatibily between running on Heroku and in dev.
    '''
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

_load_dotenv_as_environ_defaults(os.path.join(os.path.dirname(__file__), '.env'))

# Read environ vars (for use with heroku)
_config = {
    'SECRET_KEY': os.environ.get('SECRET_KEY'),
    'SQLALCHEMY_DATABASE_URI': os.environ.get('SQLALCHEMY_DATABASE_URI'),
    'POCKET_APP_CONSUMER_KEY': os.environ.get('POCKET_APP_CONSUMER_KEY')
}


###### Init ######

app = Flask(__name__)
app.config.update(_config)
db = SQLAlchemy(app)


###### Basic Setup ######

@app.before_request
def set_current_user(user=None):
    g.user = None

    if user:
        session['user_id'] = user.id
        g.user = user
    
    elif session.get('user_id', None):
        g.user = Person.query.get(session['user_id'])


###### Helpers ######

POCKET_API_BASE = 'https://getpocket.com/v3/'

def pocket_request(path, data=None):
    '''Make a request to the pocket API.

    We only need to consider POST as Pocket only takes POST.  And we want to
    always get a json respose so let's set appropriate headers for that.
    '''
    url = urlparse.urljoin(POCKET_API_BASE, path)
    headers = {'X-ACCEPT': 'application/json'}

    return requests.post(url, data, headers=headers)

AEON_FEED_URL = 'http://feeds.feedburner.com/AeonMagazineEssays'

def get_aeon_rss_soup():
    return BeautifulSoup(requests.get(AEON_FEED_URL).text)

def import_latest_aeon_articles():
    # Retreive the feed
    soup = get_aeon_rss_soup()

    # Iterate over each item in the feed
    for item in soup.find_all('item'):
        # If we already know about this article we can ignore it
        if Article.query.filter_by(guid=item.guid.text).count():
            continue

        _logger.info('Importing Article: %s' % item.text)

        article = Article()
        article.guid = item.guid.text
        article.title = item.title.text
        article.link = item.link.text
        article.pubdate = date_parser.parse(item.pubdate.text)
        article.raw_feed = item.text
        db.session.add(article)

    db.session.commit()

# Need extra consumer app permissions...
# def push_articles_for_user(user, articles):
#     data = {
#         'consumer_key': app.config['POCKET_APP_CONSUMER_KEY'],
#         'access_token': user.access_token,
#         'actions': []
#     }
#     for article in articles:
#         data['actions'].append({
#                 'action': 'add',
#                 'url': article.link
#         })
#     resp = pocket_request('send', data=data)
#     return resp

def push_article_for_user(user, article):
    data = {
        'consumer_key': app.config['POCKET_APP_CONSUMER_KEY'],
        'access_token': user.access_token,
        'url': article.link
    }
    resp = pocket_request('add', data=data)

    _logger.debug(resp)

    return resp.ok


###### Pages ######

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

    # Did they actually sign in and authorize us?  If not, get them back to the
    # home page -- but log them out first, just in case.
    if not (access_token_response.ok):
        return redirect(url_for('.logout'))

    response_data = access_token_response.json()
    access_token = response_data.get('access_token', None)
    username = response_data.get('username', None)

    # Try to find the user
    user = Person.query.filter_by(username=username).first()

    # Create new user if they're new
    if not user:
        user = Person()
        user.username = username
        db.session.add(user)
        _logger.info('New User: %s' % user.username)

    # Ensure we have their latest access_token
    user.access_token = access_token
    db.session.commit()
    
    # And log them in
    set_current_user(user)
    
    return redirect(url_for('.home'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.clear()
    return redirect(url_for('.home'))


@app.route('/')
def home():
    articles = None
    if g.user:
        articles = Article.query.order_by('pubdate DESC').all()

    return render_template('home.html', articles=articles)


@app.route('/import-latest-articles')
def import_latest_articles():
    old_count = Article.query.count()
    import_latest_aeon_articles()
    new_count = Article.query.count() - old_count
    flash('%s new articles found' % new_count, 'info')
    return redirect(url_for('.home'))


@app.route('/push-article-to-pocket/<int:article_id>')
def push_article_to_pocket(article_id=None):
    if not g.user:
        flash('Sorry, you need to be logged in to do that!', 'danger')
        return redirect(url_for('home'))

    article = Article.query.get(article_id)
    if not article:
        flash('Sorry, I don\'t know what article you\'re talking about!', 
              'danger')
        return redirect(url_for('home'))

    if push_article_for_user(g.user, article):
        flash('%s added to your pocket' % article.title, 'success')
    else:
        flash('Hmm, something went wrong!', 'danger')
    return redirect(url_for('.home'))


@app.route('/import-and-push-latest-articles')
def import_and_push_latest_articles():
    import_latest_aeon_articles()

    articles_to_push = Article.query\
        .filter_by(status='pending')\
        .order_by('pubdate ASC')\
        .all()
    people_to_recieve = Person.query.filter_by(status='active').all()

    for article in articles_to_push:
        for person in people_to_recieve:
            push_article_for_user(person, article)
        article.status = 'pushed'

    db.session.commit()
    return 'done'



###### Models ######

class Person(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    access_token = db.Column(db.String, nullable=False)
    status = db.Column(db.String, default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, 
                           nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, 
                           onupdate=datetime.utcnow, nullable=False)

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    guid = db.Column(db.String, nullable=False)
    title = db.Column(db.String, nullable=False)
    link = db.Column(db.String, nullable=False)
    pubdate = db.Column(db.DateTime, nullable=False)
    raw_feed = db.Column(db.String)
    status = db.Column(db.String, default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, 
                           nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, 
                           onupdate=datetime.utcnow, nullable=False)


###### Run Dev ######
if __name__ == "__main__":
    app.run(debug=True)

