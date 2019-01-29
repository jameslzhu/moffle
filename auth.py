from urllib.parse import unquote, urlparse
from flask import Blueprint
from flask import flash
from flask import redirect
from flask import request
from flask import session
from flask import url_for
#from flask_oauthlib.client import OAuth
from authlib.flask.client import OAuth

import config

auth = Blueprint('auth', __name__, template_folder='templates')
oauth = OAuth()
google = oauth.register(
    name='GOOGLE',
    client_id=config.GOOGLE_OAUTH_CONSUMER_KEY,
    client_secret=config.GOOGLE_OAUTH_CONSUMER_SECRET,
    request_token_url=None,  # OAuth 2
    request_token_params={
        'scope': 'https://www.googleapis.com/auth/userinfo.email'
    },
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    
    # authlib fn registry
    fetch_token=get_google_oauth_token,
)

def get_google_oauth_token():
    return session.get('google_token')


@auth.route('/')
@auth.route('/login')
def login():
    next_path = request.args.get('next')
    if next_path:
        # Since passing along the "next" URL as a GET param requires
        # a different callback for each page, and Google requires us to
        # whitelist each allowed callback page, we can't pass it as a GET
        # param. Instead, we sanitize and put into the session.
        request_components = urlparse(request.url)
        path = unquote(next_path)
        if path[0] == '/':
            # This first slash is unnecessary since we force it in when we
            # format next_url.
            path = path[1:]

        next_url = "{scheme}://{netloc}/{path}".format(
            scheme=request_components.scheme,
            netloc=request_components.netloc,
            path=path,
        )
        session['next_url'] = next_url
    redirect_uri = url_for('.authorized', _external=True)
    return google.authorize_redirect(redirect_uri)


@auth.route('/logout')
def logout():
    session.pop('google_token', None)
    session.pop('user', None)
    return redirect(url_for('index'))


@auth.route('/login/authorized')
def authorized():
    token = google.authorize_access_token()
    next_url = session.pop('next_url', url_for('index'))

    if resp is None:
        flash("You didn't sign in.")
        return redirect(next_url)

    session.permanent = True
    session['google_token'] = (token, '')
    session['user'] = google.get('userinfo').data
    return redirect(next_url)
