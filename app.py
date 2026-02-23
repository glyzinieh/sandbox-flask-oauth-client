import secrets

from authlib.integrations.flask_client import OAuth, OAuthError
from flask import Flask, redirect, session, url_for

app = Flask(__name__)
app.config.from_prefixed_env()
app.secret_key = "your_random_secret_key"

oauth = OAuth(app)
oauth.register(
    name="cicceno_id",
    client_id=app.config["OIDC_CLIENT_ID"],
    client_secret=app.config["OIDC_CLIENT_SECRET"],
    server_metadata_url=app.config["OIDC_SERVER_METADATA_URL"],
    client_kwargs={"scope": "openid profile email"},
)


@app.route("/")
def index():
    user = session.get("user")
    if user:
        return f"Hello, {user['profile']['name']}! <a href='/logout'>Logout</a>"
    return "Hello, Guest! <a href='/login'>Login</a>"


@app.route("/login")
def login():
    redirect_uri = url_for("authorize", _external=True)
    nonce = secrets.token_urlsafe(16)
    session["nonce"] = nonce
    return oauth.cicceno_id.authorize_redirect(redirect_uri, nonce=nonce)


@app.route("/authorize")
def authorize():
    try:
        token = oauth.cicceno_id.authorize_access_token()
    except OAuthError as e:
        return f"OAuth error: {e.error} - {e.description}"
    user_info = oauth.cicceno_id.parse_id_token(token, nonce=session.get("nonce"))
    session["user"] = user_info
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True, port=5000, reload=True)
