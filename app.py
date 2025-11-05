from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, make_response, session as login_session
import os
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from DB_setup import Base, Issue, Vote, Comment, User
import random
import string
import json
import requests
import httplib2
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google.auth.transport.requests import Request

app = Flask(__name__)

# --------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------

CLIENT_SECRETS_FILE = "client_secrets.json"
with open(CLIENT_SECRETS_FILE, "r") as f:
    CLIENT_CONFIG = json.load(f)["web"]

CLIENT_ID = CLIENT_CONFIG["client_id"]
APPLICATION_NAME = "Civic_Eye"
APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# Database setup
engine = create_engine("sqlite:///Civic_Eye.db", connect_args={"check_same_thread": False})
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# --------------------------------------------------------------------------------
# MAIN PAGE
# --------------------------------------------------------------------------------

@app.route('/')
@app.route('/main')
def home():
    if 'logged_in' not in login_session:
        return redirect(url_for('welcome'))
    all_issues = session.query(Issue).all()
    all_votes = session.query(Vote).all()
    all_users = session.query(User).all()
    return render_template('index.html', Issue=all_issues, Vote=all_votes, User=all_users)


# --------------------------------------------------------------------------------
# LOGIN & LOGOUT
# --------------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        all_users = session.query(User).all()
        for u in all_users:
            if request.form['username'] == u.name and request.form['password'] == u.password:
                login_session['logged_in'] = True
                login_session['U_Id'] = u.id
                flash('You were logged in.')
                return redirect(url_for('home'))
        error = 'Invalid Credentials. Please try again.'
        return render_template('normallogin.html', error=error)
    else:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
        login_session['state'] = state
        return render_template('normallogin.html', error=error, STATE=state)


@app.route('/logout')
def logout():
    if 'logged_in' not in login_session:
        flash('You need to login first.')
        return redirect(url_for('login'))
    login_session.clear()
    flash('You were logged out.')
    return redirect(url_for('welcome'))


@app.route('/welcome')
def welcome():
    return render_template('welcome.html')


# --------------------------------------------------------------------------------
# USER MANAGEMENT
# --------------------------------------------------------------------------------

@app.route('/user/new/', methods=['GET', 'POST'])
def newUser():
    if 'logged_in' in login_session:
        flash('You need to logout first.')
        return redirect(url_for('logout'))
    if request.method == 'POST':
        all_users = session.query(User).all()
        for x in all_users:
            if x.name == request.form['UserName'] or x.email == request.form['Email']:
                error = 'Username or Email already exists.'
                return render_template('newuser.html', error=error)
        new_user = User(email=request.form['Email'], name=request.form['UserName'], password=request.form['Password'])
        session.add(new_user)
        session.commit()
        login_session['U_Id'] = new_user.id
        login_session['logged_in'] = True
        flash(f'Hello {request.form["UserName"]}')
        return redirect(url_for('home'))
    return render_template('newuser.html')


@app.route('/user/edit', methods=['GET', 'POST'])
def editUser():
    return render_template('edituser.html')


# --------------------------------------------------------------------------------
# ISSUE MANAGEMENT
# --------------------------------------------------------------------------------

@app.route('/issue/new/', methods=['GET', 'POST'])
def newIssue():
    if 'logged_in' not in login_session:
        flash('You need to login first.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_issue = Issue(
            author=login_session['U_Id'],
            title=request.form['I_Title'],
            content=request.form['I_Content'],
            lat=request.form['I_Lat'],
            lng=request.form['I_Lng'],
            image="url for image",
            type=request.form['I_Type'],
            anonFlag=request.form['I_AnonFlag']
        )
        session.add(new_issue)
        session.commit()
        return redirect(url_for('home'))
    return render_template('newIssue.html')


@app.route('/issue/<int:I_Id>/view')
def showDetailedIssue(I_Id):
    if 'logged_in' not in login_session:
        flash('You need to login first.')
        return redirect(url_for('login'))

    issue = session.query(Issue).filter_by(id=I_Id).one()
    comments = session.query(Comment).filter_by(id=I_Id).order_by(asc(Comment.sqNo)).all()
    author_user = session.query(User).filter_by(id=issue.author).one()
    author_name = author_user.name if issue.anonFlag != 1 else "Anonymous"

    return render_template(
        'showdetailedissue.html',
        Issue=issue, Comment=comments,
        like=issue.like, dislike=issue.dislike, Author=author_name
    )


@app.route('/issue/<int:I_Id>/edit/', methods=['GET', 'POST'])
def editIssue(I_Id):
    if 'logged_in' not in login_session:
        flash('You need to login first.')
        return redirect(url_for('login'))

    issue = session.query(Issue).filter_by(id=I_Id).one()
    if request.method == 'POST':
        for field in ['I_Title', 'I_Content', 'I_Lat', 'I_Lng', 'I_Type', 'I_AnonFlag']:
            if request.form.get(field):
                setattr(issue, field.split('_', 1)[1].lower(), request.form[field])
        session.commit()
        flash(f'Issue Successfully Edited {issue.title}')
        return redirect(url_for('showDetailedIssue', I_Id=I_Id))
    if issue.author != login_session['U_Id']:
        flash("You do not have permission to access this page!")
        return redirect(url_for('home'))
    return render_template('editissue.html', Issue=issue)


@app.route('/issue/<int:I_Id>/delete/', methods=['GET', 'POST'])
def deleteIssue(I_Id):
    if 'logged_in' not in login_session:
        flash('You need to login first.')
        return redirect(url_for('login'))

    issue = session.query(Issue).filter_by(id=I_Id).one()
    if request.method == 'POST':
        session.delete(issue)
        session.commit()
        return redirect(url_for('home'))
    return render_template('deleteissue.html', Issue=issue)


# --------------------------------------------------------------------------------
# COMMENT MANAGEMENT
# --------------------------------------------------------------------------------

@app.route('/comment/<int:I_Id>/new/', methods=['GET', 'POST'])
def newComment(I_Id):
    if 'logged_in' not in login_session:
        flash('You need to login first.')
        return redirect(url_for('login'))

    issue = session.query(Issue).filter_by(id=I_Id).one()
    user = session.query(User).filter_by(id=login_session['U_Id']).one()
    if request.method == 'POST':
        new_comment = Comment(content=request.form['C_Content'], user=user, issue=issue)
        session.add(new_comment)
        session.commit()
        return redirect(url_for('showDetailedIssue', I_Id=I_Id))
    return render_template('newcomment.html', Issue=issue)


# --------------------------------------------------------------------------------
# MY ISSUE / COMMENT VIEWS
# --------------------------------------------------------------------------------

@app.route('/issue/my/')
def showMyIssue():
    if 'logged_in' not in login_session:
        flash('You need to login first.')
        return redirect(url_for('login'))

    my_issues = session.query(Issue).filter_by(author=login_session['U_Id']).all()
    return render_template('showmyissue.html', Issue=my_issues)


@app.route('/comment/my/')
def showMyComment():
    if 'logged_in' not in login_session:
        flash('You need to login first.')
        return redirect(url_for('login'))

    my_comments = session.query(Comment).filter_by(author=login_session['U_Id']).all()
    return render_template('showmycomment.html', Comment=my_comments)


# --------------------------------------------------------------------------------
# NEARBY ISSUE FILTER
# --------------------------------------------------------------------------------

@app.route('/issue/nearby/map/', methods=['GET', 'POST'])
def showNearbyIssueMap():
    if 'logged_in' not in login_session:
        flash('You need to login first.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        lat = float(request.form['I_Lat'])
        lng = float(request.form['I_Lng'])
        latmax, latmin = lat + 0.00654, lat - 0.00654
        lngmax, lngmin = lng + 0.00654, lng - 0.00654
        nearby_issues = session.query(Issue).filter(
            Issue.lat < latmax, Issue.lat > latmin, Issue.lng < lngmax, Issue.lng > lngmin
        ).all()
        return render_template('shownearbyissuemap.html', Issue=nearby_issues, CurrentLat=lat, CurrentLng=lng)
    return render_template('getlocation.html')


@app.route('/issue/nearby/list/', methods=['GET', 'POST'])
def showNearbyIssueList():
    if 'logged_in' not in login_session:
        flash('You need to login first.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        lat = float(request.form['I_Lat'])
        lng = float(request.form['I_Lng'])
        latmax, latmin = lat + 0.00654, lat - 0.00654
        lngmax, lngmin = lng + 0.00654, lng - 0.00654
        nearby_issues = session.query(Issue).filter(
            Issue.lat < latmax, Issue.lat > latmin, Issue.lng < lngmax, Issue.lng > lngmin
        ).all()
        return render_template('shownearbyissuelist.html', Issue=nearby_issues)
    return render_template('getlocation.html')


# --------------------------------------------------------------------------------
# GOOGLE LOGIN (Updated)
# --------------------------------------------------------------------------------

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Allow HTTP for local testing

@app.route("/glogin")
def glogin():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=["openid", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"],
        redirect_uri="http://127.0.0.1:5000/gconnect"
    )
    authorization_url, state = flow.authorization_url(prompt="consent")
    login_session["state"] = state
    return redirect(authorization_url)


@app.route("/gconnect")
def gcallback():
    state = login_session.get("state")
    if not state:
        return make_response(json.dumps("Session state missing."), 401)

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=["openid", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"],
        state=state,
        redirect_uri="http://127.0.0.1:5000/gconnect"
    )

    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    request_session = google_requests.Request()

    try:
        id_info = id_token.verify_oauth2_token(credentials.id_token, request_session, CLIENT_ID)
    except ValueError:
        return make_response(json.dumps("Invalid token."), 401)

    login_session["logged_in"] = True
    login_session["username"] = id_info.get("name")
    login_session["email"] = id_info.get("email")
    login_session["picture"] = id_info.get("picture")
    login_session["access_token"] = credentials.token

    # Check if user exists or create new one
    existing_user = session.query(User).filter_by(email=login_session["email"]).first()
    if existing_user:
        login_session["U_Id"] = existing_user.id
    else:
        new_user = User(email=login_session["email"], name=login_session["username"], password="google")
        session.add(new_user)
        session.commit()
        login_session["U_Id"] = new_user.id

    flash(f"Welcome {login_session['username']}!")
    return redirect(url_for("home"))


@app.route("/gdisconnect")
def gdisconnect():
    access_token = login_session.get("access_token")
    if not access_token:
        return make_response(json.dumps("User not connected."), 401)

    revoke = requests.post(
        "https://oauth2.googleapis.com/revoke",
        params={"token": access_token},
        headers={"content-type": "application/x-www-form-urlencoded"}
    )

    if revoke.status_code == 200:
        login_session.clear()
        flash("Successfully logged out from Google.")
        return redirect(url_for("welcome"))
    else:
        return make_response(json.dumps("Failed to revoke token."), 400)

# --------------------------------------------------------------------------------
# APP ENTRY POINT
# --------------------------------------------------------------------------------

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.run(host='0.0.0.0', port=5000, debug=True)
