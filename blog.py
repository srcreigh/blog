import webapp2 
import jinja2
import os
import re
import string
import hmac
import hashlib
import random
import json
import time
from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(autoescape=True,
	loader = jinja2.FileSystemLoader(template_dir))

secret = 'awefiOASJIAOD#&783'
latest_query_time = 0
post_query_times = {}

# data
class Post(db.Model):
	"""Models a blog post."""
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

# users
class User(db.Model):
	"""Models a user"""
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)

def valid_input(regex, s):
	USER_RE = re.compile(r"%s" % regex)
	return USER_RE.match(s)

def get_front_page_data(update = False):
	global latest_query_time

	# sets the query time if it hasn't been set
	if latest_query_time == 0:
		latest_query_time = int(round(time.time()))

	key = 'top'
	arts = memcache.get(key)
	print "ran get_front_page_data()"
	print arts
	if arts is None or update:
		latest_query_time = int(round(time.time()))
		arts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
		arts = list(arts)
		memcache.set(key, arts)
		print "set memcache"
	return arts

def get_blog_post_data(postid, update = False):
	global post_query_times

	# sets the query time if it hasn't been set
	if not post_query_times.get(postid, None):
		post_query_times[postid] = int(round(time.time()))

	# use the postid as key
	post = memcache.get(postid)

	# query the database for the post
	if post is None or update:
		post_query_times[postid] = int(round(time.time()))
		post = Post.get_by_id(int(postid))
		memcache.set(postid, post)

	return post

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))


class SignupPage(Handler):
	def get(self):
		self.render('signup.html', username="", email="", error="")

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")

		if (not valid_input("^[a-zA-Z0-9_-]{3,20}$", username) or
			  not valid_input("^.{3,20}$", password) or
			  not (valid_input("^[\S]+@[\S]+\.[\S]+$", email) or email == '') or
			  not password == verify):
			self.render('signup.html', username=username, email=email,
									error="Please fix your form.")
		else:
			h = hmac.new(secret, username).hexdigest()
			self.response.headers.add_header('Set-Cookie', str('username=%s|%s; Path=/' % (username, h)))

			salt = ''
			for unused in xrange(5):
				salt += chr(int(random.random() * 26) + 65)
			h = hashlib.sha256(username + password + salt).hexdigest()
			password = "%s,%s" % (h, salt)

			# if the username is not already in the database
			if not db.GqlQuery("SELECT * FROM User WHERE username='%s'" % username).get():
				User(username=username,password=password).put()

			self.redirect('/welcome')

class WelcomePage(Handler):
	def get(self):
		username_cookie = self.request.cookies.get('username')
		if username_cookie:
			username, h = username_cookie.split('|')
			if h == hmac.new(secret, username).hexdigest():
				self.render('welcome.html', name=username)
			else:
				self.redirect('/signup')
		else:
			self.redirect('/signup')

class LoginPage(Handler):
	def get(self):
		self.render('login.html', error='')
	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")

		user = db.GqlQuery("SELECT * FROM User WHERE username='%s'" % username).get()
		if user and username and password:
			h, salt = user.password.split(',')
			if hashlib.sha256(username + password + salt).hexdigest() == h:
				h = hmac.new(secret, username).hexdigest()
				self.response.headers.add_header('Set-Cookie', str('username=%s|%s; Path=/' % (username, h)))
				self.redirect('/welcome')
			else:
				print "incorrect password\n"
				self.render('login.html', error='invalid username or password')
		else:
			print "not finding user\n"
			self.render('login.html', error='invalid username or password')

class LogoutPage(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
		self.redirect('/signup')

class FrontPage(Handler):
	def get(self):
		# queries and retrieves posts
		posts = get_front_page_data()
		# renders with posts
		print 
		self.render('front.html', posts=posts, time=str(int(round(time.time() - latest_query_time))))

class FrontPageJson(Handler):
	def get(self):
		self.response.headers.add_header('Content-Type', 'application/json; charset=UTF-8')
		posts = get_front_page_data()
		output = json.dumps([{"content": post.content, "subject": post.subject} for post in posts])
		self.write(output)

class NewPostPage(Handler):
	def get(self):
		self.render('newpost.html', error="", subject="", content="")

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			newpost = Post(subject=subject, content=content)
			newpost.put()
			memcache.set('top', None)

			id = newpost.key().id()

			self.redirect('/%s' % id)
		else:
			error = "enter subject and content!"
			self.render('newpost.html', error=error, subject=subject, content=content)

class PostPage(Handler):
	def get(self, entry_id):
		post = get_blog_post_data(entry_id)

		if post:
			self.render('post.html', subject=post.subject, 
															 content=post.content, 
															 date=post.created,
															 time=str(int(round(time.time() - post_query_times[entry_id]))))
		else:
			subject = "404 error"
			content = "the post you were looking for was not found."
			self.render('post.html', subject=subject, content = content)

class PermalinkJson(Handler):
	def get(self, entry_id):
		post = Post.get_by_id(int(entry_id))

		if post:
			self.response.headers.add_header('Content-Type', 'application/json; charset=UTF-8')
			output = json.dumps({"content": post.content, "subject": post.subject})
			self.write(output)
		else:
			self.write("404 error")

class FlushPage(Handler):
	def get(self):
		# flushes everything in the cache
		memcache.flush_all()

		self.redirect('/')

app = webapp2.WSGIApplication([('/', FrontPage), 
															 ('/newpost', NewPostPage), 
															 ('/(\d+)', PostPage),
															#('/signup', SignupPage), 
															#('/welcome', WelcomePage),
															#('/login', LoginPage), 
															#('/logout', LogoutPage), 
															 ('/(\d+)\.json', PermalinkJson),
															 ('/\.json', FrontPageJson),
															 ('/flush', FlushPage)], 
															 debug=True)
