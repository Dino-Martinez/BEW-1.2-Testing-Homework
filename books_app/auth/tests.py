import os
from unittest import TestCase

from datetime import date

from books_app import app, db, bcrypt
from books_app.models import Book, Author, User, Audience

"""
Run these tests with the command:
python -m unittest books_app.main.tests
"""

#################################################
# Setup
#################################################

def create_books():
    a1 = Author(name='Harper Lee')
    b1 = Book(
        title='To Kill a Mockingbird',
        publish_date=date(1960, 7, 11),
        author=a1
    )
    db.session.add(b1)

    a2 = Author(name='Sylvia Plath')
    b2 = Book(title='The Bell Jar', author=a2)
    db.session.add(b2)
    db.session.commit()

def create_user():
    password_hash = bcrypt.generate_password_hash('password').decode('utf-8')
    user = User(username='me1', password=password_hash)
    db.session.add(user)
    db.session.commit()

#################################################
# Tests
#################################################

class AuthTests(TestCase):
    def setUp(self):
        """Executed prior to each test."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        db.drop_all()
        db.create_all()
    """Tests for authentication (login & signup)."""

    def test_signup(self):
        """Test that a user can signup."""
        # Make POST request with data
        post_data = {
            'username': 'tester',
            'password': 'testpass',
        }
        self.app.post('/signup', data=post_data)

        # Make sure user's profile was updated
        user = User.query.filter_by(username='tester').one()

        self.assertIsNotNone(user)
        self.assertEqual('tester', user.username)

    def test_signup_existing_user(self):
        """Test that a user cannot signup with an existing account."""
        post_data = {
            'username': 'tester',
            'password': 'testpass',
        }
        self.app.post('/signup', data=post_data)

        response = self.app.post('/signup', data=post_data)
        response_text = response.get_data(as_text=True)

        self.assertIn('That username is taken.', response_text)

    def test_login_correct_password(self):
        """Test that a user can login."""
        # Make POST request with data
        post_data = {
            'username': 'tester',
            'password': 'testpass',
        }
        self.app.post('/signup', data=post_data)

        response = self.app.post('/login', data=post_data,  follow_redirects=True)
        response_text = response.get_data(as_text=True)

        self.assertNotIn('Log In', response_text)
        self.assertIn('You are logged in as tester', response_text)

    def test_login_nonexistent_user(self):
        """Test that a user cannot login to an account that doesn't exist."""
        # Make POST request with data
        post_data = {
            'username': 'nobody',
            'password': 'exists',
        }
        response = self.app.post('/login', data=post_data,  follow_redirects=True)
        response_text = response.get_data(as_text=True)

        self.assertNotIn('Log Out', response_text)
        self.assertIn('No user with that username. Please try again.', response_text)

    def test_login_incorrect_password(self):
        """Test that a user cannot login with the wrong password."""
        # Make POST request with data
        post_data = {
            'username': 'tester',
            'password': 'testpass',
        }
        self.app.post('/signup', data=post_data)

        post_data = {
            'username': 'tester',
            'password': 'wrongpass',
        }

        response = self.app.post('/login', data=post_data,  follow_redirects=True)
        response_text = response.get_data(as_text=True)

        self.assertNotIn('Log Out', response_text)
        self.assertIn("Password doesn&#39;t match. Please try again.", response_text)


    def test_logout(self):
        """Test that a user cannot login with the wrong password."""
        # Make POST request with data
        post_data = {
            'username': 'tester',
            'password': 'testpass',
        }
        self.app.post('/signup', data=post_data)
        self.app.post('/login', data=post_data)

        response = self.app.get('/logout', follow_redirects=True)

        response_text = response.get_data(as_text=True)

        self.assertIn('Log In', response_text)
        # TODO: Write a test for the logout route. It should:
        # - Create a user
        # - Log the user in (make a POST request to /login)
        # - Make a GET request to /logout
        # - Check that the "login" button appears on the homepage
        pass
