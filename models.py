from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime


db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    # NEW FIELD — used for soft-deleting accounts
    is_active = db.Column(db.Boolean, default=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


    # Relationship to profile
    profile = db.relationship('StudentProfile', uselist=False, back_populates='user')
    scores = db.relationship('ScoreEntry', back_populates='user')


class StudentProfile(db.Model):
    __tablename__ = 'profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


    name = db.Column(db.String(200))
    father_name = db.Column(db.String(200))
    mother_name = db.Column(db.String(200))
    dob = db.Column(db.String(20))
    dob_cert_no = db.Column(db.String(100))
    gender = db.Column(db.String(20))
    address = db.Column(db.Text)
    mobile_no = db.Column(db.String(20))
    parent_mobile_no = db.Column(db.String(20))
    aadhar_no = db.Column(db.String(40))
    raa_no = db.Column(db.String(80))
    aai_no = db.Column(db.String(80))
    bow_type = db.Column(db.String(50))
    photo_filename = db.Column(db.String(300))
    age_group = db.Column(db.String(80))
    roll_no = db.Column(db.String(20), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


    user = db.relationship('User', back_populates='profile')


class Competition(db.Model):
    __tablename__ = 'competitions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    bow_type = db.Column(db.String(50))
    age_group = db.Column(db.String(80))
    gender = db.Column(db.String(20))
    target_distance = db.Column(db.String(50))
    target_serial = db.Column(db.String(20))
    num_students = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # ✅ TEAM FEATURE
    is_team_based = db.Column(db.Boolean, default=False)
    
    # Relationships
    score_entries = db.relationship('ScoreEntry', back_populates='competition', cascade='all, delete-orphan')
    teams = db.relationship('Team', back_populates='competition', cascade='all, delete-orphan')


class ScoreEntry(db.Model):
    __tablename__ = 'scores'
    id = db.Column(db.Integer, primary_key=True)
     # Making competition_id nullable so a score can remain after comp deletion
    competition_id = db.Column(db.Integer, db.ForeignKey('competitions.id', ondelete='SET NULL'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    roll_no = db.Column(db.String(20))
    target_distance = db.Column(db.String(50))
    target_serial = db.Column(db.String(20))
    # Optional: preserve the competition's name at the time of deletion
    competition_name = db.Column(db.String(200), nullable=True)

    # Stores per-set scores as JSON text for simplicity
    sets = db.Column(db.Text) # JSON string like '[10,9,8,...]'
    xs = db.Column(db.Integer, default=0)
    total = db.Column(db.Integer, default=0)

    team_id = db.Column(db.Integer, db.ForeignKey('teams.id', ondelete='SET NULL'), nullable=True)
    team = db.relationship('Team', back_populates='entries')

    competition = db.relationship('Competition', back_populates='score_entries')
    user = db.relationship('User', back_populates='scores')

class Team(db.Model):
    __tablename__ = 'teams'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    competition_id = db.Column(db.Integer, db.ForeignKey('competitions.id', ondelete='CASCADE'), nullable=False)

    competition = db.relationship('Competition', back_populates='teams')
    entries = db.relationship('ScoreEntry', back_populates='team')
