from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, IntegerField, SelectField, FileField
from wtforms.validators import DataRequired, Email, Optional, Length, Regexp


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class CreateUserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password (optional - leave blank to auto-generate)', validators=[Optional(), Length(min=6)])
    is_admin = BooleanField('Make Admin')
    submit = SubmitField('Create User & Email')

# password reset request form
class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Email')

# set new password form
class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Set Password')    



class StudentProfileForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    father_name = StringField("Father's Name", validators=[Optional()])
    mother_name = StringField("Mother's Name", validators=[Optional()])
    # DOB required and expect YYYY-MM-DD (we'll use HTML date input too)
    dob = StringField('DOB', validators=[DataRequired(), Regexp(r'^\d{4}-\d{2}-\d{2}$', message='Date must be YYYY-MM-DD')])
    dob_cert_no = StringField('DOB Certificate No.', validators=[Optional(), Length(max=40)])
    gender = SelectField('Gender', choices=[('Male','Male'),('Female','Female'),('Other','Other')], validators=[DataRequired()])
    address = TextAreaField('Address', validators=[Optional(), Length(max=1000)])
    mobile_no = StringField('Mobile No.', validators=[DataRequired(), Regexp(r'^\d{7,15}$', message='Enter a valid phone number (digits only)')])
    parent_mobile_no = StringField("Parent's Mobile No.", validators=[Optional(), Regexp(r'^\d{7,15}$', message='Enter a valid phone number (digits only)')])
    # Aadhar exactly 12 digits
    aadhar_no = StringField('Aadhar Card No.', validators=[DataRequired(), Regexp(r'^\d{12}$', message='Aadhar must be exactly 12 digits')])
    # RAA and AAI: allow alphanumeric, limit 10 chars (adjust if you want different)
    raa_no = StringField('RAA No.', validators=[Optional(), Length(max=10), Regexp(r'^[A-Za-z0-9\-]*$', message='Use letters, numbers or hyphens only')])
    aai_no = StringField('AAI No.', validators=[Optional(), Length(max=10), Regexp(r'^[A-Za-z0-9\-]*$', message='Use letters, numbers or hyphens only')])
    bow_type = SelectField('Bow Type', choices=[('Indian','Indian'),('Re-curve','Re-curve'),('Compound','Compound')], validators=[DataRequired()])
    photo = FileField('Photo', validators=[Optional()])
    age_group = SelectField('Age Group', choices=[('Mini Sub Junior','Mini Sub Junior'),('Sub Junior','Sub Junior'),('Junior','Junior'),('Senior','Senior')], validators=[DataRequired()])
    submit = SubmitField('Save Profile')


class CompetitionSetupForm(FlaskForm):
    name = StringField('Competition Name', validators=[DataRequired()])
    bow_type = SelectField('Bow Type', choices=[('Indian','Indian'),('Re-curve','Re-curve'),('Compound','Compound')], validators=[DataRequired()])
    age_group = SelectField('Age Group', choices=[('Mini Sub Junior','Mini Sub Junior'),('Sub Junior','Sub Junior'),('Junior','Junior'),('Senior','Senior')], validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('Male','Male'),('Female','Female'),('Mixed','Mixed')])
    target_distance = StringField('Target Distance', validators=[DataRequired()])
    target_serial = StringField('Target Serial No.', validators=[DataRequired()])
    num_students = IntegerField('Number of Students', validators=[DataRequired()])
    submit = SubmitField('Create Competition')