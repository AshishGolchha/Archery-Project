import os
import json
import secrets
import csv
from io import StringIO
from sqlalchemy.exc import SQLAlchemyError
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, Response, session
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from models import db, User, StudentProfile, Competition, ScoreEntry,Team
from forms import CreateUserForm, StudentProfileForm, CompetitionSetupForm, PasswordResetRequestForm, PasswordResetForm, LoginForm

ALLOWED_DISTANCES = {
    'Indian': {
        'Mini Sub Junior': [10, 20],
        'Sub Junior': [20, 30],
        'Junior': [30, 40],
        'Senior': [30, 40, 50]
    },
    'Re-curve': {
        'Mini Sub Junior': [30, 40, 50],
        'Sub Junior': [60],
        'Junior': [70],
        'Senior': [70]
    },
    'Compound': {
        'Mini Sub Junior': [30],
        'Sub Junior': [50],
        'Junior': [50],
        'Senior': [50]
    }
}



UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXT = {'png','jpg','jpeg'}


app = Flask(__name__)
# # 🔐 Session security settings
# app.config['SESSION_COOKIE_HTTPONLY'] = True     #not for localhost
# app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config.from_object(Config)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# limit upload size (e.g., 2 MB)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB
# Email token serializer
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# init
db.init_app(app)
mail = Mail(app)

# Create database tables and a default admin at app startup (Flask 3.x compatible)
with app.app_context():
    # create DB tables if they don't exist
    db.create_all()

    # create a default admin user if none exists
    if not User.query.filter_by(username='AshishGolchha').first():
        # hashed password (change the default 'admin' password later)
        hashed = generate_password_hash('9079287003')
        u = User(username='AshishGolchha', email='ashishgolchha23042001@gmail.com', password=hashed, is_admin=True)
        db.session.add(u)
        db.session.commit()



# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def home():
    return render_template('home.html')


def get_current_user():
    if not session.get('user_id'):
        return None
    return User.query.get(session['user_id'])

@app.context_processor
def inject_current_user():
    user = None
    if session.get('user_id'):
        user = User.query.get(session['user_id'])
    return dict(current_user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():

    # 🔐 Already logged in? → redirect
    if session.get('user_id'):
        user = get_current_user()
        if not user:
            session.clear()              # 🔥 VERY IMPORTANT
            return redirect(url_for('login'))
        
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        # ❌ Wrong username / password
        if not user or not check_password_hash(user.password, form.password.data):
            flash('Invalid username or password', 'danger')
            return render_template('login.html', form=form)

        # ❌ User inactive
        if not user.is_active:
            flash('Your account is deactivated. Contact admin.', 'danger')
            return render_template('login.html', form=form)

        # ✅ Login success
        session['user_id'] = user.id
        session['is_admin'] = user.is_admin

        # 🔁 Redirect based on role
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))

        # 👇 STUDENT FLOW
        profile = StudentProfile.query.filter_by(user_id=user.id).first()

        if not user.is_admin and not profile:
            return redirect(url_for('student_profile'))

        if user.is_admin:
            return redirect(url_for('admin_dashboard'))

        return redirect(url_for('student_dashboard'))



    return render_template('login.html', form=form)




# ----------------- Admin routes -----------------


@app.route('/admin/dashboard')
def admin_dashboard():

    # 🔐 Login check
    if not session.get('user_id'):
        flash('Please login first', 'warning')
        return redirect(url_for('login'))

    # 🔐 Admin check
    if not session.get('is_admin'):
        flash('Access denied', 'danger')
        return redirect(url_for('login'))

    users = User.query.all()
    competitions = Competition.query.order_by(Competition.created_at.desc()).all()

    # 📊 stats
    total_students = User.query.filter_by(is_admin=False, is_active=True).count()
    total_admins = User.query.filter_by(is_admin=True).count()
    total_competitions = Competition.query.count()

    # 🏆 recent winners
    recent_winners = []
    for c in Competition.query.order_by(Competition.created_at.desc()).limit(5):
        entries = c.score_entries
        if entries:
            top = max(entries, key=lambda e: ((e.total or 0), (e.xs or 0)))
            recent_winners.append({
                'competition': c.name,
                'roll_no': top.roll_no,
                'total': top.total,
                'xs': top.xs or 0
            })
    current_user = get_current_user()
    return render_template(
        'admin_dashboard.html',
        current_user=current_user,
        users=users,
        competitions=competitions,
        total_students=total_students,
        total_admins=total_admins,
        total_competitions=total_competitions,
        recent_winners=recent_winners
    )



@app.route('/admin/create_user', methods=['GET','POST'])
def admin_create_user():
    if not session.get('is_admin'):
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    form = CreateUserForm()
    if form.validate_on_submit():
        # Basic unique checks
        if User.query.filter_by(username=form.username.data).first():
            flash('Username exists', 'danger')
            return render_template('admin_create_user.html', form=form, current_user=get_current_user())
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', 'danger')
            return render_template('admin_create_user.html', form=form, current_user=get_current_user())
        
        # Use admin provided password if present, otherwise generate
        if form.password.data:
            raw_password = form.password.data
        else:
            raw_password = secrets.token_urlsafe(8)

        hashed = generate_password_hash(raw_password)
        u = User(username=form.username.data, email=form.email.data, password=hashed, is_admin=form.is_admin.data)
        try:
            db.session.add(u)
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            flash('User with same email or username already exists', 'danger')
            return render_template('admin_create_user.html', form=form, current_user=get_current_user())

        # send email with credentials
        try:
            msg = Message('Your Archery Portal Credentials', recipients=[u.email])
            msg.body = f"""Hello,Your account has been created.
            Username: {u.username}
            Password: {raw_password}
            Please login and complete your profile.
            """
            mail.send(msg)
            flash('User created and email sent', 'success')
        except Exception as e:
            flash('User created but email failed: ' + str(e), 'warning')
        return redirect(url_for('admin_dashboard'))
    current_user = get_current_user()
    return render_template('admin_create_user.html', form=form, current_user=current_user)

# Password reset request (send email with token)
@app.route('/password_reset_request', methods=['GET','POST'])
def password_reset_request():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = serializer.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('password_reset', token=token, _external=True)
            try:
                msg = Message('Password reset for Archery Portal', recipients=[user.email])
                msg.body = f"Hello {user.username},\n\nUse this link to reset your password (valid for 1 hour):\n\n{reset_url}\n\nIf you didn't request this, ignore."
                mail.send(msg)
                flash('Password reset email sent (check your inbox)', 'success')
            except Exception as e:
                flash('Failed to send reset email: ' + str(e), 'warning')
        else:
            flash('If the email exists we sent a reset link (for security we do not reveal existence).', 'info')
        return redirect(url_for('login'))
    return render_template('password_reset_request.html', form=form)

# Password reset page (token)
@app.route('/password_reset/<token>', methods=['GET','POST'])
def password_reset(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # 1 hour
    except SignatureExpired:
        flash('The password reset link has expired.', 'danger')
        return redirect(url_for('password_reset_request'))
    except BadSignature:
        flash('Invalid password reset token.', 'danger')
        return redirect(url_for('password_reset_request'))

    user = User.query.filter_by(email=email).first_or_404()
    form = PasswordResetForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.password.data)
        db.session.commit()
        flash('Password updated — please login.', 'success')
        return redirect(url_for('login'))
    return render_template('password_reset.html', form=form)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    # only admins can perform deletion
    if not session.get('is_admin'):
        flash('Access denied', 'danger')
        return redirect(url_for('login'))

    # protect from deleting the currently-logged-in admin accidentally
    current_user = get_current_user()
    if current_user and current_user.id == user_id:
        flash('You cannot delete your own account while logged in.', 'warning')
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)

    try:
        # Soft-delete: mark inactive so login is disabled
        user.is_active = False

        # Optional: anonymize credentials so the account cannot be used again or reused.
        # (Keeps profile & scores intact.)
        anonym = f"deleted_{user.id}_{secrets.token_hex(4)}"
        user.username = anonym
        user.email = f"{anonym}@deleted.local"
        user.password = generate_password_hash(secrets.token_urlsafe(16))

        db.session.add(user)
        db.session.commit()
        flash('User account disabled (data retained).', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Failed to delete user: ' + str(e), 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/restore_user/<int:user_id>', methods=['POST'])
def admin_restore_user(user_id):
    if not session.get('is_admin'):
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    user.is_active = True
    # NOTE: username/email were anonymized on delete — restore would need previous values.
    # If you want full restore, skip anonymization on delete, or store prior values in separate table.
    db.session.add(user)
    db.session.commit()
    flash('User restored (account enabled).', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/competition_setup', methods=['GET','POST'])
def admin_competition_setup():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    form = CompetitionSetupForm()

    # ✅ DEFAULT VALUES FOR FIRST LOAD
    bow = form.bow_type.data or 'Indian'
    age = form.age_group.data or 'Mini Sub Junior'

    # ✅ SET TARGET DISTANCE CHOICES (GET + POST)
    allowed = ALLOWED_DISTANCES.get(bow, {}).get(age, [])
    form.target_distance.choices = [(d, f"{d}m") for d in allowed]

    

    if form.validate_on_submit():
        if form.is_team_based.data:
            if not form.num_teams.data or form.num_teams.data < 2:
                flash('Please enter valid number of teams (minimum 2)', 'danger')
                return render_template('admin_competition_setup.html', form=form)

        # 🔒 Distance restriction check
        if form.target_distance.data not in allowed:
            flash(
                f"{bow} - {age} cannot play at {form.target_distance.data}m", 'danger')
            return render_template('admin_competition_setup.html', form=form)

        comp = Competition(
            name=form.name.data,
            bow_type=form.bow_type.data,
            age_group=form.age_group.data,
            gender=form.gender.data,
            target_distance=form.target_distance.data,
            target_serial=form.target_serial.data,
            num_students=form.num_students.data,
            is_team_based=form.is_team_based.data   
        )
        db.session.add(comp)
        db.session.commit()
        
        # ✅ CREATE TEAMS IF TEAM BASED
        if comp.is_team_based:
            for i in range(1, form.num_teams.data + 1):
                team = Team(
                    name=f"Team {i}",
                    competition_id=comp.id
                )
                db.session.add(team)

            db.session.commit()
        # Redirect to add participants
        return redirect(url_for('admin_add_participants', comp_id=comp.id))
    current_user = get_current_user()
    return render_template('admin_competition_setup.html', form=form, current_user=current_user)

@app.route('/admin/competition/<int:comp_id>/add', methods=['GET','POST'])
def admin_add_participants(comp_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    comp = Competition.query.get_or_404(comp_id)

    if request.method == 'POST':
        # Expect form fields roll_1..roll_n and gender_1..gender_n
        entries = []
        for i in range(1, comp.num_students + 1):
            roll = request.form.get(f'roll_{i}')
            gender = request.form.get(f'gender_{i}')
            user = None
            team_id = request.form.get(f'team_{i}')
            team = Team.query.get(team_id) if team_id else None

            # 🔒 TEAM SELECTION VALIDATION (⭐ EXACT PLACE ⭐)
            if comp.is_team_based and not team:
                flash(
                    f'Please select a team for participant #{i}',
                    'danger'
                )
                return render_template(
                    'admin_add_participants.html',
                    comp=comp,
                    teams=comp.teams
                )


            if roll:
                profile = StudentProfile.query.filter_by(roll_no=roll).first()

                if not profile:
                    flash(f'Roll {roll} not found', 'danger')
                    return render_template('admin_add_participants.html', comp=comp)
                
                user = profile.user
            entries.append({'roll': roll, 'gender': gender, 'user': user, 'team': team})
        # Create score entries rows with empty sets according to bow type
        
        for e in entries:
            # ✅ STEP 1: sets structure based on bow type
            if comp.bow_type == 'Indian':
                sets = [
                    {"round": i, "set1": 0, "set2": 0, "set3": 0, "xs": 0, "tens":0}
                    for i in range(1, 13)
                ]

            elif comp.bow_type in ['Re-curve', 'Compound']:
                sets = [
                    {
                        "round": i,
                        "set1": 0, "set2": 0, "set3": 0,
                        "set4": 0, "set5": 0, "set6": 0,
                        "xs": 0, "tens":0
                    }
                    for i in range(1, 7)
                ]

            else:
                sets = []
            se = ScoreEntry(competition_id=comp.id,
                            user_id=e['user'].id if e['user'] else None,
                            team_id=e['team'].id if comp.is_team_based and e['team'] else None,
                            roll_no=e['roll'],
                            target_distance=comp.target_distance,
                            target_serial=comp.target_serial,
                            sets=json.dumps(sets),
                            xs=0,
                            total=0)
            db.session.add(se)
        db.session.commit()
        flash('Participants added and scoring sheet created', 'success')
        return redirect(url_for('admin_scores_view', comp_id=comp.id))
    return render_template('admin_add_participants.html', comp=comp, teams=comp.teams)

@app.route('/admin/student/<int:user_id>/edit', methods=['GET', 'POST'])
def admin_edit_student_profile(user_id):

    # 🔐 admin check
    if not session.get('is_admin'):
        flash('Access denied', 'danger')
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)
    profile = StudentProfile.query.filter_by(user_id=user.id).first()

    if not profile:
        flash('Student profile not found', 'danger')
        return redirect(url_for('admin_dashboard'))

    form = StudentProfileForm(obj=profile)  # 👈 AUTO PREFILL

    if form.validate_on_submit():
        profile.name = form.name.data
        profile.father_name = form.father_name.data
        profile.mother_name = form.mother_name.data
        profile.dob = form.dob.data
        profile.dob_cert_no = form.dob_cert_no.data
        profile.gender = form.gender.data
        profile.address = form.address.data
        profile.mobile_no = form.mobile_no.data
        profile.parent_mobile_no = form.parent_mobile_no.data
        profile.aadhar_no = form.aadhar_no.data
        profile.raa_no = form.raa_no.data
        profile.aai_no = form.aai_no.data
        profile.bow_type = form.bow_type.data
        profile.age_group = form.age_group.data

        # photo update (optional)
        f = request.files.get('photo')
        if f and f.filename:
            ext = f.filename.rsplit('.', 1)[-1].lower()
            filename = secure_filename(f"{user.username}_photo.{ext}")
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            profile.photo_filename = filename

        db.session.commit()
        flash('Student profile updated successfully', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template(
        'admin_edit_student_profile.html',
        form=form,
        profile=profile,
        user=user
    )



def calculate_total(comp, sets):
    total = 0

    if comp.bow_type == 'Indian':
        for r in sets:
            total += r['set1'] + r['set2'] + r['set3']

    elif comp.bow_type in ['Re-curve', 'Compound']:
        for r in sets:
            total += (
                r['set1'] + r['set2'] + r['set3'] +
                r['set4'] + r['set5'] + r['set6']
            )

    return total



@app.route('/admin/delete_competition_keep_scores/<int:comp_id>', methods=['POST'])
def admin_delete_competition_keep_scores(comp_id):
    # Admin only
    if not session.get('is_admin'):
        flash('Access denied', 'danger')
        return redirect(url_for('login'))

    comp = Competition.query.get_or_404(comp_id)

    try:
        # Option A: copy competition name into each score entry, then null the FK
        for e in comp.score_entries:
            # preserve context
            e.competition_name = comp.name
            # keep other comp fields already exist on score entry (target_distance/serial)
            e.competition_id = None

        # Commit the updates to ScoreEntry
        db.session.commit()

        # Now safely delete the competition row
        db.session.delete(comp)
        db.session.commit()

        flash(f'Competition \"{comp.name}\" deleted. Scores kept (competition_name saved).', 'success')
    except Exception as exc:
        db.session.rollback()
        flash('Failed to delete competition: ' + str(exc), 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/competition/<int:comp_id>/scores')
def admin_scores_view(comp_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    comp = Competition.query.get_or_404(comp_id)
    entries = comp.score_entries
    return render_template('admin_scores_view.html', comp=comp, entries=entries)

from sqlalchemy import func

@app.route('/admin/competition/<int:comp_id>/leaderboard')
def admin_leaderboard(comp_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    comp = Competition.query.get_or_404(comp_id)

    # 🔥 TEAM BASED LEADERBOARD
    if comp.is_team_based:
        team_scores = (
            db.session.query(
                Team.id.label('team_id'),
                Team.name.label('team_name'),
                func.sum(ScoreEntry.total).label('total'),
                func.sum(ScoreEntry.xs).label('xs')
            ).join(ScoreEntry, ScoreEntry.team_id == Team.id).filter(ScoreEntry.competition_id == comp.id).group_by(Team.id).order_by(func.sum(ScoreEntry.total).desc(), func.sum(ScoreEntry.xs).desc()).all())

        return render_template('admin_leaderboard.html', comp=comp, team_scores=team_scores)

    # 🔹 INDIVIDUAL LEADERBOARD (OLD LOGIC)
    entries = ScoreEntry.query.filter_by(competition_id=comp.id).order_by(ScoreEntry.total.desc(), ScoreEntry.xs.desc()).all()
    return render_template('admin_leaderboard.html', comp=comp, entries=entries)


@app.route('/admin/students')
def admin_students():
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    q = request.args.get('q', '').strip()

    query = StudentProfile.query

    if q:
        query = query.filter(
            StudentProfile.name.ilike(f"%{q}%")
        )

    students = query.order_by(StudentProfile.name.asc()).all()

    return render_template(
        'admin_students.html',
        students=students,
        q=q
    )


@app.route('/admin/competition/<int:comp_id>/export_csv')
def admin_export_csv(comp_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    comp = Competition.query.get_or_404(comp_id)
    entries = comp.score_entries

    si = StringIO()
    cw = csv.writer(si)
    # header
    headers = ['roll_no', 'target_distance', 'target_serial']
    # variable number of set columns
    rounds = 12 if comp.bow_type == 'Indian' else 6
    for i in range(1, rounds+1):
        headers.append(f'set_{i}')
    headers += ["xs", "total"]
    cw.writerow(headers)

    for e in entries:
        sets = json.loads(e.sets or '[]')
        row = [e.roll_no, e.target_distance, e.target_serial]
        # append set scores (pad if necessary)
        for i in range(rounds):
            row.append(sets[i] if i < len(sets) else 0)
        row += [e.xs or 0, e.total or 0]
        cw.writerow(row)

    output = si.getvalue()
    si.close()
    return Response(output, mimetype='text/csv',
                    headers={"Content-Disposition": f"attachment;filename=competition_{comp.id}_scores.csv"})

@app.route('/admin/competition/<int:comp_id>/teams', methods=['GET','POST'])
def admin_create_teams(comp_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    comp = Competition.query.get_or_404(comp_id)

    if request.method == 'POST':
        names = request.form.getlist('team_name')
        for n in names:
            if n.strip():
                db.session.add(Team(name=n.strip(), competition=comp))
        db.session.commit()
        return redirect(url_for('admin_add_participants', comp_id=comp.id))

    return render_template('admin_create_teams.html', comp=comp)



# ---------------- Student routes ----------------

@app.route('/student/dashboard')
def student_dashboard():
    # 🔐 login check
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    current_user = get_current_user()

    if not current_user:
        session.clear()      # 🔥 LOOP TODTA HAI
        return redirect(url_for('login'))

    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))

    # 🔥 IMPORTANT PART: fetch competitions via ScoreEntry
    entries = (ScoreEntry.query.filter_by(user_id=current_user.id).join(Competition).all())


    competitions = []
    for e in entries:
        if e.competition:
            competitions.append(e.competition)

    return render_template(
        'student_dashboard.html',
        competitions=competitions,
        entries=entries
    )

@app.route('/student/profile', methods=['GET','POST'])
def student_profile():
    # 🔐 login check
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    if session.get('is_admin'):
        flash('Admins do not have student profiles', 'info')
        return redirect(url_for('admin_dashboard'))
    
    current_user = get_current_user()
    if not current_user:
        return redirect(url_for('login'))

    # # Student cannot edit profile again once created
    # if profile and not session.get('is_admin'):
    #     return redirect(url_for('student_dashboard'))

    
    form = StudentProfileForm()
    if form.validate_on_submit():

        # 🔒 Aadhar format safety check (backend)
        aadhar = form.aadhar_no.data.strip()
        if not aadhar.isdigit() or len(aadhar) != 12 or aadhar.startswith('0'):
            flash('Invalid Aadhar number. It must be 12 digits and cannot start with 0.', 'danger')
            return render_template('student_profile_form.html', form=form, profile=current_user.profile)

        # 🔒 RAA format validation
        raa = form.raa_no.data.strip()
        if not (raa.startswith('RAA') and len(raa) == 7 and raa[3:].isdigit()):
            flash('Invalid RAA number. Format must be RAA followed by 4 digits (e.g. RAA0212).', 'danger')
            return render_template('student_profile_form.html', form=form, profile=current_user.profile)
        
        # 🔒 AAI format validation
        aai = form.aai_no.data.strip()
        if not aai.isdigit() or len(aai) > 6:
            flash('Invalid AAI number. It must be numeric and up to 6 digits.', 'danger')
            return render_template('student_profile_form.html', form=form, profile=current_user.profile)

        # 🔒 Duplicate check (UNIQUE fields)
        existing = StudentProfile.query.filter(
            (StudentProfile.dob_cert_no == form.dob_cert_no.data) |
            (StudentProfile.aadhar_no == form.aadhar_no.data) |
            (StudentProfile.raa_no == form.raa_no.data) |
            (StudentProfile.aai_no == form.aai_no.data)
        ).first()

        # Agar koi record mila aur wo current user ka nahi hai
        if existing and existing.user_id != current_user.id:
            flash(
                'Profile cannot be saved. One of the following already exists: '
                'DOB Certificate No / Aadhar No / RAA No / AAI No',
                'danger'
            )
            return render_template(
                'student_profile_form.html',
                form=form,
                profile=current_user.profile
            )

        profile = current_user.profile or StudentProfile(user=current_user)
        profile.name = form.name.data
        profile.father_name = form.father_name.data
        profile.mother_name = form.mother_name.data
        profile.dob = form.dob.data
        profile.dob_cert_no = form.dob_cert_no.data
        profile.gender = form.gender.data
        profile.address = form.address.data
        profile.mobile_no = form.mobile_no.data
        profile.parent_mobile_no = form.parent_mobile_no.data
        profile.aadhar_no = form.aadhar_no.data
        profile.raa_no = form.raa_no.data
        profile.aai_no = form.aai_no.data
        profile.bow_type = form.bow_type.data
        profile.age_group = form.age_group.data
        # handle photo
        f = request.files.get('photo')
        if f and f.filename:
            ext = f.filename.rsplit('.', 1)[-1].lower()
            if ext not in ALLOWED_EXT:
                flash('Invalid file type for photo. Allowed: png, jpg, jpeg', 'danger')
                return render_template('student_profile_form.html', form=form, profile=current_user.profile)
            # check mimetype starts with image/
            if not (f.mimetype and f.mimetype.startswith('image/')):
                flash('Uploaded file is not an image.', 'danger')
                return render_template('student_profile_form.html', form=form, profile=current_user.profile)

            # file size limit enforced by MAX_CONTENT_LENGTH; handle potential exception globally
            filename = secure_filename(f"{current_user.username}_photo.{ext}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            f.save(filepath)
            profile.photo_filename = filename


        # assign roll no if not exists
        if not profile.roll_no:
            # generate DSD###
            last = StudentProfile.query.order_by(StudentProfile.id.desc()).first()
            next_id = (last.id + 1) if last else 1
            profile.roll_no = f"DTS{str(next_id).zfill(3)}"
        db.session.add(profile)
        db.session.commit()
        flash('Profile saved and roll number assigned: ' + profile.roll_no, 'success')
        return redirect(url_for('student_dashboard'))
    return render_template('student_profile_form.html', form=form, profile=current_user.profile)

def clamp_set_score(value):
    try:
        v = int(value)
    except:
        return 0
    return max(0, min(10, v))



@app.route('/competition/<int:comp_id>/score_entry/<int:entry_id>', methods=['GET','POST'])
def score_entry(comp_id, entry_id):
    comp = Competition.query.get_or_404(comp_id)
    entry = ScoreEntry.query.get_or_404(entry_id)


    # admin can edit any score; student can view only their own entry
    current_user = get_current_user()
    if not current_user:
        return redirect(url_for('login'))

    # admin can edit any score; student can view only their own entry
    if not session.get('is_admin') and entry.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('student_dashboard'))
        
    if request.method == 'POST' and session.get('is_admin'):

        sets = json.loads(entry.sets)

        for i, r in enumerate(sets):

            # Common sets (Indian / Recurve / Compound)
            r['set1'] = clamp_set_score(request.form.get(f'set1_{i}'))
            r['set2'] = clamp_set_score(request.form.get(f'set2_{i}'))
            r['set3'] = clamp_set_score(request.form.get(f'set3_{i}'))

            # Extra sets only for Recurve & Compound
            if comp.bow_type in ['Re-curve', 'Compound']:
                r['set4'] = clamp_set_score(request.form.get(f'set4_{i}'))
                r['set5'] = clamp_set_score(request.form.get(f'set5_{i}'))
                r['set6'] = clamp_set_score(request.form.get(f'set6_{i}'))

            # X count
            r['xs'] = int(request.form.get(f'xs_{i}') or 0)
            r['tens'] = int(request.form.get(f'tens_{i}') or 0)

            # 🔒 X count validation per round
            max_x = 3 if comp.bow_type == 'Indian' else 6
            max_tens = max_x

            if r['tens'] < 0 or r['tens'] > max_tens:
                flash(
                    f"Invalid X+10 count in round {r['round']}. "
                    f"Allowed range: 0 to {max_tens}",
                    'danger'
                )
                return redirect(url_for(
                    'score_entry',
                    comp_id=comp.id,
                    entry_id=entry.id
                ))

            if r['xs'] > r['tens']:
                flash(
                    f"X count cannot be greater than X+10 in round {r['round']}",
                    'danger'
                )
                return redirect(url_for(
                    'score_entry',
                    comp_id=comp.id,
                    entry_id=entry.id
                ))


            if r['xs'] < 0 or r['xs'] > max_x:
                flash(
                    f"Invalid X count in round {r['round']}. "
                    f"Allowed range: 0 to {max_x}",
                    'danger'
                )
                return redirect(url_for('score_entry',
                                        comp_id=comp.id,
                                        entry_id=entry.id))
            
            # 🔒 Round total validation (AFTER sets & X validation)
            if comp.bow_type == 'Indian':
                round_total = r['set1'] + r['set2'] + r['set3']
                if round_total > 30:
                    flash(
                        f"Round {r['round']} total cannot exceed 30",
                        'danger'
                    )
                    return redirect(url_for(
                        'score_entry',
                        comp_id=comp.id,
                        entry_id=entry.id
                    ))
            else:
                round_total = (
                    r['set1'] + r['set2'] + r['set3'] +
                    r['set4'] + r['set5'] + r['set6']
                )
                if round_total > 60:
                    flash(
                        f"Round {r['round']} total cannot exceed 60",
                        'danger'
                    )
                    return redirect(url_for(
                        'score_entry',
                        comp_id=comp.id,
                        entry_id=entry.id
                    ))


        # Total auto calculate
        total = 0
        for r in sets:
            if comp.bow_type == 'Indian':
                total += r['set1'] + r['set2'] + r['set3']
            else:
                total += (
                    r['set1'] + r['set2'] + r['set3'] +
                    r['set4'] + r['set5'] + r['set6']
                )

        entry.total = total
        entry.xs = sum(r['xs'] for r in sets)
        entry.sets = json.dumps(sets)

        db.session.commit()
        flash('Scores updated', 'success')
        return redirect(url_for('admin_scores_view', comp_id=comp.id))
    sets = json.loads(entry.sets) if entry.sets else []
    return render_template('score_sheet.html', comp=comp, entry=entry, sets=sets)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.errorhandler(413)
def request_entity_too_large(error):
    flash('Uploaded file is too large. Max allowed size is 2 MB.', 'danger')
    return redirect(request.referrer or url_for('student_profile'))


if __name__ == '__main__':
    app.run(debug=True)