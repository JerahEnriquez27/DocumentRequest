from email.mime.text import MIMEText
import random
import smtplib
import time
from flask import Flask, jsonify, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from mysql.connector import Error
from flask import flash
import mysql.connector
import os
import uuid



app = Flask(__name__)
app.secret_key = 'SecretNaPassword'

UPLOAD_FOLDER = "static/payment_proofs"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='@Hotdog-1',
            database='documentsystem'
        )
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None
    
# --------------------- OTP GENERATOR ---------------------
def generate_otp():
    return str(random.randint(100000, 999999))

# --------------------- SEND EMAIL FUNCTION ---------------------
def send_email_otp(receiver_email, otp):

    sender_email = "enriquezsantillanjerah@gmail.com"
    sender_password = "kihj scvu tsty rxof"

    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp}\nThis will expire in 5 minutes."

    msg = MIMEText(body)
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender_email, sender_password)
            smtp.sendmail(sender_email, receiver_email, msg.as_string())
        return True

    except Exception as e:
        print("Email error:", e)
        return False


# --------------------- SEND OTP ROUTE ---------------------
@app.route("/send_otp", methods=["POST"])
def send_otp():
    email = request.form.get("email")

    if not email:
        return jsonify({"success": False, "message": "Email is required."}), 400

    otp = generate_otp()
    session["otp"] = otp
    session["otp_expiry"] = time.time() + 300

    sent = send_email_otp(email, otp)

    if not sent:
        return jsonify({
            "success": False,
            "message": "Failed to send OTP. Check your email settings."
        }), 500

    return jsonify({"success": True, "message": "OTP sent successfully!"})



#----------Main Route-------------------------------------------
@app.route('/')
def main():
    return render_template('Main.html')

#----------About Route---------------------------------------------------------------
@app.route('/about')
def about():
    return render_template('About.html')

#------------track--------------
@app.route('/track')
def track():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        cursor.execute("""
            SELECT r.id, r.date_requested, r.purpose, r.address, r.contact, r.status,
                   d.name AS document_type
            FROM requests r
            JOIN documents d ON r.document_id = d.id
            WHERE r.user_id = %s
              AND r.status IN ('Approved', 'Processing', 'Ready for Delivery', 'Out for Delivery')
            ORDER BY r.date_requested DESC
        """, (user_id,))
        requests = cursor.fetchall()

    return render_template('Track.html', user=user, requests=requests)


#----------Notification Route--------------------------------------------
@app.route('/notification')
def notification():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT message, date_created
            FROM notifications
            WHERE user_id = %s
            ORDER BY date_created DESC
        """, (user_id,))
        notifications_data = cursor.fetchall()

    return render_template('Notification.html', notifications=notifications_data)

#----------Home Route-------------------------
@app.route('/home')
def home():
    return render_template('Home.html')

#----------myorders----------------------------
@app.route('/myorders')
def myorders():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT r.id, r.status, r.purpose, r.contact, r.address, r.date_requested,
                   r.copies, r.cost,
                   d.name AS document_type
            FROM requests r
            JOIN documents d ON r.document_id = d.id
            WHERE r.user_id = %s AND r.status = 'Pending'
            ORDER BY r.date_requested DESC
        """, (user_id,))
        requests_data = cursor.fetchall()

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM requests
            WHERE user_id = %s
        """, (user_id,))
        total_documents = cursor.fetchone()['total']

        return render_template('MyOrders.html',
        requests=requests_data,
        total_documents=total_documents
    )

#----------Login Route-----------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):

            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            if user['role'] == 'staff':
                return redirect(url_for('admindashboard'))
            else:
                return redirect(url_for('home'))

        else:
            error = "Invalid username or password."
            return render_template('Login.html', error=error)

    return render_template('Login.html')

#----------Register Route--------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":

        entered_otp = request.form.get("otp")

        if "otp" not in session or "otp_expiry" not in session:
            return "OTP not generated. Please request OTP again.", 400

        if time.time() > session["otp_expiry"]:
            return "OTP expired. Please request a new one.", 400

        if entered_otp != session["otp"]:
            return "Invalid OTP. Please try again.", 400

        fullname = request.form['fullname']
        username = request.form['username']
        email = request.form['email']
        address = request.form['address']
        contact = request.form['contact']
        gender = request.form['gender']
        dob = request.form['dob']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form.get('role', 'user')

        if password != confirm_password:
            return jsonify({"success": False, "message": "Passwords do not match!"})

        hashed_password = generate_password_hash(password)

        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT * FROM users WHERE username=%s OR email=%s",
                (username, email)
            )
            existing_user = cursor.fetchone()

            if existing_user:
                return jsonify({"success": False, "message": "Username or email already exists!"})

            cursor.execute("""
                INSERT INTO users 
                (fullname, username, email, address, contact, gender, dob, password, role)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (fullname, username, email, address, contact, gender, dob, hashed_password, role))
            conn.commit()

        session.pop("otp", None)
        session.pop("otp_expiry", None)

        return "Registration successful!"

    return render_template("register.html")





#----------Request Document Route-------------------------------------------
@app.route('/requestdocument', methods=['GET', 'POST'])
def requestdocument():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.execute("SELECT * FROM documents")
        documents = cursor.fetchall()

    if request.method == 'POST':
        document_id = request.form['document_type']
        purpose = request.form['purpose']
        address = request.form['address']
        email = request.form['email']
        contact = request.form['contact']
        copies = int(request.form['copies'])

        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)

            cursor.execute("SELECT cost FROM documents WHERE id = %s", (document_id,))
            cost_per_copy = cursor.fetchone()['cost']

            total_cost = cost_per_copy * copies

            cursor.execute("""
                INSERT INTO requests
                (user_id, document_id, purpose, address, email, contact, copies, cost, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                user_id, document_id, purpose, address,
                email, contact, copies, total_cost, 'Pending'
            ))

            cursor.execute("SELECT name FROM documents WHERE id = %s", (document_id,))
            doc_name = cursor.fetchone()['name']

            message = f"Your request for {doc_name} has been successfully submitted. Our staff will review it shortly."
            cursor.execute("INSERT INTO notifications (user_id, message) VALUES (%s, %s)", (user_id, message))

            conn.commit()

        return redirect(url_for('myorders'))

    return render_template('Request.html', documents=documents, user=user)


#----------Profile Route-----------------------------------------------------
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT fullname, username, email, address, contact, dob, gender FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

    return render_template('Profile.html', user=user)

#----------Edit Profile Route------------------------------------------------------------
@app.route('/editprofile', methods=['GET', 'POST'])
def editprofile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        if request.method == 'POST':
            fullname = request.form['fullname']
            username = request.form['username']
            email = request.form['email']
            address = request.form['address']
            contact = request.form['contact']
            dob = request.form['dob']
            gender = request.form['gender']


            cursor.execute("""
                UPDATE users
                SET fullname=%s, username=%s, email=%s, address=%s, contact=%s, dob=%s, gender=%s
                WHERE id=%s
            """, (fullname, username, email, address, contact, dob, gender, user_id))
            conn.commit()

            return redirect(url_for('profile'))
        else:
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()

            if user['dob']:
                user['dob'] = user['dob'].strftime('%Y-%m-%d')

    return render_template('EditProfile.html', user=user)

#----------------myorders routes-------------------------

#--------topay-------------
@app.route('/topay')
def topay():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT r.id, r.status, r.purpose, r.contact, r.address, r.date_requested,
                   r.copies, r.cost,
                   d.name AS document_type
            FROM requests r
            JOIN documents d ON r.document_id = d.id
            WHERE r.user_id = %s AND r.status = 'To Pay'
            ORDER BY r.date_requested DESC
        """, (user_id,))
        requests_data = cursor.fetchall()

    return render_template('ToPay.html',
                           requests=requests_data)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS



@app.route("/payment/<int:request_id>", methods=["GET", "POST"])
def payment(request_id):
    user_id = session.get("user_id")

    if not user_id:
        flash("You must be logged in.")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM requests WHERE id=%s AND user_id=%s", (request_id, user_id))
    req = cursor.fetchone()

    if not req:
        flash("Invalid request.")
        return redirect(url_for("myorders"))

    if request.method == "POST":
        reference = request.form.get("reference")
        amount_paid = request.form.get("amount_paid")
        file = request.files.get("payment_proof")

        if not reference:
            flash("Reference No is required.")
            return redirect(request.url)

        if not amount_paid or not amount_paid.replace(".", "", 1).isdigit():
            flash("Amount must be numeric.")
            return redirect(request.url)

        if not file or file.filename == "":
            flash("Please upload a payment proof.")
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash("Invalid file type.")
            return redirect(request.url)

        ext = file.filename.rsplit(".", 1)[1].lower()
        new_filename = secure_filename(f"{uuid.uuid4()}.{ext}")
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)
        file.save(file_path)

        cursor2 = conn.cursor()
        cursor2.execute("""
            INSERT INTO payments (user_id, request_id, reference_no, amount_paid, image_path)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, request_id, reference, amount_paid, f"static/payment_proofs/{new_filename}"))

        cursor2.execute("UPDATE requests SET status='Payment Under Review' WHERE id=%s", (request_id,))
        conn.commit()
        cursor2.close()
        cursor.close()
        conn.close()

        flash("Payment submitted successfully!")
        return redirect(url_for('myorders'))

    return render_template("payment.html", req=req)

#-----------------toprocess-----------

@app.route('/toprocess')
def toprocess():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT r.id, r.status, r.purpose, r.contact, r.address, r.date_requested,
                   r.copies, r.cost,
                   d.name AS document_type
            FROM requests r
            JOIN documents d ON r.document_id = d.id
            WHERE r.user_id = %s AND r.status = 'Processing'
            ORDER BY r.date_requested DESC
        """, (user_id,))
        requests_data = cursor.fetchall()

    return render_template('ToProcess.html',
                           requests=requests_data)

@app.route('/cancel_order/<int:id>')
def cancel_order(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT user_id, status FROM requests WHERE id = %s", (id,))
        request_row = cursor.fetchone()

        if request_row is None or request_row[0] != user_id:
            return "Unauthorized", 403

        cursor.execute("UPDATE requests SET status = 'Cancelled' WHERE id = %s", (id,))
        conn.commit()

    return redirect(url_for('toprocess'))

#------------------ready for delivery---------------

@app.route('/readyfordelivery')
def readyfordelivery():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT r.id, r.status, r.purpose, r.contact, r.address, r.date_requested,
                   r.copies, r.cost,
                   d.name AS document_type
            FROM requests r
            JOIN documents d ON r.document_id = d.id
            WHERE r.user_id = %s AND r.status = 'Ready For Delivery'
            ORDER BY r.date_requested DESC
        """, (user_id,))
        requests_data = cursor.fetchall()

    return render_template('ReadyForDelivery.html',
                           requests=requests_data)

#------------payment review

@app.route('/paymentreview')
def paymentreview():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT r.id, r.status, r.purpose, r.contact, r.address, r.date_requested,
                   r.copies, r.cost,
                   d.name AS document_type
            FROM requests r
            JOIN documents d ON r.document_id = d.id
            WHERE r.user_id = %s AND r.status = 'Payment Under Review'
            ORDER BY r.date_requested DESC
        """, (user_id,))
        requests_data = cursor.fetchall()

    return render_template('PaymentReview.html',
                           requests=requests_data)


#-------------------out for delivery---------------------

@app.route('/outfordelivery')
def outfordelivery():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT r.id, r.status, r.purpose, r.contact, r.address, r.date_requested,
                   r.copies, r.cost,
                   d.name AS document_type
            FROM requests r
            JOIN documents d ON r.document_id = d.id
            WHERE r.user_id = %s AND r.status = 'Out For Delivery'
            ORDER BY r.date_requested DESC
        """, (user_id,))
        requests_data = cursor.fetchall()

    return render_template('OutForDelivery.html',requests=requests_data)

@app.route('/mark_complete/<int:req_id>', methods=['POST'])
def mark_complete(req_id):
    if 'user_id' not in session:
        flash("You must be logged in.")
        return redirect(url_for('login'))

    user_id = session['user_id']

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT user_id, document_id, status FROM requests WHERE id=%s", (req_id,))
        req = cursor.fetchone()

        if req and req['user_id'] == user_id and req['status'] == 'Out for Delivery':
            cursor.execute("UPDATE requests SET status='Completed' WHERE id=%s", (req_id,))

            cursor.execute("SELECT name FROM documents WHERE id=%s", (req['document_id'],))
            doc_name = cursor.fetchone()['name']

            message = f"Your request for {doc_name} has been completed."
            cursor.execute("INSERT INTO notifications (user_id, message) VALUES (%s, %s)", (user_id, message))

            conn.commit()
            flash("Order marked as completed successfully!")
        else:
            flash("Unable to complete order. It may not be out for delivery or does not belong to you.")

    return redirect(url_for('outfordelivery'))


@app.route('/completed')
def completed():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT r.id, r.status, r.purpose, r.contact, r.address, r.date_requested,
                   r.copies, r.cost,
                   d.name AS document_type
            FROM requests r
            JOIN documents d ON r.document_id = d.id
            WHERE r.user_id = %s AND r.status = 'Completed'
            ORDER BY r.date_requested DESC
        """, (user_id,))
        requests_data = cursor.fetchall()

    return render_template('Completed.html',
                           requests=requests_data)

@app.route('/cancelled')
def cancelled():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT r.id, r.status, r.purpose, r.contact, r.address, r.date_requested,
                   r.copies, r.cost,
                   d.name AS document_type
            FROM requests r
            JOIN documents d ON r.document_id = d.id
            WHERE r.user_id = %s AND r.status = 'Cancelled'
            ORDER BY r.date_requested DESC
        """, (user_id,))
        requests_data = cursor.fetchall()

    return render_template('Cancelled.html',
                           requests=requests_data)



#------------------------------------------ADMIN------------------------------------------------------------

@app.route('/admindashboard')
def admindashboard():
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT COUNT(*) AS total FROM users")
        total_users = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) AS total FROM requests")
        total_requests = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) AS total FROM documents")
        total_documents = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) AS total FROM requests WHERE status = 'Pending'")
        pending_requests = cursor.fetchone()['total']
    
    return render_template('AdminDashboard.html', 
                           total_users=total_users, 
                           total_requests=total_requests, 
                           total_documents=total_documents, 
                           pending_requests=pending_requests)


#----------------manage user-----------------
@app.route('/manageuser')
def manageuser():
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, fullname, username, email, contact, gender
            FROM users
            WHERE role = 'user'
        """)
        users = cursor.fetchall()
    return render_template('AdminManageUsers.html', users=users)

#edituser--------------------
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        if request.method == 'POST':
            fullname = request.form['fullname']
            username = request.form['username']
            email = request.form['email']
            address = request.form['address']
            contact = request.form['contact']
            dob = request.form['dob']
            gender = request.form['gender']

            cursor.execute("""
                UPDATE users
                SET fullname=%s, username=%s, email=%s, address=%s, contact=%s, dob=%s, gender=%s
                WHERE id=%s
            """, (fullname, username, email, address, contact, dob, gender, user_id))
            conn.commit()
            return redirect(url_for('manageuser'))

        else:
            cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
            user = cursor.fetchone()

    return render_template('EditUser.html', user=user)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
        conn.commit()
    return redirect(url_for('manageuser'))


# ----------Manage Request----------
@app.route('/managerequest')
def managerequest():
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT r.id, r.status, r.purpose, r.contact, r.address, r.date_requested,
                   u.fullname, d.name AS document_type
            FROM requests r
            JOIN users u ON r.user_id = u.id
            JOIN documents d ON r.document_id = d.id
            WHERE r.status IN ('Pending')
            ORDER BY r.date_requested DESC
        """)
        requests_data = cursor.fetchall()

    return render_template('AdminManageRequest.html', requests=requests_data)

#------------approve request
@app.route('/approve_request/<int:req_id>')
def approve_request(req_id):
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT user_id, document_id FROM requests WHERE id=%s", (req_id,))
        req = cursor.fetchone()
        user_id = req['user_id']

        cursor.execute("UPDATE requests SET status=%s WHERE id=%s", ('To Pay', req_id))

        cursor.execute("SELECT name FROM documents WHERE id=%s", (req['document_id'],))
        doc_name = cursor.fetchone()['name']

        message = f"Your request for {doc_name} has been approved. Please proceed to payment to complete your request."
        cursor.execute("INSERT INTO notifications (user_id, message) VALUES (%s, %s)", (user_id, message))

        conn.commit()
    return redirect(url_for('managerequest'))


@app.route('/cancel_request/<int:req_id>')
def cancel_request(req_id):
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT user_id, document_id FROM requests WHERE id=%s", (req_id,))
        req = cursor.fetchone()
        user_id = req['user_id']

        cursor.execute("UPDATE requests SET status=%s WHERE id=%s", ('Rejected', req_id))

        cursor.execute("SELECT name FROM documents WHERE id=%s", (req['document_id'],))
        doc_name = cursor.fetchone()['name']

        message = f"Your request for '{doc_name}' has been rejected."
        cursor.execute("INSERT INTO notifications (user_id, message) VALUES (%s, %s)", (user_id, message))

        conn.commit()
    return redirect(url_for('managerequest'))

#payment------------------
@app.route('/reviewpayments')
def reviewpayment():
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT 
                p.id,
                p.reference_no,
                p.amount_paid,
                p.image_path,
                p.created_at,
                u.fullname,
                r.purpose,
                r.copies,
                r.cost,
                d.name AS document_type,
                r.id AS request_id 
            FROM payments p
            LEFT JOIN users u ON p.user_id = u.id
            LEFT JOIN requests r ON p.request_id = r.id
            LEFT JOIN documents d ON r.document_id = d.id
            WHERE r.status = 'Payment Under Review'
            ORDER BY p.created_at DESC
        """)

        payments = cursor.fetchall()

    return render_template('reviewpayments.html', payments=payments)


@app.route('/approve_payment/<int:payment_id>', methods=['POST'])
def approve_payment(payment_id):
    if 'user_id' not in session or session.get('role') != 'staff':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT request_id FROM payments WHERE id = %s", (payment_id,))
        payment = cursor.fetchone()
        if not payment:
            flash("Payment not found.")
            return redirect(url_for('reviewpayment'))
        
        request_id = payment['request_id']
        
        cursor.execute("UPDATE requests SET status = 'Processing' WHERE id = %s", (request_id,))
        
        cursor.execute("SELECT user_id, document_id FROM requests WHERE id = %s", (request_id,))
        req = cursor.fetchone()
        user_id = req['user_id']
        cursor.execute("SELECT name FROM documents WHERE id = %s", (req['document_id'],))
        doc_name = cursor.fetchone()['name']
        
        message = f"Your payment for {doc_name} has been successfully approved. Your request is now being processed."
        cursor.execute("INSERT INTO notifications (user_id, message) VALUES (%s, %s)", (user_id, message))
        
        conn.commit()
    
    flash("Payment approved successfully.")
    return redirect(url_for('reviewpayment'))

@app.route('/reject_payment/<int:payment_id>', methods=['POST'])
def reject_payment(payment_id):
    if 'user_id' not in session or session.get('role') != 'staff':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT request_id FROM payments WHERE id = %s", (payment_id,))
        payment = cursor.fetchone()
        if not payment:
            flash("Payment not found.")
            return redirect(url_for('reviewpayment'))
        
        request_id = payment['request_id']
        
        cursor.execute("UPDATE requests SET status = 'Rejected' WHERE id = %s", (request_id,))
        
        cursor.execute("SELECT user_id, document_id FROM requests WHERE id = %s", (request_id,))
        req = cursor.fetchone()
        user_id = req['user_id']
        cursor.execute("SELECT name FROM documents WHERE id = %s", (req['document_id'],))
        doc_name = cursor.fetchone()['name']
        
        message = f"Your payment for '{doc_name}' has been rejected. Please check your payment details."
        cursor.execute("INSERT INTO notifications (user_id, message) VALUES (%s, %s)", (user_id, message))
        
        conn.commit()
    
    flash("Payment rejected successfully.")
    return redirect(url_for('reviewpayment'))

#---------------------manage document-----------------------------

@app.route('/managedocument/', methods=['GET'])
@app.route('/managedocument', methods=['GET'])
def managedocument():
    """Display all documents"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM documents")
        documents = cursor.fetchall()
    return render_template('AdminManageDocument.html', documents=documents)

@app.route('/add_document/', methods=['POST'])
@app.route('/add_document', methods=['POST'])
def add_document():
    """Add a new document"""
    name = request.form['name']
    description = request.form['description']
    cost = request.form['cost']
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO documents (name, description, cost) VALUES (%s, %s, %s)",
            (name, description, cost)
        )
        conn.commit()
    return redirect(url_for('managedocument'))

@app.route('/edit_document/<int:doc_id>/', methods=['GET', 'POST'])
@app.route('/edit_document/<int:doc_id>', methods=['GET', 'POST'])
def edit_document(doc_id):
    """Edit an existing document"""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        if request.method == 'POST':
            name = request.form['name']
            description = request.form['description']
            cost = request.form['cost']
            cursor.execute(
                "UPDATE documents SET name=%s, description=%s, cost=%s WHERE id=%s",
                (name, description, cost, doc_id)
            )
            conn.commit()
            return redirect(url_for('managedocument'))
        else:
            cursor.execute("SELECT * FROM documents WHERE id=%s", (doc_id,))
            doc = cursor.fetchone()
    return render_template('EditDocument.html', doc=doc)


@app.route('/delete_document/<int:doc_id>/', methods=['GET'])
@app.route('/delete_document/<int:doc_id>', methods=['GET'])
def delete_document(doc_id):
    """Delete a document"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM documents WHERE id=%s", (doc_id,))
        conn.commit()
    return redirect(url_for('managedocument'))

#-----------history-------------------------------------------------------
@app.route('/requestlog')
def requestlog():
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT r.id, r.purpose, r.contact, r.address, r.date_requested,
                   r.status, u.fullname, d.name AS document_type
            FROM requests r
            JOIN users u ON r.user_id = u.id
            JOIN documents d ON r.document_id = d.id
            WHERE r.status IN ('Completed', 'Rejected')  -- filter only completed & rejected
            ORDER BY r.date_requested DESC
        """)
        all_requests = cursor.fetchall()

    return render_template('RequestLogs.html', requests=all_requests)

@app.route('/admin/delete/<int:req_id>')
def delete_request(req_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM requests WHERE id = %s", (req_id,))
        conn.commit()

    return redirect(url_for('requestlog'))

#---------------trackadmin--------------------------
@app.route('/admintrack')
def admintrack():
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT r.id, r.date_requested, r.purpose, r.cost, r.address, r.contact, r.status,
                   d.name AS document_type, u.fullname
            FROM requests r
            JOIN documents d ON r.document_id = d.id
            JOIN users u ON r.user_id = u.id
            WHERE r.status IN ('Processing', 'Ready for Delivery', 'Out for Delivery')
            ORDER BY r.date_requested DESC
        """)
        requests = cursor.fetchall()
    return render_template('AdminTrack.html', requests=requests)

@app.route('/admin/update_status/<int:req_id>', methods=['POST'])
def update_status(req_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    new_status = request.form.get('status')
    if not new_status:
        return redirect(url_for('admintrack'))

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT user_id, document_id FROM requests WHERE id=%s", (req_id,))
        req = cursor.fetchone()
        if req:
            cursor.execute("UPDATE requests SET status=%s WHERE id=%s", (new_status, req_id))

            cursor.execute("SELECT name FROM documents WHERE id=%s", (req['document_id'],))
            doc_name = cursor.fetchone()['name']
            message = f"Your request for {doc_name} is now {new_status}."
            cursor.execute("INSERT INTO notifications (user_id, message) VALUES (%s, %s)", (req['user_id'], message))

        conn.commit()

    return redirect(url_for('admintrack'))





if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
