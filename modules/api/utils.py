import smtplib, ssl
import json
import uuid
import random
import string

from fastapi import Depends, Response, status
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from jinja2 import Environment, select_autoescape, PackageLoader, FileSystemLoader

from email_validator import validate_email, EmailNotValidError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy.orm import Session
import http.client

from .database import get_db
from .exceptions import invalid_email_exception
from .logs import print_message

from .config import settings
from .models import *

def validate_email_address(email):
    try:
        v = validate_email(email)
        print(f"Email address is valid: {email}")
        return True
    except EmailNotValidError as e:
        return invalid_email_exception(e)

def get_uuid():
    return str(uuid.uuid4())

def generate_order_id(order_name):
    return f"{order_name}_{get_uuid()}"

def send_email(mail_to:str, subject:str, content:str, mail_host: str = None, mail_port: int = None, mail_from:str = None, mail_pw: str = None, debug:bool = False, *attachments):
    print(f"Send email to {mail_to}")
    mail_host = settings.EMAIL_ADMIN_HOST if not mail_host else mail_host
    mail_port = settings.EMAIL_ADMIN_PORT if not mail_port else mail_port
    mail_from = settings.EMAIL_ADMIN if not mail_from else mail_from
    mail_pw = settings.EMAIL_ADMIN_PW if not mail_pw else mail_pw
    
    if not validate_email_address(mail_to):
        print(f"Email address is invalid: {mail_to}")
        raise invalid_email_exception()
    
    is_html = False
    # check if content is html
    if "</html" in content:
        is_html = True
    
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = mail_from
    msg['To'] = mail_to
    msg.attach(MIMEText(content, 'html')) if is_html else msg.attach(MIMEText(content, 'plain'))
    msg_string = msg.as_string()
    for att in attachments:
        msg.add_header('Content-Disposition', 'attachment', filename=att)
    print(f"Send email to {mail_to}")
    
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL(mail_host, mail_port, context=context) as server:
            if debug: server.set_debuglevel(1) # debug mode
            server.login(mail_from, mail_pw)
            server.sendmail(from_addr=mail_from, 
                            to_addrs= mail_to, 
                            msg= msg_string)
    except smtplib.SMTPRecipientsRefused as e:
        print(f"SMTPRecipientsRefused: {e}")
        return {"status": "fail", "detail": f"SMTPRecipientsRefused: {e}"}
    
    return {"status": "success", "detail": "Email sent successfully"}

def toss_confirm(toss_request: TossConfirmRequest, db: Session, email:str):
    conn = http.client.HTTPSConnection("api.tosspayments.com")

    payload = f"{{\"paymentKey\":\"{toss_request.payment_key}\",\"amount\":\"{toss_request.amount}\",\"orderId\":\"{toss_request.order_id}\"}}"

    headers = {
        'Authorization': "Basic dGVzdF9za19rNmJKWG1nbzI4ZWdHbDFiTUU2VkxBbkdLV3g0Og==",
        'Content-Type': "application/json"
        }

    print(f"headers: {headers}")
    print(f"payload: {payload}")
    
    conn.request("POST", "/v1/payments/confirm", payload, headers)

    res = conn.getresponse()
    data = res.read()
    
    print(data.decode("utf-8"))
    
    response = json.loads(data.decode("utf-8"))
    
    payment_history_db = PaymentHistoryDB()
    payment_history_db.email = email
    payment_history_db.order_id = toss_request.order_id
    payment_history_db.order_name = response["orderName"]
    payment_history_db.payment_key = toss_request.payment_key
    payment_history_db.amount = toss_request.amount
    payment_history_db.response = json.dumps(response)
    
    db.add(payment_history_db)
    db.commit()
    
    return response

def get_payment_history(email: str, db: Session):
    return json.loads(db.query(PaymentHistoryDB).filter(PaymentHistoryDB.email == email).all())

def get_items(item_id: int = None, db: Session = None, payment_class: str = None):
    if item_id and payment_class is None:
        return db.query(OrderclassesDB).filter(OrderclassesDB.id == item_id).first()
    elif item_id and payment_class: # item_id and payment_class, return specific item
        if payment_class == "credits":
            return db.query(OrderNamesCreditsDB).filter(OrderNamesCreditsDB.id == item_id).first()
        elif payment_class == "subs":
            return db.query(OrderNamesSubsDB).filter(OrderNamesSubsDB.id == item_id).first()
    elif item_id is None and payment_class: # payment_class, but no item_id, return all items
        if payment_class == "credits": 
            return db.query(OrderNamesCreditsDB).all()
        elif payment_class == "subs":
            return db.query(OrderNamesSubsDB).all()
    else:
        return db.query(OrderNamesCreditsDB).all() + db.query(OrderNamesSubsDB).all()

def get_random_string(length):
    # With combination of lower and upper case
    result_str = ''.join(random.choice(string.ascii_letters) for i in range(length))
    # print random string
    print(result_str)
    return result_str