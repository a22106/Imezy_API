import smtplib, ssl
import json

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from jinja2 import Environment, select_autoescape, PackageLoader, FileSystemLoader

from email_validator import validate_email, EmailNotValidError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from .exceptions import invalid_email_exception
from .logs import print_message
from .config import settings

with open('/data/StableDiffusion/stable-diffusion-webui-test/modules/api/configs.json', 'r') as f:
    IMEZY_CONFIG = json.load(f)

def validate_email_address(email):
    try:
        print_message(f"Email address is valid: {email}")
        return True    
    except EmailNotValidError as e:
        return invalid_email_exception(e)

def send_email(receiver, subject, content, *attachments):
    print(f"Send email to {receiver}")
    
    if not validate_email_address(receiver):
        return invalid_email_exception()
    
    mail_domain = IMEZY_CONFIG["email"].split('@')[1].split('.')[0]
    mail_port = 587
    if mail_domain == 'gmail':
        mail_server = "smtp.gmail.com"
        mail_port = 465
    elif mail_domain == 'naver':
        mail_server = "smtp.naver.com"
    elif mail_domain == 'mailplug':
        mail_server = "smtp.mailplug.co.kr"
        
    
    is_html = False
    # check if content is html
    if "</html>" in content:
        is_html = True
    
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = IMEZY_CONFIG["admin_email"]
    msg['To'] = receiver
    msg.attach(MIMEText(content, 'html')) if is_html else msg.attach(MIMEText(content, 'plain'))
    msg_string = msg.as_string()
    for att in attachments:
        msg.add_header('Content-Disposition', 'attachment', filename=att)
    print_message(f"Send email to {receiver}")
    
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(mail_server, mail_port, context=context) as server:
        server.login(IMEZY_CONFIG["admin_email"], IMEZY_CONFIG["admin_email_password"])
        server.sendmail(IMEZY_CONFIG["admin_email"], receiver, msg_string)
    
    return {"status": "success", "detail": "Email sent successfully"}
