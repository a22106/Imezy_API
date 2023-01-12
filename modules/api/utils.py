import smtplib, ssl

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from jinja2 import Environment, select_autoescape, PackageLoader, FileSystemLoader

from email_validator import validate_email, EmailNotValidError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from .exceptions import invalid_email_exception
# from .logs import print_message
from .config import settings

def validate_email_address(email):
    try:
        print(f"Email address is valid: {email}")
        return True    
    except EmailNotValidError as e:
        return invalid_email_exception(e)

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
    with smtplib.SMTP_SSL(mail_host, mail_port, context=context) as server:
        if debug: server.set_debuglevel(1) # debug mode
        server.login(mail_from, mail_pw)
        server.sendmail(from_addr=mail_from, 
                        to_addrs= mail_to, 
                        msg= msg_string)
    
    return {"status": "success", "detail": "Email sent successfully"}
