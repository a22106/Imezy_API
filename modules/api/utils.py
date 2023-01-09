import smtplib
from email_validator import validate_email, EmailNotValidError
from .exceptions import invalid_email_exception
from .logs import print_message
from email.mime.text import MIMEText
import json

with open('modules/api/configs.json', 'r') as f:
    IMEZY_CONFIG = json.load(f)

def validate_email_address(email):
    try:
        print_message(f"Email address is valid: {email}")
        return True    
    except EmailNotValidError as e:
        return invalid_email_exception(e)

def email_setting(email:str, password:str, type:str = None, port:int = 587, debug:bool = False):
    """
    args:
        email: email address
        password: password
        type: type of email server
        port: port number
    """
    
    mail_type = None
    if type is None:
        type = email.split('@')[1].split('.')[0]
    
    if type.lower() == 'g' or type.lower() == 'gmail':
        mail_type = "smtp.gmail.com"
    elif type.lower() == 'n' or type.lower() == 'naver':
        mail_type = "smtp.naver.com"
    elif type.lower() == 'm' or type.lower() == 'mailplug':
        mail_type = "smtp.mailplug.co.kr"
        port = 465
    else:
        raise Exception("Invalid email type. 'g' or 'gmail' for gmail, 'n' or 'naver' for naver, 'm' or 'mailplug' for mailplug")
    
    print_message(f"Email type: {mail_type}, port: {port}")
    
    # create SMTP session
    smtp = smtplib.SMTP(mail_type, port)
    if debug is True: smtp.set_debuglevel(1) # debug mode
    
    # smtp auth login
    smtp.ehlo() # say Hello
    if mail_type != "smtp.mailplug.co.kr":
        smtp.starttls()
    print_message(f"SMTP email login: {email}")
    smtp.login(email, password)
    
    return smtp

def send_email(receiver, subject, content):
    msg = MIMEText(content)
    msg['Subject'] = subject
    msg['From'] = IMEZY_CONFIG["email"]
    msg['To'] = receiver
    
    print_message(f"Send email to {receiver}")
    
    smtp = email_setting(IMEZY_CONFIG["email"], IMEZY_CONFIG["email_password"])
    smtp.sendmail(IMEZY_CONFIG["email"], receiver, msg.as_string())
    smtp.quit()
    
    return True