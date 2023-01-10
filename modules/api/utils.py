import smtplib, ssl
import json

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from jinja2 import Environment, select_autoescape, PackageLoader, FileSystemLoader

from email_validator import validate_email, EmailNotValidError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from .exceptions import invalid_email_exception
from .logs import print_message


with open('/data/StableDiffusion/stable-diffusion-webui-test/modules/api/configs.json', 'r') as f:
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
    
    return smtp

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
    msg['From'] = IMEZY_CONFIG["email"]
    msg['To'] = receiver
    msg.attach(MIMEText(content, 'html')) if is_html else msg.attach(MIMEText(content, 'plain'))
    msg_string = msg.as_string()
    for att in attachments:
        msg.add_header('Content-Disposition', 'attachment', filename=att)
    print_message(f"Send email to {receiver}")
    
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(mail_server, mail_port, context=context) as server:
        server.login(IMEZY_CONFIG["email"], IMEZY_CONFIG["email_password"])
        server.sendmail(IMEZY_CONFIG["email"], receiver, msg_string)
    
    return {"status": "success", "detail": "Email sent successfully"}

from .config import settings
email_env = Environment(loader=FileSystemLoader('templates'), autoescape=select_autoescape(['html', 'xml']))
class EmailSchema(BaseModel):
    email: str
    subject: str
    body: str
    html: Optional[bool] = False
    
class Email:
    def __init__(self, username: str, url: str, email: List[EmailStr]):
        self.user = user
        self.url = url
        self.email = email