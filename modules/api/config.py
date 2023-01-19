from pydantic import BaseSettings, EmailStr

class Settings(BaseSettings):
    # database config
    IMEZY_DB_PW: str
    IMEZY_DB_USER: str
    IMEZY_DB_SERVER: str
    IMEZY_DB_PORT: int
    IMEZY_LOGO_140: str
    IMEZY_LOGO_250: str
    IMEZY_LOGO_IMEZY: str

    
    # jwt config
    JWT_ACCESS_KEY: str
    JWT_REFRESH_KEY: str
    GOOGLE_API_KEY: str
    JWT_ALGORITHM: str
    JWT_ACCESS_TOKEN_EXPIRE_HOURS: int
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int
    
    # email config
    EMAIL_ADMIN_HOST: str
    EMAIL_ADMIN_PORT: int
    EMAIL_USERNAME: str
    EMAIL_ADMIN_PW: str
    EMAIL_ADMIN: EmailStr
    
    # credits config
    DEFAULT_CREDITS: int
    CREDITS_PER_IMAGE: int
    
    # verification config
    VERIFICATION_EXPIRE_SECONDS: int
    VERIFICATION_MAIL_HTML_PATH: str
    
    # feedback config
    FEEDBACK_TYPE: dict
    
    
    class Config:
        env_file = "./modules/api/.env"
        env_file_encoding = "utf-8"
        
settings = Settings()