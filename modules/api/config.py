from pydantic import BaseSettings, EmailStr

class Settings(BaseSettings):
    IMEZY_DB_PW= str
    IMEZY_DB_USER= str
    IMEZY_DB_SERVER = str
    IMEZY_DB_PORT = int
    
    JWT_ACCESS_KEY: str
    JWT_REFRESH_KEY: str
    JWT_ALGORITHM: str
    JWT_ACCESS_TOKEN_EXPIRE_HOURS: int
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int
    
    EMAIL_HOST: str
    EMAIL_PORT: int
    EMAIL_USERNAME: str
    EMAIL_PASSWORD: str
    EMAIL_FROM: EmailStr
    
    DEFAULT_CREDITS: int
    CREDITS_PER_IMAGE: int
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        
settings = Settings()