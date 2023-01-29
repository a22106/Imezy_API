# -*- coding: utf-8 -*-
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os

from .config import settings

IMEZYEB_PW = os.getenv("imezy_db")
# IMEZY_DATABASE_URL = "mysql+pymysql://admin:{}@imezy.cfrm6ylsjgcg.ap-northeast-2.rds.amazonaws.com:3306/imezy?charset=utf8mb4".format(os.environ["imezy_db"])
IMEZY_DATABASE_URL = "mysql+pymysql://admin:{}@imezy.cfrm6ylsjgcg.ap-northeast-2.rds.amazonaws.com:3306/imezy?charset=utf8mb4".format(settings.IMEZY_DB_PW)


engine = create_engine(IMEZY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()