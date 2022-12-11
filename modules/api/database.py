from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# IMEZY_DATABASE_URL = "sqlite:///./database/imezy.db"


# engine = create_engine(
#     IMEZY_DATABASE_URL, connect_args={"check_same_thread": False}
# )
IMEZY_DATABASE_URL = "mysql+pymysql://admin:imezy2022!@imezy.cfrm6ylsjgcg.ap-northeast-2.rds.amazonaws.com:3306/imezy?charset=utf8mb4"


engine = create_engine(
    IMEZY_DATABASE_URL
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()