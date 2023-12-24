import os
from sqlalchemy import create_engine
from dotenv import load_dotenv
from src.db.models import Base

load_dotenv()
engine = create_engine(os.environ["POSTGRES"], echo=True)
Base.metadata.create_all(bind=engine)
