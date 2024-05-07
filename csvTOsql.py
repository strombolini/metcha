from sqlalchemy import create_engine, Column, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import csv

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    email = Column(String, primary_key=True)
    password = Column(String)
    name = Column(String)

def create_db():
    engine = create_engine('sqlite:///metcha.db')  # Creates a SQLite database named metcha.db
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    with open('users.csv', 'r') as file:
        csv_file = csv.DictReader(file)
        for row in csv_file:
            user = User(email=row['email'], password=row['password'], name=row['name'])
            session.add(user)
    
    session.commit()
    session.close()

if __name__ == '__main__':
    create_db()
