from datetime import date
import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
from requests.sessions import session
from sqlalchemy import (
    Column,
    Integer,
    Float,
    String,
    VARCHAR,
    JSON,
    Sequence,
    UniqueConstraint,
    MetaData,
    Table,
)
from sqlalchemy.orm import sessionmaker

from sqlalchemy.orm import declarative_base
from sqlalchemy import create_engine
from os import path
from base64 import b64encode
from loguru import logger
from sqlalchemy import PrimaryKeyConstraint
from sqlalchemy.exc import IntegrityError
from requests.adapters import HTTPAdapter
import time

Base = declarative_base()


SQLITE = "sqlite"
FIELD_WEATHER = "FIELD_WEATHER"
api_key = "rcL6JaZwX8Vzemah8shK5HIQbaJlEvGe"  #should be removed for prod purposes
api_secret = "QF7c72TJEMOB3ALB"


def read_google_sheet():
    """
    Read google sheet with list of farms
    """
    sheet_url = "https://docs.google.com/spreadsheets/d/1Zz47QHb1Dz9IDEJJLb1LwwSBJRvB_ARz-4AxhXHAAWI/edit#gid=0"
    google_sheet_url = sheet_url.replace("/edit#gid=", "/export?format=csv&gid=")
    df = pd.read_csv(google_sheet_url)
    return df


def encode_keys(api_key, api_secret):
    """
    Encode api_key and api_secret
    """
    keys = {"consumer_key": api_key, "consumer_secret": api_secret}
    combination = "{consumer_key}:{consumer_secret}".format(**keys).encode()
    credentials = b64encode(combination).decode("utf8")
    return credentials


def get_access_token():
    """
    Login to get user access token
    """
    credentials = encode_keys(api_key, api_secret)
    response = requests.post(
        "https://api.awhere.com/oauth/token",
        data="grant_type=client_credentials",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic {}".format(credentials),
        },
    ).json()
    if "access_token" and "expires_in" in response.keys():
        return response


def get_weather_info(lat, long, day):
    """
    Query weather observations API to get weather info for a particular day
    """

    token = get_access_token()
    token["access_token"]

    response = requests.get(
        f"https://api.awhere.com/v2/weather/locations/{lat},{long}/observations/{day}",
        headers={"Authorization": "Bearer {}".format(token["access_token"])},
        timeout=10,
    )
    logger.info(f"Weather info {response} for day {day} ")
    if response.status_code == 429:
        logger.error(response)
    if response.status_code == 200:
        return response.json()
    return None


def create_field_weather_record(session):

    """
    Insert Weather Field Info into the table
    """
    first_day_of_the_month = pd.date_range(
        "2021-01-01", "2021-12-31", freq="1M"
    ) - pd.offsets.MonthBegin(1)
    for index, row in read_google_sheet().iterrows():
        for i, n in enumerate(first_day_of_the_month):
            results = get_weather_info(row["gps_lat"], row["gps_long"], n.date())
            if results is None:
                return None
            try:
                field_data = FieldWeather(
                    kom_id=row["kom_id"],
                    latitude=results["location"]["latitude"],
                    longitude=results["location"]["latitude"],
                    date=results["date"],
                    temperatures=results["temperatures"],
                    precipitation=results["precipitation"],
                    solar=results["solar"],
                    relative_humidity=results["relativeHumidity"],
                    wind=results["wind"],
                )
                session.add(field_data)
                session.commit()
                logger.info(
                    f"Saving Weather info for {field_data.kom_id} for day {field_data.date} "
                )
            except IntegrityError as e:
                logger.error(e)


class FieldWeather(Base):
    __tablename__ = "FieldWeather"
    __table_args__ = (PrimaryKeyConstraint("kom_id", "date"),)
    kom_id = Column(String, nullable=False)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    date = Column(String, nullable=False)
    temperatures = Column(JSON, nullable=False)
    precipitation = Column(JSON, nullable=False)
    solar = Column(JSON, nullable=False)
    relative_humidity = Column(JSON, nullable=False)
    wind = Column(JSON, nullable=False)


class MyDatabase:
    """
    Initialize DB Creation
    """

    DB_ENGINE = {SQLITE: "sqlite:///{DB}"}
    db_engine = None

    def __init__(self, dbtype, username="", password="", dbname=""):
        dbtype = dbtype.lower()
        if dbtype in self.DB_ENGINE.keys():
            engine_url = self.DB_ENGINE[dbtype].format(DB=dbname)
            self.db_engine = create_engine(engine_url)
            logger.info(f"DB Engine {self.db_engine}")
        else:
            print("DBType is not found in DB_ENGINE")

    def engine(self, dbtype, dbname=""):
        dbtype = dbtype.lower()
        engine_url = self.DB_ENGINE[dbtype].format(DB=dbname)
        return create_engine(engine_url)


def main():
    dbs = MyDatabase(SQLITE, dbname="mydb.weather")
    Base.metadata.create_all(dbs.db_engine)
    Session = sessionmaker(bind=dbs.db_engine)
    session = Session()
    create_field_weather_record(session)


if __name__ == "__main__":
    main()
