import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    MONGO_URI = "mongodb://" + os.getenv("MONGO_INITDB_ROOT_USERNAME") + ":" + os.getenv("MONGO_INITDB_ROOT_PASSWORD") + "@" + os.getenv(
        # type: ignore
        "MONGO_HOSTNAME") + ':27017/' + os.getenv("MONGO_DATABASE") + "?authSource=admin"

    SECRET_KEY = os.getenv("JWT_SECRET_KEY")
