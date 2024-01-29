from flask_pymongo import PyMongo
class MongoContext:
  def __init__(self, app):
    self.app = app
    try:
      self.mongo = PyMongo(app)
    except Exception as e:
      raise ValueError(f'Failed to connect to Mongodb')