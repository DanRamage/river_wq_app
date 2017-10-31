from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
#from config import *

DATABASE_FILE = 'river_db.sqlite'
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + DATABASE_FILE
SQLALCHEMY_ECHO = False

"""
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
"""
app = Flask(__name__)
# Create in-memory database
app.config['DATABASE_FILE'] = DATABASE_FILE
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_ECHO'] = SQLALCHEMY_ECHO

db = SQLAlchemy(app)


migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)

class Project_Type(db.Model):
  __tablename__ = 'project_type'
  id = db.Column(db.Integer, primary_key=True)
  row_entry_date = db.Column(db.String(32))
  row_update_date = db.Column(db.String(32))
  name = db.Column(db.String(100))

  #Use the __str__ for the foreign key relationships.
  def __str__(self):
    return self.name


class Project_Area(db.Model):
  __tablename__ = 'project_area'
  id = db.Column(db.Integer, primary_key=True)
  row_entry_date = db.Column(db.String(32))
  row_update_date = db.Column(db.String(32))
  area_name = db.Column(db.String(100))
  display_name =  db.Column(db.String(100))
  #bounding_box = db.Column(Geometry(geometry_type='POLYGON', srid=4326))
  bounding_box = db.Column(db.Text)
  #area_message = db.relationship('WQ_Site_Message', backref='wq_area', uselist=False)

  site_type_id = db.Column(db.Integer, db.ForeignKey('project_type.id'))
  site_type = db.relationship('Project_Type', backref='project_area')

  column_filters = ('area_name', 'display_name', 'bounding_box', 'site_type')
  #Use the __str__ for the foreign key relationships.
  def __str__(self):
    return self.area_name

class Site_Message_Level(db.Model):
  __tablename__ = 'site_message_level'
  id = db.Column(db.Integer, primary_key=True)
  row_entry_date = db.Column(db.String(32))
  row_update_date = db.Column(db.String(32))

  message_level = db.Column(db.String(32))

  def __str__(self):
    return self.message_level

class Site_Message(db.Model):
  __tablename__ = 'site_message'
  id = db.Column(db.Integer, primary_key=True)
  row_entry_date = db.Column(db.String(32))
  row_update_date = db.Column(db.String(32))
  site_id = db.Column(db.Integer, db.ForeignKey('project_area.id'))
  message_level = db.Column(db.Integer, db.ForeignKey('site_message_level.id'))
  message = db.Column(db.String(512))

  site = db.relationship('Project_Area', backref='site_message')
  site_message_level = db.relationship('Site_Message_Level', backref='site_message')
  def __str__(self):
    return self.message


class Project_Info_Page(db.Model):
  __tablename__ = 'project_info_page'
  id = db.Column(db.Integer, primary_key=True)
  row_entry_date = db.Column(db.String(32))
  row_update_date = db.Column(db.String(32))
  site_id = db.Column(db.Integer, db.ForeignKey('project_area.id'))
  sampling_program = db.Column(db.String(128))
  url = db.Column(db.String(2048))
  description = db.Column(db.Text())
  swim_advisory_info = db.Column(db.Text())
  site = db.relationship('Project_Area', backref='project_info_page')

class Advisory_Limits(db.Model):
  __tablename__ = 'advisory_limits'
  id = db.Column(db.Integer, primary_key=True)
  row_entry_date = db.Column(db.String(32))
  row_update_date = db.Column(db.String(32))
  site_id = db.Column(db.Integer, db.ForeignKey('project_area.id'))
  min_limit = db.Column(db.Float)
  max_limit = db.Column(db.Float)
  icon = db.Column(db.String(32))
  limit_type = db.Column(db.String(32))

  site = db.relationship('Project_Area', backref='advisory_limits')

if __name__ == '__main__':
  manager.run()
