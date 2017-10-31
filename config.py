FLASK_DEBUG = False
PYCHARM_DEBUG=True
DEBUG_DATA_FILES=False
# Create dummy secrey key so we can use sessions
SECRET_KEY = '123456790'
SECRET_KEY_FILE = 'secret_key'

IS_MAINTENANCE_MODE = False

# Create in-memory database
DATABASE_FILE = 'river_db.sqlite'
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + DATABASE_FILE
SQLALCHEMY_ECHO = False

if PYCHARM_DEBUG:
  LOGFILE='/Users/danramage/tmp/log/river_view_site.log'
else:
  LOGFILE='/var/log/wq_rest/river_view_site.log'