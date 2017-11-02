import click
from flask import Flask, current_app, redirect, url_for, request
import logging.config
from logging.handlers import RotatingFileHandler
from logging import Formatter
import time
from app import db
from config import *
from wq_models import Project_Area, Sample_Site, Boundary, Site_Extent


app = Flask(__name__)
db.app = app
db.init_app(app)
# Create in-memory database
app.config['DATABASE_FILE'] = DATABASE_FILE
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_ECHO'] = SQLALCHEMY_ECHO

def init_logging(app):
  app.logger.setLevel(logging.DEBUG)
  file_handler = RotatingFileHandler(filename = LOGFILE)
  file_handler.setLevel(logging.DEBUG)
  file_handler.setFormatter(Formatter('%(asctime)s,%(levelname)s,%(module)s,%(funcName)s,%(lineno)d,%(message)s'))
  app.logger.addHandler(file_handler)

  app.logger.debug("Logging initialized")

  return


@app.cli.command()
@click.option('--params', nargs=2)
def build_sites(params):
  start_time = time.time()
  init_logging(app)
  site_name = params[0]
  output_file = params[1]
  current_app.logger.debug("build_sites started Site: %s Outfile: %s" % (site_name, output_file))
  try:
    sample_sites = db.session.query(Sample_Site) \
      .join(Site_Extent, Site_Extent.site_id == Sample_Site.id) \
      .join(Boundary, Sample_Site.boundaries) \
      .join(Project_Area, Project_Area.id == Sample_Site.project_site_id) \
      .filter(Project_Area.area_name == site_name).all()
  except Exception as e:
    current_app.logger.exception(e)
  else:
    try:
      with open(output_file, "w") as sample_site_file:
        #Write header
        row = 'WKT,EPAbeachID,SPLocation,Description,County,Boundary,ExtentsWKT\n'
        sample_site_file.write(row)
        for site in sample_sites:
          boundaries = []
          for boundary in site.boundaries:
            boundaries.append(boundary.boundary_name)
          #extents = []
          #for extent in site.extents:
          #  extents.append(extent.wkt_extent)
          row = '\"%s\",%s,%s,\"%s\",%s,\"%s\",\"%s\"\n' % (site.wkt_location,
                                       site.epa_id,
                                       site.site_name,
                                       site.description,
                                       site.county,
                                       ",".join(boundaries),
                                       site.extents[0].wkt_extent)
          sample_site_file.write(row)

    except (IOError, Exception) as e:
      current_app.logger.exception(e)

  current_app.logger.debug("build_sites finished in %f seconds" % (time.time()-start_time))

@app.cli.command()
@click.option('--params', nargs=2)
def build_boundaries(params):
  start_time = time.time()
  init_logging(app)
  site_name = params[0]
  output_file = params[1]
  current_app.logger.debug("build_boundaries started. Site: %s Outfile: %s" % (site_name, output_file))
  try:
    boundaries = db.session.query(Boundary) \
      .join(Project_Area, Project_Area.id == Boundary.project_site_id) \
      .filter(Project_Area.area_name == site_name).all()
  except Exception as e:
    current_app.logger.exception(e)
  else:
    try:
      with open(output_file, "w") as boundary_file:
        #Write header
        row = 'WKT,Name\n'
        boundary_file.write(row)
        for boundary in boundaries:
          row = '\"%s\",\"%s\"\n' % (boundary.wkt_boundary,
                                     boundary.boundary_name)
          boundary_file.write(row)

    except (IOError, Exception) as e:
      current_app.logger.exception(e)

  current_app.logger.debug("build_boundaries finished in %f seconds" % (time.time()-start_time))
