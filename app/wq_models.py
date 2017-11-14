from app import db

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
  site_id = db.Column(db.Integer, db.ForeignKey('project_area.id'), unique=True)
  message_lvl_id = db.Column(db.Integer, db.ForeignKey('site_message_level.id'))
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



class Boundary(db.Model):
  __table_name__ = 'boundary'
  id = db.Column(db.Integer, primary_key=True)
  row_entry_date = db.Column(db.String(32))
  row_update_date = db.Column(db.String(32))
  boundary_name  = db.Column(db.String(128), nullable=False)
  wkt_boundary = db.Column(db.Text, nullable=True)

  project_site_id = db.Column('project_site_id', db.Integer, db.ForeignKey('project_area.id'))
  project_site = db.relationship('Project_Area', backref='boundary')

  def __str__(self):
    return self.boundary_name

class Boundary_Mapper(db.Model):
  __table_name__ = 'boundary_mapper'
  sample_site_id = db.Column(db.Integer, db.ForeignKey('sample__site.id'), primary_key=True)
  boundary_id = db.Column(db.Integer, db.ForeignKey('boundary.id'), primary_key=True)



class Sample_Site(db.Model):
  __table_name__ = "sample_site"
  id = db.Column(db.Integer, primary_key=True)
  row_entry_date = db.Column(db.String(32))
  row_update_date = db.Column(db.String(32))

  project_site_id = db.Column('project_site_id', db.Integer, db.ForeignKey('project_area.id'))
  project_site = db.relationship('Project_Area', backref='sample_sites')

  latitude = db.Column(db.Float, nullable=True)
  longitude = db.Column(db.Float, nullable=True)
  wkt_location = db.Column(db.Text, nullable=False)

  site_name = db.Column(db.String(128), nullable=False)
  description = db.Column(db.Text, nullable=True)
  epa_id = db.Column(db.String(32), nullable=True)
  county = db.Column(db.String(32), nullable=True)
  issues_advisories = db.Column(db.Boolean, nullable=True)
  advisory_text = db.Column(db.String(32), nullable=True)
  temporary_site = db.Column(db.Boolean, nullable=False)
  boundaries = db.relationship(Boundary,
                             secondary='boundary__mapper',
                             primaryjoin=(Boundary_Mapper.sample_site_id == id),
                             backref='sample_site')
  extents = db.relationship("Site_Extent", backref='sample_site')

  def __str__(self):
    return self.site_name


class Site_Extent(db.Model):
  __table_name__ = 'site_extent'
  id = db.Column(db.Integer, primary_key=True)
  row_entry_date = db.Column(db.String(32))
  row_update_date = db.Column(db.String(32))
  extent_name  = db.Column(db.String(128), nullable=False)
  wkt_extent = db.Column(db.Text, nullable=True)

  site_id = db.Column(db.Integer, db.ForeignKey(Sample_Site.id))
  sample_site_name = db.relationship('Sample_Site', backref='site_extents', foreign_keys=[site_id])

