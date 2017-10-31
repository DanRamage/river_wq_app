//Various helper functions
Math.roundTo = function(val, dec) {
  if (!isNaN(val)) {
    var mult = Math.pow(10,dec);
    return ( Math.round(val*mult) / mult );
  }
  else {
    return val;
  }
};
function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}

//Define key global variables and arrays
var userLat;
var userLng;
var dateSet;
var onlineStatus = 'on';

var current_date = new Date();
var markerType = 'advisories'; //Initial markers set to show forecast results

var advisory_limits;
var predictionData = {};
var has_prediction_data = false;
var currentEtcoc = {};
var has_sample_data = false;
var wq_site_name = "";
var wq_site_bbox;
var site;
var legendContentHtml = [];
var html_colors = {};
var latest_sample_date;

function initialize_app(site_name, data, limits) {
  site = site_name;
  advisory_limits = limits;

  if(data['prediction_data'].contents !== null ) {
    var forecast_date = data['prediction_data'].contents.testDate;
    $.each(data['prediction_data'].contents.stationData.features, function (i, beach) {
      predictionData[beach.properties.station] = {
        "station": beach.properties.station,
        "desc": beach.properties.desc,
        "ensemble": beach.properties.ensemble,
        "forecast_date": forecast_date,
        "message": beach.properties.message,
        "region": beach.properties.region,
        "lat": beach.geometry.coordinates[1],
        "lng": beach.geometry.coordinates[0]
      };
    });
    has_prediction_data = true;
  }
  if(data['advisory_data'].features !== null) {
    var latest_ms = 0;
    $.each(data['advisory_data'].features, function (s, stations) {
      permanentAdvisory = stations.properties.sign;

      $.each(stations.properties.test, function (i, j) {

        //Determine if an advisory is in place (permanent or temporary based on ETCOC of 104)
        if (parseInt(j.value, 10) >= limits["High"].min_limit || permanentAdvisory === true) {
          if (permanentAdvisory === true) {
            advisoryText = 'Long Term';
          }
          else {
            advisoryText = 'Yes';
          }
        }
        else {
          advisoryText = 'None';
        }

        currentEtcoc[stations.properties.station] = {
          "desc": stations.properties.desc,
          "date": j.date,
          "lat": stations.geometry.coordinates[1],
          "lng": stations.geometry.coordinates[0],
          "value": j.value,
          "advisory": advisoryText
        };
        if('extents_geometry' in stations.properties)
        {
          currentEtcoc[stations.properties.station]['extents_geometry'] = stations.properties.extents_geometry.geometry.coordinates[0];
        }
        var date_time = j.date.split(' ');
        var sample_date_ms = Date.parse(date_time[0]);
        if(latest_sample_date === undefined || latest_ms < sample_date_ms)
        {
          latest_sample_date = date_time[0];
          latest_ms = sample_date_ms;
        }
      });
    });
    has_sample_data = true;
  }
  if(has_prediction_data) {
    var forecast_legend = [
      '<div></div><p><strong>Today\'s forecasted conditions</strong></p>',
      '<div style="float:left;padding-right:10px;">'];
    forecast_legend.push('<img src="static/images/none_marker.png" /> No forecast available<br />');
    if("Low" in advisory_limits) {
      forecast_legend.push('<img src="static/images/' + advisory_limits["Low"].icon + '" /> Low bacteria level</div>');
    }
    forecast_legend.push('<div style="float:left">');
    if("Medium" in advisory_limits) {
      forecast_legend.push('<img src="static/images/' + advisory_limits["Medium"].icon + '" /> Medium bacteria level<br />');
    }
    if("High" in advisory_limits) {
      forecast_legend.push('<img src="static/images/' + advisory_limits["High"].icon + '" /> High bacteria level</div>');
    }
    forecast_legend.push('<br style="clear:both"><a class="ui-btn ui-btn-corner-all ui-mini ui-btn-up-c" data-theme="c" data-wrapperels="span" data-corners="true" href="#moreInformation" data-role="button" data-mini="true" style="padding:0.4em 1em;"><span class="ui-btn-inner ui-btn-corner-all"><span class="ui-btn-text">More Info</span></span></a></div>');
    legendContentHtml['forecast'] = forecast_legend.join('');
  }
  if(has_sample_data) {
    var advisories_legend = [];
    advisories_legend.push('<div><p><strong>Swim advisories</strong></p>');
    if("Low" in advisory_limits) {
      advisories_legend.push('<p><img src="static/images/' + advisory_limits["Low"].icon + '" /> None: no swimming advisory issued - safe to swim.<br />');
    }
    if("Medium" in advisory_limits) {
      advisories_legend.push('<img src="static/images/' + advisory_limits["Medium"].icon + '" /> Medium bacteria level<br />');
    }
    if("High" in advisory_limits) {
      advisories_legend.push('<img src="static/images/' + advisory_limits["High"].icon + '" /> Yes: an advisory is current - swimming not recommended.</br>');
    }
    advisories_legend.push('<img src="static/images/none_marker.png" />No data available or data older than 30 days.<br /></p><a class="ui-btn ui-btn-corner-all ui-mini ui-btn-up-c" data-theme="c" data-wrapperels="span" data-corners="true" href="#moreInformation" data-role="button" data-mini="true" style="padding:0.4em 1em;"><span class="ui-btn-inner ui-btn-corner-all"><span class="ui-btn-text">More Info</span></span></a></div>');
    legendContentHtml['advisories'] =  advisories_legend.join('');
    /*
    legendContentHtml['advisories'] = '<div><p><strong>Swim advisories</strong></p>' +
      '<p><img src="static/images/"' + advisory_limits["Low"].icon + '" /> None: no swimming advisory issued - safe to swim.<br />' +
      '<img src="static/images/"' + advisory_limits["High"].icon + '" /> Yes: an advisory is current - swimming not recommended.</br>' +
      '<img src="static/images/none_marker.png" />No data available or data older than 30 days.<br /></p><a class="ui-btn ui-btn-corner-all ui-mini ui-btn-up-c" data-theme="c" data-wrapperels="span" data-corners="true" href="#moreInformation" data-role="button" data-mini="true" style="padding:0.4em 1em;"><span class="ui-btn-inner ui-btn-corner-all"><span class="ui-btn-text">More Info</span></span></a></div>';
    */
    var data_legend = [];
    data_legend.push('<div><p><strong>Bacteria level data</strong></p>');
    data_legend.push('<div style="float:left;padding-right:10px;">');
    data_legend.push('<img src="static/images/none_marker.png" /> No data available<br />');
    if("Low" in advisory_limits)
    {
      data_legend.push('<img src="static/images/' + advisory_limits["Low"].icon + '" /> Low bacteria level</div>');
    }
    data_legend.push('<div style="float:left">');
    if("Medium" in advisory_limits) {
      data_legend.push('<img src="static/images/' + advisory_limits["Medium"].icon + '" /> Medium bacteria level<br />');
    }
    if("High" in advisory_limits) {
      data_legend.push('<img src="static/images/' + advisory_limits["High"].icon + '" /> High bacteria level</div>');
    }
    data_legend.push('<br style="clear:both"><a class="ui-btn ui-btn-corner-all ui-mini ui-btn-up-c" data-theme="c" data-wrapperels="span" data-corners="true" href="#moreInformation" data-role="button" data-mini="true" style="padding:0.4em 1em;"><span class="ui-btn-inner ui-btn-corner-all"><span class="ui-btn-text">More Info</span></span></a></div>')
    legendContentHtml['data'] = data_legend.join('');
    /*
    legendContentHtml['data'] = '<div><p><strong>Bacteria level data</strong></p>' +
      '<div style="float:left;padding-right:10px;">' +
      '<img src="static/images/none_marker.png" /> No data available<br />' +
      '<img src="static/images/"' + advisory_limits["Low"].icon + '" /> Low bacteria level</div>' +
      '<div style="float:left">' +
      '<img src="static/images/"' + advisory_limits["Medium"].icon + '" /> Medium bacteria level<br />' +
      '<img src="static/images/"' + advisory_limits["High"].icon + '" /> High bacteria level</div>' +
      '<br style="clear:both"><a class="ui-btn ui-btn-corner-all ui-mini ui-btn-up-c" data-theme="c" data-wrapperels="span" data-corners="true" href="#moreInformation" data-role="button" data-mini="true" style="padding:0.4em 1em;"><span class="ui-btn-inner ui-btn-corner-all"><span class="ui-btn-text">More Info</span></span></a></div>';
      */
  }

  //Get the HTML color codes for low/medium/high/none
  var dummy = $('<div class="popup_label_low" style="display: none;"></div>').appendTo('body');
  var color = dummy.css('background-color');
  dummy.remove();
  html_colors['Low'] = color;

  var dummy = $('<div class="popup_label_medium" style="display: none;"></div>').appendTo('body');
  var color = dummy.css('background-color');
  dummy.remove();
  html_colors['Medium'] = color;

  var dummy = $('<div class="popup_label_high" style="display: none;"></div>').appendTo('body');
  var color = dummy.css('background-color');
  dummy.remove();
  html_colors['High'] = color;

  var dummy = $('<div class="popup_label_none" style="display: none;"></div>').appendTo('body');
  var color = dummy.css('background-color');
  dummy.remove();
  html_colors['None'] = color;

  $("a#message_link").click(function(event){
      $("#about").collapsible("collapse");
      $("#faq").collapsible("expand");
    });

  return;
}


function days_between(date1, date2) {

    // The number of milliseconds in one day
    var ONE_DAY = 1000 * 60 * 60 * 24;

    // Convert both dates to milliseconds
    var date1_ms = date1.getTime();
    var date2_ms = date2.getTime();

    // Calculate the difference in milliseconds
    var difference_ms = Math.abs(date1_ms - date2_ms);

    // Convert back to days and return
    return Math.round(difference_ms/ONE_DAY);

}


function toRad(degrees){
    return degrees * Math.PI / 180;
}

function calcDistance(lat1,lng1,lat2,lng2){
  var R = 6371; // Radius of the earth in km
  var dLat = toRad(lat2-lat1);  // Javascript functions in radians
  var dLng = toRad(lng2-lng1);
  var a = Math.sin(dLat/2) * Math.sin(dLat/2) +
          Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
          Math.sin(dLng/2) * Math.sin(dLng/2);
  var c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  var d = R * c; // Distance in km
  return d;
}

/*
function GetURLParameter(sParam)
{
  var sPageURL = window.location.search.substring(1);
  var sURLVariables = sPageURL.split('&');
  for (var i = 0; i < sURLVariables.length; i++)
  {
    var sParameterName = sURLVariables[i].split('=');
    if (sParameterName[0] == sParam)
    {
      return sParameterName[1];
    }
  }
  return null;
}
*/
/*
function GetSiteFromURL(url)
{
  //Split the domain components up to get the subdomain which should be the
  //site of interest.
  //var domain_components= url.split('.');
  var path = url.split('/');
  return(path[1]);
}

function strtr(str,list){
  for( var c in list ){
    str = String(str).replace( new RegExp( c ,"g"), list[c] );
  }
  return str;
}
*/
function capitalize (text) {
    return text.charAt(0).toUpperCase() + text.slice(1).toLowerCase();
}


function getScreenSize(dimension){
  if(dimension == 'width'){
    return window.innerWidth ? window.innerWidth : $(window).width();
  }
  if(dimension == 'height'){
    return window.innerHeight ? window.innerHeight : $(window).height();
  }
}


var month=[];
month[0]="Jan";
month[1]="Feb";
month[2]="Mar";
month[3]="Apr";
month[4]="May";
month[5]="Jun";
month[6]="Jul";
month[7]="Aug";
month[8]="Sep";
month[9]="Oct";
month[10]="Nov";
month[11]="Dec";


//Need this because Safari can't handle iso8601 with the JS Date.parse function - all other browsers work though
//Options
//parseDate('06.21.2010', 'mm.dd.yyyy');
//parseDate('21.06.2010', 'dd.mm.yyyy');
//parseDate('2010/06/21', 'yyyy/mm/dd');
//parseDate('2010-06-21');

function parseDate(input, format) {
  if(typeof input !== "undefined" && input.length) {
    format = format || 'yyyy-mm-dd'; // default format
    var parts = input.match(/(\d+)/g),
        i = 0, fmt = {};
    // extract date-part indexes from the format
    format.replace(/(yyyy|dd|mm)/g, function(part) { fmt[part] = i++; });

    //return Date.UTC(parts[fmt['yyyy']], parts[fmt['mm']]-1, parts[fmt['dd']]);
    return Date.parse(month[parseInt(parts[fmt['mm']]-1, 10)] + ' ' + parts[fmt['dd']] + ', ' + parts[fmt['yyyy']]);
  }
}


function ISODateString(d){
 function pad(n){return n<10 ? '0'+n : n;}
 return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate());
}


function date_by_subtracting_days(date, days) {
    return new Date(
        date.getFullYear(),
        date.getMonth(),
        date.getDate() - days,
        date.getHours(),
        date.getMinutes(),
        date.getSeconds(),
        date.getMilliseconds()
    );
}



//Function for changing the marker types on the main map when user clicks one of the buttons at bottom right of map
function changeMapMarker(dataType){
  markerType = dataType;
  mapType = $('#map_canvas').gmap('getType');

  if(getScreenSize('height') > getScreenSize('width')){
    legendWidth = "275";
    infoPopupWidth = "200";
    infoPopupHeight = "200";
  }
  else{
    legendWidth = "400";
    infoPopupWidth = "370";
    infoPopupHeight = "130";
  }

  $('#map_canvas').gmap('clearControl',google.maps.ControlPosition.RIGHT_BOTTOM); //Clearing prevents position migration downwards
  legendMain = new Legend("Legend", "80px", legendContentHtml[dataType], legendWidth+'px'); //Redefine legend text for new marker type

  $('#map_canvas').gmap('clear', 'markers');

  populateMarkers(false); //false refers to not setting the map zoom to the marker bounds - this prevents re-zooming/centering of the map when changing the marker type
  mapUserMarker();

  $('#markerTypeSelector').trigger('create'); //Applies JQM styling to the markerTypeSelector radio buttons
}


//Functions for geolocating user and displaying them on the map - need to consolidate extra "detail" map code into main function
var markerMapped;

function mapUserMarker(){
  var clientPosition = new google.maps.LatLng(userLat, userLng);
  $('#map_canvas').gmap('addMarker', {'position': clientPosition, 'icon': 'static/images/blue_dot_circle.png', 'bounds': false});
  markerMapped = 1;

  if((userLat > 33.501 && userLat < 33.880) && (userLng > -79.067 && userLng < -78.511)){ //Check if user is in the area and if so, zoom in to their location
    $('#map_canvas').gmap('option', 'zoom', 11);
    $('#map_canvas').gmap('option', 'center', new google.maps.LatLng(userLat,userLng));
    $('#map_canvas').gmap('refresh');
  }

}


function initializeGeoDetail() {
  if (navigator.geolocation) {

    navigator.geolocation.getCurrentPosition(
      onSuccessDetail);
  }
  else {
    alert('Geolocation not supported.');
  }
}

function onSuccessDetail(position) {
  userLat = position.coords.latitude;
  userLng = position.coords.longitude;

  var clientPosition = new google.maps.LatLng(userLat, userLng);
  $('#detail_map_canvas').gmap('addMarker', {'position': clientPosition, 'icon': 'static/images/blue_dot_circle.png', 'bounds': false});
}



function onLocationSuccess(position) {
  userLat = position.coords.latitude;
  userLng = position.coords.longitude;
  //userLat = 33.726856; //fake user lat for testing
  //userLng = -78.927974; //fake user lng for testing

  if ($("#beachListPage").is(".ui-page-active")){
    $('#beachListPage').trigger('pageinit');
  }

  if ($("#mapPage").is(".ui-page-active")){
    mapUserMarker();
  }
}



function getUserLocation() {
  if (navigator.geolocation) {
    navigator.geolocation.getCurrentPosition(
      onLocationSuccess);
  }
  else {
    alert('Geolocation not supported.');
  }
}


document.addEventListener("deviceready", function(){

    function onDeviceReady() {
      StatusBar.hide();
    }

    //navigator.geolocation.getCurrentPosition(onsuccess, onerror, params);
    getUserLocation();
    navigator.splashscreen.hide();
}, false);






//Redirect to Offline page on pageshow if internet is not available
$('[data-role="page"]').on('pageshow', function () {
  if(onlineStatus == 'off') $.mobile.pageContainer.pagecontainer('change', '#offlineMessage');
});


waitUntilExists("markerTypeSelector",function(){
  $('#markerTypeSelector').trigger('create'); //Applies JQM styling to the markerTypeSelector radio buttons
});

waitUntilExists("homeResetButton",function(){
  $('#homeResetButton').trigger('create'); //Applies JQM styling to the home reset button
});


$(window).bind('orientationchange', function(e) {
  //alert('orientationchange: '+e.orientation);
  $(window).trigger('resize');
});

$(window).bind('resize', function(e) {
  if ($("#beachDetailsPage").is(".ui-page-active")){
    $('#beachDetailsPage').trigger('pageshow');
  }
  if ($("#mapPage").is(".ui-page-active")){
    $('#mapPage').trigger('pageshow');

    //alert('H:'+getScreenSize('height')+' W:'+getScreenSize('width'));
    //if(e.orientation == 'portrait'){
    if(getScreenSize('height') > getScreenSize('width')){
      legendWidth = "275";
      infoPopupWidth = "200";
      infoPopupHeight = "200";
    }
    else{
      legendWidth = "400";
      infoPopupWidth = "370";
      infoPopupHeight = "130";
    }

    $('#legend').width(legendWidth);
    $('#map_canvas').gmap('closeInfoWindow'); //close it because it will have the wrong dimensions for new screen orientation

  }
});

// Apply loading spinner for all clicks accept those with 'noloader' class
$('a:not(.noloader)').on('click', function() {
  $(window).bind('hashchange', function() {
    $('body').addClass('ui-loading');
  });
});


//Retrieve the GET parameters - used for beach details page - makes use of the jqm.page.params.js script
$(document).bind("pagebeforechange", function( event, data ) {
  $.mobile.pageData = (data && data.options && data.options.pageData) ? data.options.pageData : null;
});


//Populate predictionData array with needed parameters for all stations.
//Using $.ajax and async: false, rather than $.getJSON to ensure that predictionData is populated before pages try to use it.


//Get monitoring data and populate currentEtcoc array for all stations
//Using $.ajax and async: false, rather than $.getJSON to ensure that currentEtcoc is populated before pages try to use it.

if(onlineStatus != 'off'){

  function calcDataRating(etcoc, station_data) {
    var rating = 'none';
    var station_sample_date = station_data.date;
    var advisory = station_data.advisory;

    if(advisory=='Yes' || advisory=='Long Term')
    {
      rating = 'high';
    }
    else {
      if (station_sample_date !== undefined && station_sample_date.length) {
        var sampleDate = parseDate(station_sample_date);

        sampleDate = new Date(sampleDate);

        //remove > and < for calculating color
        if (typeof etcoc !== 'undefined') {
          //DWR 2015-12-10
          //Verify that the etcoc is a string.
          if (typeof etcoc === "string") {
            etcoc = etcoc.replace('>', '').replace('<', '');
          }
        }

        if (etcoc == 'None' || days_between(new Date(), sampleDate) > 30) {
          rating = 'none';
        }
        else if((isNaN(etcoc) || etcoc <= advisory_limits["Low"].max_limit) ||
          (etcoc > advisory_limits["Low"].max_limit && etcoc <= advisory_limits["Medium"].max_limit))
        {
          rating = 'low';
        }
        /*
        else if (etcoc > advisory_limits["Low"].max_limit && etcoc <= advisory_limits["Medium"].max_limit) {
          rating = 'medium';
        }
        */
        else {
          rating = 'high';
        }
      }
    }
    return  rating;
  }

  function calcAdvisoryRating(station){
    var rating = 'none';
    var advisory = station.advisory;
    if(advisory == 'Long Term')
    {
      rating = 'high';
    }
    else
    {
      if(station.date.length) {
        var date = station.date;
        var data_age_days = days_between(new Date(), new Date(date));
        if (data_age_days > 30) {
          rating = 'none';
        }
        else {
          if (advisory == 'Yes') {
            rating = 'high';
          }
          else {
            rating = 'low';
          }
        }
      }
    }
    return rating;

  }
  function get_bacteria_style(station, etcoc)
  {
    var css_class = 'popup_label_none';
    var station_sample_date = station.date;

    if (station_sample_date !== undefined && station_sample_date.length)
    {
      var sampleDate = parseDate(station_sample_date);

      sampleDate = new Date(sampleDate);

      //remove > and < for calculating color
      if (typeof etcoc !== 'undefined') {
        if (typeof etcoc === "string") {
          etcoc = etcoc.replace('>', '').replace('<', '');
        }
      }

      if (etcoc == 'None' || days_between(new Date(), sampleDate) > 30) {
        css_class = 'popup_label_none';
      }
      else if (isNaN(etcoc) || etcoc <= advisory_limits["Low"].max_limit) {
        css_class = 'popup_label_low';
      }
      else if (("Medium" in advisory_limits) && (etcoc > advisory_limits["Low"].max_limit && etcoc <= advisory_limits["Medium"].max_limit)) {
        css_class = 'popup_label_medium';
      }
      else {
        css_class = 'popup_label_high';
      }
    }

    return(css_class);
  }
  function get_advisory_style(station)
  {
    var css_class = 'popup_label_none';
    var advisory = station.advisory;
    if(advisory == 'Long Term')
    {
      css_class = 'popup_label_high';
    }
    else
    {
      if(station.date.length) {
        var date = station.date;
        var data_age_days = days_between(new Date(), new Date(date));
        if (data_age_days > 30) {
          css_class = 'popup_label_nodata';
        }
        else {
          if (advisory == 'Yes') {
            css_class = 'popup_label_high';
          }
          else {
            css_class = 'popup_label_low';
          }
        }
      }
    }
    return css_class;
  }

  function latest_sample_date_div()
  {
    this.name = "LatestSample";
    var container = document.createElement("div");
    container.setAttribute('id', 'latest_sample');
    container.style.position = "relative";
    container.style.margin = "5px 5px 5px 5px";
    container.style.zIndex = "9999999999999999999999999";

    var legendButtonHtml = '<div style="padding:3px" class="ui-btn ui-input-btn ui-corner-all ui-mini">' +
            'Latest Sample: ' + latest_sample_date +
           '</div>';

    container.innerHTML = legendButtonHtml;
    this.div = container;
  };
  //Map legend setup
  function Legend(name, controlWidth, content, contentWidth) {
    this.name = name;
    this.content = content;

    var container = document.createElement("div");
    container.style.position = "relative";
    container.style.margin = "0 10px 5px 5px";
    container.style.zIndex = "9999999999999999999999999";

    var legendButtonHtml = '<div style="padding:3px" class="ui-btn ui-input-btn ui-corner-all ui-mini">' +

                   name +

               '</div>' +
               '<div id="legend" class="legend" style="display: none;width: ' + contentWidth + '">' +
               '<div id="legend_close" style="width: 18px; height: 18px; overflow: hidden; position: absolute; opacity: 0.7; right: 12px; top: 12px; z-index: 10000; cursor: pointer;"><img src="http://maps.gstatic.com/mapfiles/api-3/images/mapcnt3.png" draggable="false" style="position: absolute; left: -2px; top: -336px; width: 59px; height: 492px; -webkit-user-select: none; border: 0px; padding: 0px; margin: 0px;"></div>' +
                 content +
               '</div>';

    container.innerHTML = legendButtonHtml;
    this.div = container;

    var control = container.childNodes[0];
    var legend  = container.childNodes[1];
    var legendCloseButton = container.childNodes[1].childNodes[0];

    control.onclick = toggle;
    legendCloseButton.onclick = toggle;


    function toggle() {
      if (legend.style.display == "none") {
        legend.style.display = "block";
      } else {
        legend.style.display = "none";
      }
    }
  }

  if(getScreenSize('height') > getScreenSize('width')){
    legendWidth = "275";
    infoPopupWidth = "200";
    infoPopupHeight = "200";
  }
  else{
    legendWidth = "400";
    infoPopupWidth = "370";
    infoPopupHeight = "130";
  }



  function resetHome(zoom, center){
    $('#map_canvas').gmap('option', 'center', center);
    $('#map_canvas').gmap('option', 'zoom', zoom);
  }


  //Home/reset button setup
  function Button(name) {

    var content = '<input type="button" data-mini="true" data-role="button" name="home" id="home" data-icon="home" data-iconpos="notext" onclick="resetHome(initialZoom,initialCenter);" />';

    this.name = name;
    this.content = content;

    var container = document.createElement("div");
    container.id = "homeResetButton";
    container.style.position = "relative";
    container.style.margin = "0 0 0 5px";
    container.style.padding = "3px";
    container.innerHTML = content;
    this.div = container;

  }

  var homeButton = new Button("Home");



  //Function for populating main overview map with markers
  function populateMarkers(bounds){

      $.each( currentEtcoc, function(i, station) {
        var forecast = 'None';
        var station_message = '';

        forecast = 'None';
        station_message = '';
        if(Object.keys(predictionData).length && i in predictionData) {
          //Map markers
          if (typeof predictionData[i] === "undefined" || predictionData[i].ensemble == "NO TEST") {
            forecast = 'None';
          }
          else {
            forecast = predictionData[i].ensemble;
          }

          if (typeof predictionData[i].message !== 'undefined') {
            station_message = predictionData[i].message;
          }
          else {
            station_message = '';
          }
        }
        var dateIcon = '';

        var sample_date = '';
        if (typeof station.date === "undefined" || station.date.length === 0) {
          dateIcon = '';
          var data = 'None';
        }
        else {
          var sample_date = new Date(parseDate(station.date));
          dateIcon = ' (' + sample_date.getDate() + ' ' + month[sample_date.getMonth()] + ' \'' + sample_date.getFullYear().toString().substr(2, 2) + ')';
          var data = station.value;
        }

        if (markerType == 'forecast') {
          markerRating = forecast;
        }

        if (markerType == 'advisories') {
          markerRating = calcDataRating(data, station);
        }
        //https://developers.google.com/maps/documentation/javascript/reference#MapTypeControlStyle for options to disable other elements on the map
        var myStyles = [
          {
            featureType: "poi",
            elementType: "labels",
            stylers: [
              {visibility: "off"}
            ]
          }
        ];

        $('#map_canvas').gmap('option', 'mapTypeId', google.maps.MapTypeId.MAP);
        $('#map_canvas').gmap('option', 'styles', myStyles);
        $('#map_canvas').gmap('option', 'disableDefaultUI', true); //disable all controls then add in what we want
        $('#map_canvas').gmap('option', 'mapTypeControl', true);
        $('#map_canvas').gmap('option', 'streetViewControl', true);
        $('#map_canvas').gmap('option', 'mapTypeControlOptions', {style: google.maps.MapTypeControlStyle.DROPDOWN_MENU});

        var marker_rating = capitalizeFirstLetter(markerRating);
        var marker_icon;
        if(marker_rating !== 'None') {
          marker_icon = 'static/images/' + advisory_limits[marker_rating].icon;
        }
        else
        {
          marker_icon =  'static/images/none_marker.png';
        }

        //'static/images/' + markerRating.toLowerCase() + '_marker.png'
        $('#map_canvas').gmap('addMarker', {
          'position': new google.maps.LatLng(station.lat, station.lng),
          'icon': marker_icon,
          'bounds': bounds
        }).click(function ()
        {
          var popup_items = [];
          if(has_prediction_data) {
            popup_items.push('<div class="info_popup_forecast_outer_div"><div id="info_popup_forecast" class="info_popup_forecast_inner_div">Forecast (' + new Date().getDate() + ' ' + month[new Date().getMonth()] + ')&nbsp;&nbsp;&nbsp;<span class="popup_label_' + forecast.toLowerCase().replace(' ', '') + '">' + capitalize(forecast) + '</span></div></div>');
          }
          if(has_sample_data) {
            popup_items.push('<div class="info_popup_advisory_outer_div"><div id="info_popup_advisory" class="info_popup_advisory_inner_div">Advisory&nbsp;&nbsp;&nbsp;<span class="' + get_advisory_style(station) + '">' + station.advisory.replace("<br />", " ") + '</span></div></div><br style="clear:both">');
            popup_items.push('<div class="info_popup_data_outer_div"><div id="info_popup_sample_data" class="info_popup_data_inner_div">Bacteria Data' + dateIcon + '&nbsp;&nbsp;&nbsp;<span class="' + get_bacteria_style(station, data) + '">' + data + '</span></div></div>');
          }
          var site_popup = '<div id="infoPopup" style="width:' + infoPopupWidth + 'px;height:' + infoPopupHeight + 'px;clear:both;white-space:nowrap;line-height:normal;"><strong>' + station.desc + '</strong>' +
                        '<div>' +
                        popup_items.join('') +
                        '<div style="float:left;padding-left:30px;">' +
                        '<div>' +
                          '<a style="float:right;margin:10px 0;padding:6px 12px 3px 12px;" class="ui-btn ui-btn-corner-all ui-mini ui-btn-up-c" data-theme="c" data-wrapperels="span" data-history="false" data-corners="true" href="#beachDetailsPage?id=' + i + '" data-role="button" data-icon="info" data-mini="true">' +
                            '<span class="ui-btn-inner ui-btn-corner-all">' +
                              '<span class="ui-btn-text">More Details</span>' +
                              '<span class="ui-icon ui-icon-info ui-icon-shadow">&nbsp;</span>' +
                            '</span>' +
                          '</a>' +
                        '</div>' +
                        '</div>' +
                        '<div style="clear:both;white-space:normal;">' + station_message + '</div>' +
                        '</div>' +
                        '</div>';

          /*
          var site_popup = '<div id="infoPopup" style="width:' + infoPopupWidth + 'px;height:' + infoPopupHeight + 'px;clear:both;white-space:nowrap;line-height:normal;"><strong>' + station.desc + '</strong>' +
                        '<div>' +
                        '<div style="float:left;padding-right:20px;padding-top:15px;">' +
                          '<div id="info_popup_forecast" style="text-align:right">Forecast (' + new Date().getDate() + ' ' + month[new Date().getMonth()] + ')&nbsp;&nbsp;&nbsp;<span class="popup_label_' + forecast.toLowerCase().replace(' ', '') + '">' + capitalize(forecast) + '</span></div>' +
                        '</div>' +
                        '<div style="float:left;padding-top:15px;">' +
                          '<div id="info_popup_advisory" style="text-align:right">Advisory&nbsp;&nbsp;&nbsp;<span class="' + get_advisory_style(station) + '">' + station.advisory.replace("<br />", " ") + '</span></div>' +
                        '</div><br style="clear:both">' +
                        '<div style="float:left;padding-right:20px;padding-top:15px;">' +
                          '<div id="info_popup_sample_data" style="text-align:right">Bacteria Data' + dateIcon + '&nbsp;&nbsp;&nbsp;<span class="' + get_bacteria_style(station, data) +'">' + data + '</span></div>' +
                        '</div>' +
                        '<div style="float:left;padding-left:30px;">' +
                          '<div><a style="float:right;margin:10px 0;padding:6px 12px 3px 12px;" class="ui-btn ui-btn-corner-all ui-mini ui-btn-up-c" data-theme="c" data-wrapperels="span" data-history="false" data-corners="true" href="#beachDetailsPage?id=' + i + '" data-role="button" data-icon="info" data-mini="true"><span class="ui-btn-inner ui-btn-corner-all"><span class="ui-btn-text">More Details</span><span class="ui-icon ui-icon-info ui-icon-shadow">&nbsp;</span></span></a></div>' +
                        '</div>' +
                        '<div style="clear:both;white-space:normal;">' + station_message + '</div>' +
                        '</div>' +
                        '</div>'
          */
          $('#map_canvas').gmap('openInfoWindow',
            {'content': site_popup}, this);
          ga('send', {
            hitType: 'event',
            eventCategory: 'SampleSiteClick',
            eventAction: 'click',
            eventLabel: station.desc
          });

        });

        if('extents_geometry' in station)
        {
          var line_path = [];
          $.each(station.extents_geometry, function(ndx, coord)
          {
            line_path.push({lat: coord[1], lng: coord[0]});
          });
          var g_map = $('#map_canvas').gmap('get', 'map');
          var z_index = 1;
          if(marker_rating == "High")
          {
            z_index = 99999;
          }
          new google.maps.Polyline({
            path: line_path,
            strokeWeight: 3,
            strokeOpacity: 0.75,
            strokeColor: html_colors[marker_rating],
            map: g_map,
            zIndex: z_index
          });
        }
      });
    /*
    click(function () {
              $('#map_canvas').gmap('openInfoWindow', {
                'content': '<div id="infoPopup" style="width:' + infoPopupWidth + 'px;height:' + infoPopupHeight + 'px;clear:both;white-space:nowrap;line-height:normal;"><strong>' + station.desc + '</strong>' +
                '<div>' +
                '<div style="float:left;padding-right:20px;padding-top:15px;"><div style="text-align:right">Forecast (' + new Date().getDate() + ' ' + month[new Date().getMonth()] + ')&nbsp;&nbsp;&nbsp;<span class="popup_label_' + forecast.toLowerCase().replace(' ', '') + '">' + capitalize(forecast) + '</span></div></div>' +
                '<div style="float:left;padding-top:15px;"><div style="text-align:right">Advisory&nbsp;&nbsp;&nbsp;<span class="' + get_advisory_style(station) + '">' + station.advisory.replace("<br />", " ") + '</span></div></div><br style="clear:both">' +
                '<div style="float:left;padding-right:20px;padding-top:15px;"><div style="text-align:right">Bacteria Data' + dateIcon + '&nbsp;&nbsp;&nbsp;<span class="' + get_bacteria_style(station, data) +'">' + data + '</span></div></div>' +
                '<div style="float:left;padding-left:30px;"><div><a style="float:right;margin:10px 0;padding:6px 12px 3px 12px;" class="ui-btn ui-btn-corner-all ui-mini ui-btn-up-c" data-theme="c" data-wrapperels="span" data-history="false" data-corners="true" href="#beachDetailsPage?id=' + i + '" data-role="button" data-icon="info" data-mini="true"><span class="ui-btn-inner ui-btn-corner-all"><span class="ui-btn-text">More Details</span><span class="ui-icon ui-icon-info ui-icon-shadow">&nbsp;</span></span></a></div></div>' +
                '<div style="clear:both;white-space:normal;">' + station_message + '</div>' +
                '</div>' +
                '</div>'
              }, this);
            });
    */
    var legendMain = new Legend("Legend", "80px", legendContentHtml[markerType], legendWidth+'px');

    $('#map_canvas').gmap('addControl', legendMain.div, google.maps.ControlPosition.RIGHT_BOTTOM); //Add legend back in with text for new marker type
    if(markerType == 'advisories')
    {
      if($("#latest_sample").length == 0) {
        var sample_date = new latest_sample_date_div();
        $('#map_canvas').gmap('addControl', sample_date.div, google.maps.ControlPosition.TOP_CENTER); //Add legend back in with text for new marker type
      }
    }
  }


  //Set up the main overview map
  var initialZoom;
  var initialCenter;

  $('#mapPage').bind('pageinit', function(event) {
    populateMarkers('true'); //true refers to setting the map zoom to the marker bounds

    $('#map_canvas').gmap('addControl', homeButton.div, google.maps.ControlPosition.TOP_LEFT);
    $('#markerTypeSelector').trigger('create'); //Applies JQM styling to the markerTypeSelector radio buttons
  });



  $('#mapPage').bind('pageshow', function(event) {

    var mapHeight = getScreenSize('height') - (document.getElementById('mainheader').offsetHeight) - (document.getElementById('mainfooter').offsetHeight) + 2;


    $('#map_canvas').css( "height", mapHeight );

    if(markerMapped!==1){
      if(typeof userLat !== 'undefined'){
        mapUserMarker();
      }
      else{
        getUserLocation();
      }
    }

    //This repositions the map in case the user reloaded on the search or info pages - hence the zoom defaults to world level = 2
    if($('#map_canvas').gmap('getZoom') <= 2){
      $('#map_canvas').gmap('fitbounds');
      //Increase zoom one level on smaller phones
      if(getScreenSize('height') < 500){
        $('#map_canvas').gmap('option', 'zoom', ($('#map_canvas').gmap('getZoom')+1));
      }
      $('#map_canvas').gmap('refresh');
    }

    $('#markerTypeSelector').trigger('create'); //Applies JQM styling to the markerTypeSelector radio buttons

    $('#map_canvas').gmap('refreshZoom');

    $('body').removeClass('ui-loading');


    //if(popupMessage != '') alert(popupMessage);
  });


  $('#map_canvas').gmap().bind('init', function(event, map) {
    initialZoom = $('#map_canvas').gmap('getZoom');
    initialCenter = $('#map_canvas').gmap('getCenter');

    //Increase zoom one level on smaller phones
    if(getScreenSize('height') < 500){
      $('#map_canvas').gmap('option', 'zoom', (initialZoom+1));
      $('#map_canvas').gmap('refreshZoom');
    }
  });


  //Populates the List page with all the beaches and their current forecast, latest monitoring ETCOC, and advisory status

  //Function to sort list columns onclick in alternate directions
  var aAsc = [];
  function sortBy(column){
    aAsc[column] = aAsc[column]=='asc'?'desc':'asc';
    $('ul#beachList>li').tsort('span:eq('+column+')',{attr:'id', order:aAsc[column]});
    $('#arrows_1').removeClass('arrow-asc');
    $('#arrows_3').removeClass('arrow-asc');
    $('#arrows_4').removeClass('arrow-asc');
    $('#arrows_5').removeClass('arrow-asc');
    $('#arrows_1').removeClass('arrow-desc');
    $('#arrows_3').removeClass('arrow-desc');
    $('#arrows_4').removeClass('arrow-desc');
    $('#arrows_5').removeClass('arrow-desc');
    $('#arrows_'+column).addClass('arrow-'+aAsc[column]);

    $('#beachList').listview('refresh');
  }

  // Deals with converting low, medium, high into something we can sort
  function numerizeForecast(forecast){
    if(forecast == 'Low'){
      return 1;
    }
    if(forecast == 'Medium'){
      return 2;
    }
    if(forecast == 'High'){
      return 3;
    }
    if(forecast == 'None'){
      return 4;
    }

  }


  function numerizeAdvisory(advisory){
    if(advisory == 'None'){
      return 1;
    }
    if(advisory == 'Yes'){
      return 2;
    }
  }


  function numerizeNone(data){
    if(data == 'None'){
      return 99999999999; //force no data to end of sort
    }
    else {
      if(typeof data !== 'undefined') {
        //DWR 2015-12-10
        //Verify that the etcoc is a string.
        if (typeof data === "string") {
          return data.replace('>', '').replace('<', '');
        }
      }
    }

    /*
    if(data == 'None'){
      return 99999999999; //force no data to end of sort
    }
    else{
      return data.replace('>','').replace('<','');
    }*/
  }

  $('#beachListPage').bind('pageinit', function(event) {

    if(has_prediction_data) {
      if (typeof dateSet === 'undefined') {
        $("#forecast_column").append(' (' + new Date().getDate() + ' ' + month[new Date().getMonth()] + ')');
        dateSet = 1;
      }
    }
    $('#beachList li').remove();

    $.each(currentEtcoc, function(i,station){
      var span_entries = [];

      //Site location span.
      if(typeof userLat !== 'undefined'){
        distance = calcDistance(userLat,userLng,station.lat,station.lng)*0.621371;
        if(distance <100){
          round = 2;
        }
        else if(distance >=100 && distance <1000){
          round = 1;
        }
        else{
          round = 0;
        }
        distance = Math.roundTo(distance,round);
        distanceUnits = ' miles';
      }
      else{
        distance = '';
        distanceUnits = '';
      }
      span_entries.push('<span class="rating-name" style="text-align:left">' + $.trim(station.desc).replace(/\(.*?\)/g, '').replace(/^(.{23}[^\s]*).*/, "$1") +'<br/>\
            <span id="' + distance + '" style="font-weight:normal">' + distance + '</span>\
            <span style="font-weight:normal">' + distanceUnits + '</span>\
          </span>'
       )
      if(has_prediction_data) {
        if (typeof predictionData[i] === "undefined" || predictionData[i].ensemble == "NO TEST") {
          var forecast = 'None';
        }
        else {
          var forecast = predictionData[i].ensemble;
        }
        //Forecast span
        span_entries.push('<span id="' + numerizeForecast(capitalize(forecast)) + '" class="'+forecast.toLowerCase().replace(' ','')+' rating">' + capitalize(forecast) + '</span>')
      }
      var dateIcon = '';

      if(typeof station.date === "undefined" || station.date.length === 0){
        dateIcon = '<span>&nbsp;</span>'; //need to keep number of spans consistent which is important for column sorting and was being affected if no data available and hence no date span being displayed
        var data = 'None';
      }
      else{
        var sample_date = new Date(parseDate(station.date));
        dateIcon = ' ('+sample_date.getDate()+'&nbsp;'+month[sample_date.getMonth()]+' \''+sample_date.getFullYear().toString().substr(2,2)+')';
        //dateIcon = ' ('+new Date(parseDate(station.date)).getDate()+'&nbsp;'+month[new Date(parseDate(station.date)).getMonth()]+' \''+new Date(parseDate(station.date)).getFullYear().toString().substr(2,2)+')';
        var data = station.value;
      }
      //Advisory span
      span_entries.push('<span id="' + numerizeAdvisory(station.advisory) + '" class="' +calcAdvisoryRating(station)+ ' rating" style="width:23.5%">'+station.advisory+'</span>')
      //Sample data span
      span_entries.push('<span id="' + numerizeNone(data) + '" class="'+calcDataRating(data, station)+' rating">'+data+'<br/>'+dateIcon+'</span></a>')
      var list_entry = '<li data-theme="d" style="padding:0" data-icon="false"\
            data-filtertext="' + forecast + ' ' + i + ' ' + station.region + ' ' + station.desc + '"><a\
          style="text-decoration:none;padding:2px 2px 2px 5px;" href="#beachDetailsPage?id=' + i + '">'
          + span_entries.join('') + '</li>';
      $('#beachList').append(list_entry);
      //$('#beachList').append('<li data-theme="d" style="padding:0" data-icon="false" data-filtertext="' + forecast + ' ' + i + ' ' + station.region + ' ' + station.desc + '"><a style="text-decoration:none;padding:2px 2px 2px 5px;" href="#beachDetailsPage?id=' + i + '"><span class="rating-name" style="text-align:left">' + $.trim(station.desc).replace(/\(.*?\)/g, '').replace(/^(.{23}[^\s]*).*/, "$1") +'<br /><span id="' + distance + '" style="font-weight:normal">' + distance + '</span><span style="font-weight:normal">' + distanceUnits + '</span></span><span id="' + numerizeForecast(capitalize(forecast)) + '" class="'+forecast.toLowerCase().replace(' ','')+' rating">' + capitalize(forecast) + '</span><span id="' + numerizeAdvisory(station.advisory) + '" class="' +calcAdvisoryRating(station)+ ' rating" style="width:23.5%">'+station.advisory+'</span><span id="' + numerizeNone(data) + '" class="'+calcDataRating(data, station)+' rating">'+data+'<br />'+dateIcon+'</span></a></li>');

    });

    $('#beachList').append('<li>&nbsp;</li>');
    $('ul#beachList>li').tsort('span:eq(1)');//sort by the second span, which is distance from the user's location
    $('#beachList').listview('refresh');

  });


  $('#beachListPage').bind('pageshow', function(event) {
    $('body').removeClass('ui-loading');
  });


  $('#moreInformation').bind('pageshow', function(event) {
    $('body').removeClass('ui-loading');
  });

  $('#offlineMessage').bind('pageshow', function(event) {
    $('body').removeClass('ui-loading');
  });



  //Populates the beach details page with map and graph tabs
  var options;
  var monitoringChart;

  $('#beachDetailsPage').bind('pageinit', function(event) {
    if(has_prediction_data) {
      $("#details_forecast_column").append(' (' + new Date().getDate() + ' ' + month[new Date().getMonth()] + ')');
    }
    if(has_sample_data) {
      if (currentEtcoc[$.mobile.pageData.id].date.length == 0 || typeof currentEtcoc[$.mobile.pageData.id].date === "undefined") {
        $("#details_data_column").append('<span>&nbsp;</span>'); //need to keep number of spans consistent - maybe not necessary here like it is on the beach list page
      }
      else {
        $("#details_data_column").append(' (' + new Date(parseDate(currentEtcoc[$.mobile.pageData.id].date)).getDate() + ' ' + month[new Date(parseDate(currentEtcoc[$.mobile.pageData.id].date)).getMonth()] + ' \'' + new Date(parseDate(currentEtcoc[$.mobile.pageData.id].date)).getFullYear().toString().substr(2, 2) + ')');
      }
    }
    dateSet = 1;

    var legendDetail = new Legend("Legend", "80px", legendContentHtml[markerType], legendWidth+'px');

    //Legend needs to be set up on pageinit or it duplicates, or is positioned further down the page
    $('#detail_map_canvas').gmap('addControl', legendDetail.div, google.maps.ControlPosition.RIGHT_BOTTOM);

    $('#detail_map_canvas').gmap('option', 'mapTypeId', google.maps.MapTypeId.HYBRID);
    $('#detail_map_canvas').gmap('option', 'disableDefaultUI', true); //disable all controls then add in what we want
    $('#detail_map_canvas').gmap('option', 'mapTypeControl', true);
    $('#detail_map_canvas').gmap('option', 'streetViewControl', true);
    $('#detail_map_canvas').gmap('option', 'mapTypeControlOptions', {style: google.maps.MapTypeControlStyle.DROPDOWN_MENU});


    //Build band limits/colors based on what we have.
    var plot_bands = [];
    if('Low' in advisory_limits) {
      //TO get the color used, we have to create a dummy variable to then get the background-color
      //attribute.
      var dummy = $('<div class="popup_label_low" style="display: none;"></div>').appendTo('body');
      var color = dummy.css('background-color');
      dummy.remove();
      plot_bands.push({
        color: color,
        from: advisory_limits["Low"].min_limit,
        to: advisory_limits["Low"].max_limit
      });
    }
    if('Medium' in advisory_limits) {
      //TO get the color used, we have to create a dummy variable to then get the background-color
      //attribute.
      var dummy = $('<div class="popup_label_medium" style="display: none;"></div>').appendTo('body');
      var color = dummy.css('background-color');
      dummy.remove();
      plot_bands.push({
        color: color,
        from: advisory_limits["Medium"].min_limit,
        to: advisory_limits["Medium"].max_limit
      });
    }
    if('High' in advisory_limits) {
      //TO get the color used, we have to create a dummy variable to then get the background-color
      //attribute.
      var dummy = $('<div class="popup_label_high" style="display: none;"></div>').appendTo('body');
      var color = dummy.css('background-color');
      dummy.remove();
      plot_bands.push({
        color: color,
        from: advisory_limits["High"].min_limit,
        to: 10000
      });
    }


    //Set up monitoring data graph - no data at this stage - this gets populated when #beachDetailsPage is loaded with station code
    options = {
        chart: {
            renderTo: 'monitoring_data_graph',
                backgroundColor: 'rgba(0,0,0,0)',
                defaultSeriesType: 'scatter',
                marginRight: 0,
                marginLeft:65,
                marginTop: 20
            },
            credits: {
                enabled: false
            },
            title: {
                text: null
            },
            colors:['#333333'],
            xAxis: {
                endOnTick: true,
                showLastLabel: false,
                title: {
                    text: 'Date',
                    offset: 30
                },
                type: 'datetime',
                dateTimeLabelFormats: {
                    day: '%e %b \'%y',
                    week: '%e %b \'%y',
                    month: '%e %b \'%y',
                    year: '%e %b \'%y',
                },
                labels: {
                    rotation: 0,
                    y: 20
                },
                tickWidth: 0
            },
            yAxis: {
                type: 'logarithmic',
                showFirstLabel: false,
                tickPositioner: function(min, max) {
                  var ticks = [1, 10, 100, 1000, 10000],
                      i = ticks.length;

                  while (i--)
                      ticks[i] = this.val2lin(ticks[i]);

                  return ticks;
                },
                labels: {
                    formatter: function(){
                      return this.value < 10 ? 1 : this.value;
                    }
                },
                gridLineWidth: 0,
                lineWidth: 1,
                title: {
                    text: 'Bacteria per 100 mL',
                    margin: 25
                },
                plotBands: plot_bands
            },
            tooltip: {
                formatter: function() {
                    return '<strong>Date:</strong> ' + Highcharts.dateFormat('%e %B %Y', this.x) + '<br /><strong>Bacteria level:</strong> ' + Math.round(this.y);
                }
            },
            legend: {
                enabled: false
            },
            series: [{
                name: 'Station',
                data: []
        }]

    };

  });


  $('#beachDetailsPage').bind('pagebeforeshow', function(event) {

    //To set the currently active tab to the data tab, otherwise map will open first if it was left open from a previous beach details view
    $('#details_map_tab_link').removeClass("ui-btn-active");
    $('#details_data_tab_link').addClass("ui-btn-active");
    $('#data_panel').addClass('ui-tabs-content-active');
    $('#map_panel').removeClass('ui-tabs-content-active');

    $('#beachDetails li').remove();


    var beach_details_spans = [];
    //Populate details at top of graph
    if(has_prediction_data) {
      if (typeof predictionData[$.mobile.pageData.id] === "undefined" || predictionData[$.mobile.pageData.id].ensemble == "NO TEST") {
        var forecast = 'None';
      }
      else {
        var forecast = predictionData[$.mobile.pageData.id].ensemble;
      }
      beach_details_spans.push('<span class="'+forecast.toLowerCase().replace(' ','')+' details-rating">' + capitalize(forecast) + '</span>');
    }
    if(has_sample_data) {
      var shortName = $.trim(currentEtcoc[$.mobile.pageData.id].desc).replace(/\(.*?\)/g, '').replace(/^(.{23}[^\s]*).*/, "$1");
      $('#beachName').text(shortName);

      if (typeof currentEtcoc[$.mobile.pageData.id].value === "undefined") {
        data = 'None';
      }
      else {
        data = currentEtcoc[$.mobile.pageData.id].value;
      }
      beach_details_spans.push('<span class="' +calcAdvisoryRating(currentEtcoc[$.mobile.pageData.id])+ ' details-rating">'+currentEtcoc[$.mobile.pageData.id].advisory+'</span>');
      beach_details_spans.push('<span class="'+calcDataRating(data, currentEtcoc[$.mobile.pageData.id])+' details-rating">'+data+'&nbsp;&nbsp;</em></span>');
    }
    var beach_details = '<li data-theme="d" style="padding:0">' + beach_details_spans.join('') + '</li>';
    $('#beachDetails').append(beach_details);
    /*
    <li data-theme="d" style="padding:0">
      <span class="'+forecast.toLowerCase().replace(' ','')+' details-rating">' + capitalize(forecast) + '</span>
      <span class="' +calcAdvisoryRating(currentEtcoc[$.mobile.pageData.id])+ ' details-rating">'+currentEtcoc[$.mobile.pageData.id].advisory+'</span>
      <span class="'+calcDataRating(data, currentEtcoc[$.mobile.pageData.id])+' details-rating">'+data+'&nbsp;&nbsp;</em></span>
    </li>
    */
    //$('#beachDetails').append('<li data-theme="d" style="padding:0"><span class="'+forecast.toLowerCase().replace(' ','')+' details-rating">' + capitalize(forecast) + '</span><span class="' +calcAdvisoryRating(currentEtcoc[$.mobile.pageData.id])+ ' details-rating">'+currentEtcoc[$.mobile.pageData.id].advisory+'</span><span class="'+calcDataRating(data, currentEtcoc[$.mobile.pageData.id])+' details-rating">'+data+'&nbsp;&nbsp;</em></span></span></a></li>');

  });

  $('#beachDetailsPage').bind('pageshow', function(event) { //graph generation needs to be on pageshow, else x-axis labels are cut off

    var graphHeight = getScreenSize('height') - document.getElementById('detailsheader').offsetHeight - document.getElementById('beachDetailsContainer').offsetHeight;
    //If phone size screen gets rotated to landscape, graph height is not enough for effective viewing of graph so set it to getScreenSize('height') - user can then scroll down to see the rest of the graph which is fullscreen
    if(graphHeight < 200){
      graphHeight = getScreenSize('height')-30;
    }

    if(typeof predictionData[$.mobile.pageData.id] === "undefined" || predictionData[$.mobile.pageData.id].ensemble == "NO TEST"){
      var forecast = 'None';
    }
    else{
      var forecast = predictionData[$.mobile.pageData.id].ensemble;
    }

    $('#monitoring_data_graph').css( "height", graphHeight );

    var detailsMapHeight = getScreenSize('height') - document.getElementById('detailsheader').offsetHeight + 4;
    $('#detail_map_canvas').css( "height", detailsMapHeight );


    //Create the beach details map
    $('#detail_map_canvas').gmap('clear', 'markers'); //clear the marker from the last beach details view

    var marker_rating = capitalizeFirstLetter(forecast);
    var marker_icon;
    if(marker_rating !== 'None') {
      marker_icon = 'static/images/' + advisory_limits[marker_rating].icon;
    }
    else
    {
      marker_icon =  'static/images/none_marker.png';
    }
    //'static/images/'+forecast.toLowerCase()+'_marker.png'
    $('#detail_map_canvas').gmap('addMarker', {
      'position': new google.maps.LatLng(currentEtcoc[$.mobile.pageData.id].lat,currentEtcoc[$.mobile.pageData.id].lng),
      'icon': marker_icon,
      'bounds': false

    });


    if(typeof userLat !== 'undefined'){
      var clientPosition = new google.maps.LatLng(userLat, userLng);
      $('#detail_map_canvas').gmap('addMarker', {'position': clientPosition, 'icon': 'static/images/blue_dot_circle.png', 'bounds': false});
    }
    else{
      initializeGeoDetail();
    }

    $('#detail_map_canvas').gmap('option', 'center', new google.maps.LatLng(currentEtcoc[$.mobile.pageData.id].lat,currentEtcoc[$.mobile.pageData.id].lng));
    $('#detail_map_canvas').gmap('option', 'zoom', 19);

    $('#detail_map_canvas').gmap('refreshCenter');



    // Populate the graph - framework for graph is set up above
    monitoringChart = new Highcharts.Chart(options);

    var series = {
    data: []
    };

    //Using $.ajax and async: false, rather than $.getJSON to ensure that testData is populated before page tries to use it.
    var get_data = {'station': $.mobile.pageData.id,
                    'startdate': ISODateString(date_by_subtracting_days(current_date, 365))
                  };
    $.ajax({
      type: "GET",
      cache : false,
      async: false,
      crossDomain: false,
      timeout: 5000,
      url: "/station_data/" + site + '/' + $.mobile.pageData.id,
      data: get_data,
      dataType: "json",
      success: function(testData) {
        $.each(testData.contents.properties.test.beachadvisories, function(i,j){
          if(parseInt(j.value,10)===0 || j.value=='<10'){
            j.value=1;
          }
          series.data.push([parseDate(j.date),parseInt(j.value,10)]);
        });

        monitoringChart.series[0].setData(series.data);
        monitoringChart.xAxis[0].setExtremes(Date.parse(date_by_subtracting_days(current_date, 365)),Date.parse(current_date));
      }
    });



    $('body').removeClass('ui-loading');

  });

}
