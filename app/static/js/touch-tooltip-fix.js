//https://gist.github.com/nicholasklick/6083417

Highcharts.Chart.prototype.callbacks.push(function(chart) {
  var hasTouch = document.documentElement.ontouchstart !== undefined,
      mouseTracker = chart.pointer,
      container = chart.container,
      mouseMove;

  mouseMove = function (e) {

    // let the system handle multitouch operations like two finger scroll
    // and pinching
    if (e && e.touches && e.touches.length > 1) {
      return;
    }

    if (hasTouch) {
        if (e && e.touches && e.touches.length > 1) {
            mouseTracker.onContainerTouchMove(e);
        } else {
            return;
        }
    } else {
      mouseTracker.onContainerMouseMove(e);
    }
  };

  click = function (e) {
    if (hasTouch) {
        mouseTracker.onContainerMouseMove(e);
    }
    mouseTracker.onContainerClick(e);
  }

  container.onmousemove = container.ontouchstart = container.ontouchmove = mouseMove;
  container.onclick = click;
});


/*
//https://gist.github.com/ricardoferreira1980/5335186

Highcharts.Chart.prototype.callbacks.push(function(chart) {
  var hasTouch = document.documentElement.ontouchstart !== undefined,
      mouseTracker = chart.pointer,
      container = chart.container,
      mouseMove;

  mouseMove = function (e) {
    if (hasTouch) {
        if (e && e.touches && e.touches.length > 1) {
            mouseTracker.onContainerTouchMove(e);
        } else {
            return;
        }
    } else {
      mouseTracker.onContainerMouseMove(e);
    }
  };

  click = function (e) {
    if (hasTouch) {
        mouseTracker.onContainerMouseMove(e);
    }
    mouseTracker.onContainerClick(e);
  }

  container.onmousemove = container.ontouchstart = container.ontouchmove = mouseMove;
  container.onclick = click;
});
*/