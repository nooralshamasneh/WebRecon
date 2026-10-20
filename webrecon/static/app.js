(function () {
  var box = document.getElementById('progress');
  if (!box) { return; }
  var bar = document.getElementById('bar');
  var stage = document.getElementById('stage');
  function poll() {
    fetch(box.dataset.api, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (s) {
        bar.value = s.progress || 0;
        stage.textContent = 'Stage: ' + s.stage;
        if (s.status === 'completed' || s.status === 'failed') { window.location.reload(); }
        else { setTimeout(poll, 2000); }
      })
      .catch(function () { setTimeout(poll, 5000); });
  }
  poll();
}());