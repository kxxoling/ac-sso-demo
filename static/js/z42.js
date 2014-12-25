// Generated by CoffeeScript 1.8.0
(function() {
  var _def_view;

  window.V = {};

  window.def_view = _def_view = function(id, ctrl) {
    return V[id] = avalon.define(id, ctrl);
  };

  $(function() {
    return window.def_view = function(id, ctrl) {
      var v;
      v = _def_view(id, ctrl);
      avalon.scan();
      return v;
    };
  });

  window.def_edit_view = function(name, callback) {
    return def_view(name, function(v) {
      v.is_edit = 0;
      v.edit = function() {
        return V[name].is_edit = 1;
      };
      v.cancel = function() {
        return V[name].is_edit = 0;
      };
      return callback(v);
    });
  };

}).call(this);
