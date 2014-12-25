// Generated by CoffeeScript 1.8.0
(function() {
  var RE_CNCHAR, ajaxing, doc, errtip_explain, errtip_poshytip, _ajax_success, _cnenlen,
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  if (!console || !console.log) {
    window.console = {
      log: function() {}
    };
  }

  errtip_poshytip = function(elem, body) {
    return {
      set: function(v) {
        var alignX, aligny, border_css, offsetY, offsety;
        this.reset();
        alignX = elem.data('errtip-alignx') || "right";
        offsetY = 0;
        aligny = 'center';
        if (elem.prop('tagName') === 'SELECT') {
          offsety = -28;
          aligny = 'bottom';
        }
        border_css = elem.css('border');
        if (border_css.indexOf('none') >= 0 && elem.attr('type') !== 'checkbox' && elem.attr('type') !== 'submit') {
          elem.parents('ul').poshytip({
            className: 'tip-err',
            showOn: 'none',
            alignTo: 'target',
            alignY: aligny,
            offsetY: offsety,
            keepInViewport: false,
            alignX: alignX,
            content: v,
            offsetX: 10,
            body: elem[0].parentNode
          }).poshytip('show').addClass('ERR');
        } else {
          elem.poshytip({
            className: 'tip-err',
            showOn: 'none',
            alignTo: 'target',
            alignY: aligny,
            offsetY: offsety,
            keepInViewport: false,
            alignX: alignX,
            content: v,
            offsetX: 10,
            body: elem[0].parentNode
          }).poshytip('show').addClass('ERR');
        }
        return this;
      },
      reset: function() {
        return elem.poshytip('destroy').removeClass('ERR');
      }
    };
  };

  errtip_explain = function(elem) {
    var err_cls, html, p;
    html = elem.data('default');
    if (!html) {
      html = elem.html();
      elem.data('default', html);
    }
    p = elem.parent('.ui-form-item');
    err_cls = 'ui-form-item-error';
    return {
      set: function(content) {
        this.reset();
        p.addClass(err_cls);
        p.keydown(function() {
          elem.html(html);
          return p.removeClass(err_cls);
        });
        if (content) {
          elem.html(content).fadeOut().fadeIn();
          return this;
        }
      },
      reset: function() {
        elem.html(html);
        p.removeClass(err_cls);
        return false;
      }
    };
  };

  $(document).ajaxError(function(event, request, settings) {
    var status;
    status = request.status;
    if (status && status !== 200) {
      return alert("出错 : " + status + "\n" + settings.url);
    }
  });

  jQuery.fn.extend({
    ctrl_enter: function(callback) {
      return $(this).keydown(function(event) {
        event = event.originalEvent;
        if (event.keyCode === 13 && (event.metaKey || event.ctrlKey)) {
          if (typeof callback === "function") {
            callback();
          }
          return false;
        }
      });
    },
    click_drop: function(drop, callback1, callback2) {
      var html;
      html = $("html,body");
      return $(this).click(function(e) {
        var clicked, self, _;
        self = this;
        self.blur();
        _ = function() {
          drop.hide();
          html.unbind('click', _);
          return callback2 && callback2();
        };
        if (drop.is(":hidden")) {
          drop.show();
          e.stopPropagation();
          html.click(_);
          clicked = true;
          return callback1 && callback1();
        } else {
          return _();
        }
      });
    }
  });

  jQuery.extend({
    timestampsort: function(li) {
      if (!li) {
        return;
      }
      return li.sort(function(a, b) {
        if (!a.time) {
          return 1;
        }
        if (!b.time) {
          return -1;
        }
        if (a.time < b.time) {
          return 1;
        } else if (a.time > b.time) {
          return -1;
        }
      });
    },
    isodate: function(timestamp) {
      if (timestamp === 1 || timestamp === '1') {
        return '至今';
      }
      return $.isotime(timestamp).slice(0, 10);
    },
    escape: function(txt) {
      return $('<div/>').text(txt).html();
    },
    html: function() {
      var r, _;
      r = [];
      _ = function(o) {
        return r.push(o);
      };
      _.html = function() {
        return r.join('');
      };
      return _;
    },
    uid: function() {
      return ("" + Math.random()).slice(2);
    },
    postJSON: function(url, data, callback) {
      var processData, type;
      if (jQuery.isFunction(data)) {
        callback = data;
        data = 0;
      }
      data = JSON.stringify(data || {});
      if (url.indexOf("callback=?") > 0) {
        data = {
          "o": data
        };
        processData = true;
        type = 'GET';
      } else {
        type = 'POST';
        processData = false;
      }
      return jQuery.ajax({
        url: url,
        data: data,
        dataType: "json",
        type: type,
        processData: processData,
        success: _ajax_success(callback)
      });
    },
    localtime: function(timestamp) {
      var date;
      if (!timestamp) {
        return '';
      }
      date = new Date(timestamp * 1000);
      return date.getFullYear() + "年" + date.getMonth() + "月" + date.getDate() + "日";
    },
    isotime: function(timestamp) {
      var d, date, hour, i, m, minute, now, result, y, _i, _len, _result;
      if (!timestamp) {
        return '';
      }
      date = new Date(timestamp * 1000);
      _result = [date.getFullYear(), date.getMonth() + 1, date.getDate(), date.getHours(), date.getMinutes()];
      result = [];
      for (_i = 0, _len = _result.length; _i < _len; _i++) {
        i = _result[_i];
        if (i <= 9) {
          i = "0" + i;
        }
        result.push(i);
      }
      y = result[0], m = result[1], d = result[2], hour = result[3], minute = result[4];
      now = new Date();
      return [y, m, d].join("-") + " " + [hour, minute].join(":");
    },
    timeago: function(timestamp) {
      var ago, date, minute;
      date = new Date(timestamp * 1000);
      ago = parseInt((new Date().getTime() - date.getTime()) / 1000);
      minute = void 0;
      if (ago <= 0) {
        return "刚刚";
      } else if (ago < 60) {
        return ago + "秒前";
      } else {
        minute = parseInt(ago / 60);
        if (minute < 60) {
          return minute + "分钟前";
        }
      }
      return jQuery.isotime(timestamp).split(" ")[0];
    },
    num_format: function(num, length) {
      num = num - 0;
      if (num < 0.01) {
        length = 8;
      }
      if (length) {
        num = num.toFixed(length);
      }
      return num - 0;
    },
    require: function(o, name, index) {
      var err, i, _i, _len, _ref;
      if (index == null) {
        index = "";
      }
      err = {};
      _ref = name.split(" ");
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        i = _ref[_i];
        if (!o[i]) {
          err[i + index] = "";
        }
      }
      return err;
    },
    errtip: function(o, focus) {
      var elem, kv;
      if (focus == null) {
        focus = 1;
      }
      elem = $(o);
      if (!elem[0]) {
        return;
      }
      if (elem[0].tagName === "FORM") {
        elem.find("input:first").focus();
        kv = [];
        return {
          reset: function() {
            var i, _i, _len;
            for (_i = 0, _len = kv.length; _i < _len; _i++) {
              i = kv[_i];
              i.reset();
            }
            return kv = [];
          },
          set: function(o) {
            var count, event, explain, focused, k, t, tiper, v, _;
            this.reset();
            if (typeof o === "string") {
              alert(o);
              return 1;
            }
            focused = 0;
            count = 0;
            for (k in o) {
              v = o[k];
              count += 1;
              t = elem.find("[name=" + k + "]");
              if (!t[0]) {
                alert(v);
                continue;
              }
              if (!focused && t[0].tagName === "INPUT" && focus) {
                t.focus().select();
                focused = 1;
              }
              explain = t.parents('.ui-form-item').find('.ui-form-explain');
              if (explain.length) {
                tiper = errtip_explain(explain);
              } else {
                tiper = errtip_poshytip(t);
              }
              if (t[0].tagName === "INPUT" || t[0].tagName === "SELECT") {
                if (!focused && focus) {
                  t.focus().select();
                  focused = 1;
                }
                if (t[0].type === "checkbox") {
                  event = "change";
                } else {
                  event = "keypress";
                }
                t.bind("" + event + ".errtip", function() {
                  tiper.reset();
                  return t.unbind('keypress.errtip');
                });
              }
              _ = tiper.set(v);
              if (_) {
                kv.push(_);
              }
            }
            return count;
          }
        };
      }
    }
  });

  $.ajaxSetup({
    beforeSend: function(jqXHR, settings) {
      return jqXHR.url = settings.url;
    }
  });

  $._AJAXING = {};

  _ajax_success = function(callback) {
    var _;
    _ = function(data, textStatus, jqXHR) {
      var err;
      if (data && data.err) {
        err = data.err;
        if (callback != null) {
          if (typeof callback.end === "function") {
            callback.end();
          }
        }
        if (err.code === 403) {
          return $$('SSO/user.login');
        } else if (err.html) {
          return $.dialog("err", {
            content: error.html
          });
        } else if (err.script) {
          return eval(err.script);
        }
      }
      if (callback) {
        return callback(data, textStatus, jqXHR);
      }
    };
    return _;
  };

  jQuery.getJSON = function(url, data, callback, cache) {
    if (cache == null) {
      cache = 0;
    }
    if (jQuery.isFunction(data)) {
      cache = callback;
      callback = data;
      data = 0;
    }
    return jQuery.ajax({
      url: url,
      cache: cache || false,
      data: data || {},
      dataType: "json",
      type: "GET",
      success: _ajax_success(callback)
    });
  };

  jQuery.getUser = function() {
    var user_id;
    user_id = $.cookie.get("S");
    if (user_id) {
      return user_id;
    }
    return 0;
  };

  $.whenScroll = function(pos_get, more_than, less_than) {
    var body, pos, resize, top, when_change;
    body = $(window);
    top = body.scrollTop();
    pos = 0;
    resize = function() {
      return setTimeout(function() {
        var _top;
        pos = pos_get();
        _top = body.scrollTop();
        if (_top > pos) {
          return more_than();
        } else if (_top < pos) {
          return less_than();
        }
      }, 10);
    };
    when_change = function() {
      var _top;
      _top = body.scrollTop();
      if (top <= pos && _top > pos) {
        more_than();
      } else if (top >= pos && _top < pos) {
        less_than();
      }
      return top = _top;
    };
    body.resize(resize).scroll(when_change);
    return resize();
  };

  $.loader = {
    show: function() {
      if (!this._timer) {
        return this._timer = setTimeout(function() {
          var e;
          if (!$("#spin")[0]) {
            $("body").append('<div id="spin"></div>');
            try {
              return delete this._timer;
            } catch (_error) {
              e = _error;
              if (this.removeAttribute) {
                return this.removeAttribute(_timer);
              }
            }
          }
        }, 300);
      }
    },
    hide: function() {
      var e;
      clearTimeout(this._timer);
      try {
        delete this._timer;
      } catch (_error) {
        e = _error;
        if (this.removeAttribute) {
          this.removeAttribute(_timer);
        }
      }
      return $("#spin").remove();
    }
  };

  ajaxing = function(func) {
    return function(url, data, callback, cache) {
      var end, _callback;
      if (cache == null) {
        cache = false;
      }
      if ($._AJAXING[url]) {
        return;
      }
      $._AJAXING[url] = 1;
      if (jQuery.isFunction(data)) {
        cache = callback;
        callback = data;
        data = 0;
      }
      $.loader.show();
      _callback = function(data, textStatus, jqXHR) {
        if (callback) {
          callback(data, textStatus, jqXHR);
        }
        return end();
      };
      _callback.end = end = function() {
        $.loader.hide();
        return delete $._AJAXING[url];
      };
      return func(url, data, _callback, cache).fail(end);
    };
  };

  $.postJSON1 = ajaxing($.postJSON);

  $.getJSON1 = ajaxing($.getJSON);

  $.get1 = ajaxing($.get);

  $.post1 = ajaxing($.post);

  $.ajax_submit = function(url, view, callback, failed) {
    var errtip;
    errtip = 0;
    return function() {
      var disable, form, submit;
      if (this.tagName === "FORM") {
        form = $(this);
      } else {
        form = $(this).parents('form');
      }
      errtip = errtip || $.errtip(form);
      form.find('input').each(function() {
        return this.value = this.value;
      });
      submit = form.find('input[type=submit]');
      disable = 'ui-button-disable';
      submit.addClass(disable);
      $.postJSON1(url, view.o.$model, function(r) {
        submit.removeClass(disable);
        errtip.reset();
        if (r.err) {
          errtip.set(r.err);
          return typeof failed === "function" ? failed(r.err) : void 0;
        } else {
          return callback(r);
        }
      });
      return false;
    };
  };

  $.get_current_user = function() {
    var s;
    s = $.cookie.get("S");
    if (s) {
      $.current_user_id = s.split(".")[0] - 0;
      return $.current_user = {
        id: $.current_user_id,
        url: "//" + $.current_user_id + "." + CONST.HOST
      };
    }
  };

  $.get_current_user();

  $.dialog = function(id, html, option) {
    var elem;
    if ($("#" + id)[0]) {
      return;
    }
    elem = $(html);
    elem.attr('id', id);
    if (__indexOf.call(option, 'modal') < 0) {
      option.modal = true;
    }
    if (__indexOf.call(option, 'resizable') < 0) {
      option.resizable = false;
    }
    return elem.dialog(option);
  };

  doc = $(document);

  $.scrollTop = function(top) {
    if (top == null) {
      top = 0;
    }
    return $("html,body").animate({
      scrollTop: top
    });
  };

  RE_CNCHAR = /[^\x00-\x80]/g;

  _cnenlen = function(str) {
    var aMatch;
    if (typeof str === "undefined") {
      return 0;
    }
    aMatch = str.match(RE_CNCHAR);
    return str.length + (!aMatch ? 0 : aMatch.length);
  };

  $.cnenlen = function(str) {
    return Math.ceil(_cnenlen($.trim(str)) / 2);
  };

  $.login = function() {
    if ($.current_user_id) {
      return 1;
    } else {
      $$('SSO/user.login');
      return false;
    }
  };

  $.login_dialog = function(id, html, option) {
    if ($.login()) {
      return $.dialog(id, html, option);
    }
  };

}).call(this);
