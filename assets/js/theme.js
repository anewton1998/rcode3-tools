(function (global) {
    "use strict";
    var KEY = "rcode3-theme";

    function read() {
        try { return localStorage.getItem(KEY); } catch (e) { return null; }
    }

    function write(value) {
        try { localStorage.setItem(KEY, value); } catch (e) {}
    }

    function isValid(name) {
        return typeof name === "string" && name.indexOf("theme_") === 0;
    }

    var saved = read();
    if (isValid(saved)) {
        document.documentElement.className = saved;
    }

    global.RdapTheme = {
        key: KEY,
        current: function () { return document.documentElement.className; },
        get: read,
        set: function (name) {
            if (!isValid(name)) return;
            document.documentElement.className = name;
            write(name);
        }
    };
})(window);
