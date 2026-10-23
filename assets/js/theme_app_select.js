(function (global) {
    "use strict";

    // Wires up the combined theme + apps control rendered by the
    // ThemeAppSelect component. Works for any number of instances and for
    // both the wide-screen <select> and the narrow-screen hamburger menu.
    // Theme state itself lives in RdapTheme (theme.js / localStorage).

    function themeSelects() {
        return Array.prototype.slice.call(
            document.querySelectorAll(".theme_app_select")
        );
    }

    function markActiveTheme(menu) {
        if (!menu) return;
        var current = global.RdapTheme ? global.RdapTheme.current() : null;
        var buttons = menu.querySelectorAll(".theme_app_theme");
        for (var i = 0; i < buttons.length; i++) {
            var isActive = buttons[i].getAttribute("data-theme") === current;
            buttons[i].setAttribute("aria-current", isActive ? "true" : "false");
        }
    }

    function syncSelect(sel) {
        if (!global.RdapTheme) return;
        var current = global.RdapTheme.current();
        for (var i = 0; i < sel.options.length; i++) {
            if (sel.options[i].value === current) {
                sel.value = current;
                break;
            }
        }
    }

    function closeMenu(burger, menu) {
        if (!menu) return;
        menu.hidden = true;
        if (burger) burger.setAttribute("aria-expanded", "false");
    }

    function openMenu(burger, menu) {
        if (!menu) return;
        markActiveTheme(menu);
        menu.hidden = false;
        if (burger) burger.setAttribute("aria-expanded", "true");
    }

    function init() {
        // Reflect the persisted theme in every wide-screen select.
        themeSelects().forEach(syncSelect);

        // Wide-screen select: navigate on app options, switch theme otherwise.
        document.addEventListener("change", function (e) {
            var sel = e.target.closest ? e.target.closest(".theme_app_select") : null;
            if (!sel) return;
            var opt = sel.options[sel.selectedIndex];
            if (!opt) return;
            if (opt.dataset && opt.dataset.app) {
                global.location.href = opt.dataset.app;
            } else if (global.RdapTheme) {
                global.RdapTheme.set(opt.value);
            }
        });

        // Hamburger toggle.
        document.addEventListener("click", function (e) {
            var burger = e.target.closest ? e.target.closest(".theme_app_burger") : null;
            if (burger) {
                var menu = document.getElementById(burger.getAttribute("aria-controls"));
                if (menu && menu.hidden) {
                    openMenu(burger, menu);
                } else {
                    closeMenu(burger, menu);
                }
                return;
            }

            // Theme picked from the hamburger menu.
            var themeBtn = e.target.closest ? e.target.closest(".theme_app_theme") : null;
            if (themeBtn && global.RdapTheme) {
                global.RdapTheme.set(themeBtn.getAttribute("data-theme"));
                markActiveTheme(themeBtn.closest(".theme_app_menu"));
                // Keep any wide-screen select in sync too.
                themeSelects().forEach(syncSelect);
                return;
            }

            // Click outside an open menu closes it.
            var openMenuEl = e.target.closest ? e.target.closest(".theme_app_menu") : null;
            if (!openMenuEl) {
                var burgers = document.querySelectorAll('.theme_app_burger[aria-expanded="true"]');
                for (var i = 0; i < burgers.length; i++) {
                    var m = document.getElementById(burgers[i].getAttribute("aria-controls"));
                    closeMenu(burgers[i], m);
                }
            }
        });

        // Escape closes any open menu and returns focus to its button.
        document.addEventListener("keydown", function (e) {
            if (e.key !== "Escape") return;
            var burgers = document.querySelectorAll('.theme_app_burger[aria-expanded="true"]');
            for (var i = 0; i < burgers.length; i++) {
                var m = document.getElementById(burgers[i].getAttribute("aria-controls"));
                closeMenu(burgers[i], m);
                burgers[i].focus();
            }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})(window);
