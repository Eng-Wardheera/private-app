/* =========================================================
ELEMENTS
========================================================== */

const body =
document.body;

const sidebar =
document.getElementById(
    "teacherSidebar"
);

const overlay =
document.getElementById(
    "sidebarOverlay"
);

const mobileMenu =
document.getElementById(
    "mobileMenu"
);

const themeToggle =
document.getElementById(
    "themeToggle"
);

const themeIcon =
document.getElementById(
    "themeIcon"
);

const notificationButton =
document.getElementById(
    "notificationButton"
);

const toast =
document.getElementById(
    "toast"
);

const toastMessage =
document.getElementById(
    "toastMessage"
);


/* =========================================================
DARK / LIGHT MODE
========================================================== */

function applyTheme(theme) {

if (theme === "dark") {

    body.classList.add("dark");

    themeIcon.className =
        "fa-solid fa-sun";

    themeToggle.title =
        "Switch to light mode";

} else {

    body.classList.remove("dark");

    themeIcon.className =
        "fa-solid fa-moon";

    themeToggle.title =
        "Switch to dark mode";
}
}


const savedTheme =
localStorage.getItem(
    "teacher_dashboard_theme"
);


if (savedTheme) {

applyTheme(savedTheme);

} else {

const prefersDark =
    window.matchMedia &&
    window.matchMedia(
        "(prefers-color-scheme: dark)"
    ).matches;

applyTheme(
    prefersDark
        ? "dark"
        : "light"
);
}


themeToggle.addEventListener(
"click",
function () {

    const isDark =
        body.classList.contains(
            "dark"
        );

    const nextTheme =
        isDark
            ? "light"
            : "dark";

    applyTheme(
        nextTheme
    );

    localStorage.setItem(
        "teacher_dashboard_theme",
        nextTheme
    );

    showToast(
        nextTheme === "dark"
            ? "Dark mode enabled"
            : "Light mode enabled"
    );
}
);


/* =========================================================
MOBILE SIDEBAR
========================================================== */

function openSidebar() {

sidebar.classList.add(
    "open"
);

overlay.classList.add(
    "active"
);
}


function closeSidebar() {

sidebar.classList.remove(
    "open"
);

overlay.classList.remove(
    "active"
);
}


mobileMenu.addEventListener(
"click",
openSidebar
);


overlay.addEventListener(
"click",
closeSidebar
);


/* =========================================================
CLOSE MOBILE SIDEBAR AFTER CLICK
========================================================== */

document
.querySelectorAll(
    ".sidebar-link"
)
.forEach(
    function(link) {

        link.addEventListener(
            "click",
            function() {

                if (
                    window.innerWidth <= 900
                ) {

                    closeSidebar();
                }
            }
        );

    }
);


/* =========================================================
LIVE CLOCK
========================================================== */

function updateClock() {

const clock =
    document.getElementById(
        "liveClock"
    );

if (!clock) {
    return;
}


const now =
    new Date();


clock.textContent =
    now.toLocaleTimeString(
        [],
        {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        }
    );
}


updateClock();


setInterval(
updateClock,
1000
);


/* =========================================================
CURRENT YEAR
========================================================== */

const currentYear =
document.getElementById(
    "currentYear"
);


if (currentYear) {

currentYear.textContent =
    new Date().getFullYear();
}


/* =========================================================
TOAST
========================================================== */

let toastTimer;


function showToast(message) {

toastMessage.textContent =
    message;

toast.classList.add(
    "show"
);


clearTimeout(
    toastTimer
);


toastTimer =
    setTimeout(
        function() {

            toast.classList.remove(
                "show"
            );

        },
        2500
    );
}


/* =========================================================
NOTIFICATION
========================================================== */

notificationButton.addEventListener(
"click",
function() {

    showToast(
        "No new notifications"
    );

}
);


/* =========================================================
GLOBAL SEARCH
========================================================== */

const globalSearch =
document.getElementById(
    "globalSearch"
);


globalSearch.addEventListener(
"input",
function() {

    const query =
        this.value
            .toLowerCase()
            .trim();


    const searchableItems =
        document.querySelectorAll(
            ".subject-row, .quick-action, .activity-item"
        );


    searchableItems.forEach(
        function(item) {

            const text =
                item.textContent
                    .toLowerCase();


            if (
                !query ||
                text.includes(query)
            ) {

                item.style.display =
                    "";

            } else {

                item.style.display =
                    "none";
            }

        }
    );

}
);


/* =========================================================
ESC KEY
========================================================== */

document.addEventListener(
"keydown",
function(event) {

    if (
        event.key === "Escape"
    ) {

        closeSidebar();

    }

}
);


/* =========================================================
PREVENT EMPTY # LINKS
========================================================== */

document
.querySelectorAll(
    'a[href="#"]'
)
.forEach(
    function(link) {

        link.addEventListener(
            "click",
            function(event) {

                event.preventDefault();

            }
        );

    }
);