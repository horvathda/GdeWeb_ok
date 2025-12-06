(function () {
    // Debug vagy Release?
    // A MAUI WebView-ben a launch URL alapján tudjuk eldönteni:
    // Ha file:/// vagy localhost, akkor valószínűleg Debug.
    var isDebug =
        location.hostname === "localhost" ||
        location.protocol === "file:";

    // Debug = timestamp
    // Release = fix verzió
    var version = isDebug ? Date.now() : "1.0.0";

    // A frissítendő CSS fájlok ID alapján
    var cssFiles = [
        "css-edu",
        "css-lottie",
        "css-openai"
    ];

    cssFiles.forEach(function (id) {
        var link = document.getElementById(id);
        if (!link) return;

        var href = link.getAttribute("href") || "";

        // Ha már van verzió, ne duplázzuk
        if (href.indexOf("?v=") !== -1) return;

        link.setAttribute("href", href + "?v=" + version);
    });
})();