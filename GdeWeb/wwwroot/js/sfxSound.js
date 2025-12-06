window.quizSfx = {
    play: function (id) {
        const el = document.getElementById(id);
        if (!el) return;
        // Ha többször gyors egymás után, tekerjük vissza
        el.currentTime = 0;
        const p = el.play();
        if (p && typeof p.catch === 'function') {
            p.catch(_ => { /* autoplay policy hiba – első kattintás után már menni fog */ });
        }
    }
};
