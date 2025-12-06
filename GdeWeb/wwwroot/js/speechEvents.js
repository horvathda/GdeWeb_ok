window.tts = (function () {
    let audioEl;

    function ensureAudio() {
        if (!audioEl) {
            audioEl = document.createElement('audio');
            audioEl.preload = 'auto';
            audioEl.controls = false;
            document.body.appendChild(audioEl);
        }
        return audioEl;
    }

    async function playBase64(apiUrl, accessToken, text) {
        try {
            const form = new FormData();
            form.append('text', text);

            const resp = await fetch(`${apiUrl}/api/audio/tts`, {
                method: 'POST',
                headers: { 'AccessToken': accessToken },
                body: form
            });
            if (!resp.ok) throw new Error('TTS hívás sikertelen');

            const blob = await resp.blob(); // audio/mpeg
            const url = URL.createObjectURL(blob);

            const audio = ensureAudio();
            audio.src = url;
            await audio.play();

        } catch (e) {
            console.error('TTS hiba:', e);
        }
    }

    function stop() {
        if (!audioEl) return;
        try { audioEl.pause(); audioEl.src = ""; } catch { }
    }

    return { playBase64, stop, ensureAudio };
})();