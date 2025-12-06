window.AudioContext = window.AudioContext || window.webkitAudioContext;

let mediaRecorder;
let audioChunks = [];
let silenceTimer;
let audioContext;
let analyser;
let sourceNode;

let running = false;

async function startRecording(dotNetRef) {
    try {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            throw new Error("getUserMedia not supported");
        }

        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });

        audioChunks = [];
        mediaRecorder = new MediaRecorder(stream);
        mediaRecorder.ondataavailable = event => {
            audioChunks.push(event.data);
        };

        // AudioContext és hangszint elemzés
        audioContext = new AudioContext();
        analyser = audioContext.createAnalyser();
        sourceNode = audioContext.createMediaStreamSource(stream);
        sourceNode.connect(analyser);
        analyser.fftSize = 2048;
        const dataArray = new Uint8Array(analyser.fftSize);

        running = true;
        function checkSilence() {
            if (!running) return;
            analyser.getByteTimeDomainData(dataArray);
            const rms = Math.sqrt(dataArray.reduce((sum, value) => {
                const norm = (value - 128) / 128;
                return sum + norm * norm;
            }, 0) / dataArray.length);

            // Ha alacsony a hangerő (pl. < 0.01), akkor újraindítjuk a 3 másodperces időzítőt
            if (rms > 0.01) {
                if (silenceTimer) {
                    clearTimeout(silenceTimer);
                    silenceTimer = null;
                }
            } else {
                if (!silenceTimer) {
                    silenceTimer = setTimeout(() => {
                        //stopRecording();
                        // A JS oldalon meghívjuk a Blazor metódust
                        dotNetRef.invokeMethodAsync("OnRecordingStopped", "");

                    }, 1000); // 1 másodperc csend után automatikus leállítás
                }
            }

            requestAnimationFrame(checkSilence);
        }

        requestAnimationFrame(checkSilence);
        mediaRecorder.start();

    } catch (err) {
        console.error("getUserMedia error", err);

        let msg = (err.name || "Error") + " " + (err.message || "");
        if (err.name === "NotReadableError") {
            msg = "Nem sikerült elindítani a mikrofont. " +
                "Ellenőrizze, hogy a mikrofon engedélyezve van-e és nem használja-e más alkalmazás.";
        }

        await dotNetRef.invokeMethodAsync("OnRecordingError", msg);
    }
}

function stopRecording(apiUrl, accessToken) {
    running = false;
    return new Promise((resolve) => {
        if (silenceTimer) clearTimeout(silenceTimer);
        if (audioContext) {
            audioContext.close();
            audioContext = null;
        }

        mediaRecorder.onstop = async () => {
            const audioBlob = new Blob(audioChunks, { type: 'audio/wav' });
            audioChunks = [];
            const formData = new FormData();
            formData.append('file', audioBlob);

            const response = await fetch(apiUrl + '/api/audio/stt', {
                method: 'POST',
                headers: {
                    'AccessToken': accessToken
                },
                body: formData
            });

            const result = await response.json();
            resolve(result.text);
        };

        mediaRecorder.stop();
    });
}
