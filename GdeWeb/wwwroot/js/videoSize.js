window.getVideoDimensions = async (fileBytes) => {
    return new Promise((resolve, reject) => {
        let fileBlob = new Blob([fileBytes], { type: "video/mp4" }); // A Blazor által kapott adatot Blob-ra alakítjuk
        let video = document.createElement("video");
        video.preload = "metadata";

        video.onloadedmetadata = () => {
            resolve({ width: video.videoWidth, height: video.videoHeight });
            URL.revokeObjectURL(video.src); // Memóriaszivárgás elkerülése
        };

        video.onerror = () => {
            reject("Error loading video metadata.");
        };

        video.src = URL.createObjectURL(fileBlob);
    });
};