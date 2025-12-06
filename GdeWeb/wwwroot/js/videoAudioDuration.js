window.getMediaDurationFromBytes = async (byteArray, mimeType) => {
    return new Promise((resolve, reject) => {
        try {
            // ByteArray konvertálása Blob objektummá
            let blob = new Blob([new Uint8Array(byteArray)], { type: mimeType });
            let url = URL.createObjectURL(blob);
            let mediaElement;

            if (mimeType.startsWith("audio/")) {
                mediaElement = new Audio();
            } else if (mimeType.startsWith("video/")) {
                mediaElement = document.createElement("video");
            } else {
                reject("Invalid media type");
                return;
            }

            mediaElement.src = url;
            mediaElement.onloadedmetadata = () => {
                resolve(mediaElement.duration);
                URL.revokeObjectURL(url);
            };
            mediaElement.onerror = () => {
                reject("Error loading media file");
            };
        } catch (error) {
            reject("Failed to process media: " + error);
        }
    });
};