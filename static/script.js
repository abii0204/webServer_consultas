const video = document.getElementById('video');
        const canvas = document.getElementById('canvas');
        const context = canvas.getContext('2d');
        const qrResult = document.getElementById('qrResult');

        // Función para escanear el QR
        function scanQR() {
            if (video.readyState === video.HAVE_ENOUGH_DATA) {
                canvas.width = video.videoWidth;
                canvas.height = video.videoHeight;
                context.drawImage(video, 0, 0, canvas.width, canvas.height);

                const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
                const qrCode = jsQR(imageData.data, imageData.width, imageData.height);

                if (qrCode) {
                    qrResult.textContent = `QR Detectado: ${qrCode.data}`;
                    sendQRData(qrCode.data);
                } else {
                    qrResult.textContent = "Buscando QR...";
                    requestAnimationFrame(scanQR);
                }
            } else {
                requestAnimationFrame(scanQR);
            }
        }

        // Función para enviar los datos del QR al servidor
        function sendQRData(qrData) {
            fetch('/qr-data', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ qr_data: qrData })
            })
                .then(response => response.json())
                .then(data => {
                    if (data.content === "qr_ok") {
                        window.location.href = '/qr_ok';
                    } else {
                        window.location.href = '/qr_fail';
                    }
                })
                .catch(err => {
                    console.error("Error enviando QR:", err);
                });
        }

        // Función para iniciar la cámara
        function startCamera() {
            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                console.error("getUserMedia no es compatible con este navegador.");
                qrResult.textContent = "Tu navegador no soporta acceso a la cámara.";
                return;
            }

            navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
                .then(stream => {
                    video.srcObject = stream;
                    video.setAttribute("playsinline", true); // Para iOS
                    video.play();
                    requestAnimationFrame(scanQR);
                })
                .catch(err => {
                    console.error("Error al acceder a la cámara:", err.message);
                    qrResult.textContent = `Error: ${err.message}. Verifica permisos.`;
                });
        }

        // Iniciar la cámara al cargar la página
        startCamera();