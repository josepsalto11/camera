import cv2
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer

# Configuración de la cámara
cap = cv2.VideoCapture(0)

# Verificación de que la cámara está abierta
if not cap.isOpened():
    print("No se pudo abrir la cámara.")
    exit()

# Obtener la dirección IP local del PC
hostname = socket.gethostname()
ip_address = socket.gethostbyname(hostname)

# Clase que maneja las solicitudes HTTP
class VideoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Establecer la respuesta HTTP
        self.send_response(200)
        self.send_header('Content-type', 'multipart/x-mixed-replace; boundary=frame')
        self.end_headers()
        
        while True:
            # Leer un frame de la cámara
            ret, frame = cap.read()
            if not ret:
                break

            # Codificar el frame como JPEG
            _, jpeg = cv2.imencode('.jpg', frame)

            # Enviar el frame como respuesta HTTP
            self.wfile.write(b'--frame\r\n')
            self.send_header('Content-Type', 'image/jpeg')
            self.end_headers()
            self.wfile.write(jpeg.tobytes())
            self.wfile.write(b'\r\n')

# Configurar el servidor HTTP en el puerto 8080
def run(server_class=HTTPServer, handler_class=VideoHandler, port=8080):
    server_address = ('', port)  # Escuchar en todas las interfaces de red
    httpd = server_class(server_address, handler_class)
    print(f'Servidor iniciado en http://{ip_address}:{port}')
    httpd.serve_forever()

# Iniciar el servidor
if __name__ == '__main__':
    run()
