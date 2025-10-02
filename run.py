import threading
from backend import app, socketio, run_frontend_server, open_browser

if __name__ == "__main__":
    import eventlet
    eventlet.monkey_patch()

    threading.Thread(target=run_frontend_server, daemon=True).start()
    threading.Thread(target=open_browser, daemon=True).start()

    socketio.run(app, host="0.0.0.0", port=8000, debug=False)

