from backend.web import create_app


app, socketio = create_app()
config = app.extensions["apt_config"]


if __name__ == "__main__":
    socketio.run(app, host=config.web_host, port=config.web_port)
