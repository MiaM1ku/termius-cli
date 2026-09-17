"""Runtime constants aligned with Termius desktop 10.0.6."""

APP_NAME = 'Termius CLI'
APP_VERSION = '10.0.6'
CLIENT_VERSION = '2.0.0'
DEVICE_PLATFORM = 'Desktop'
API_HOST = 'api.termius.com'
API_BASE_URL = 'https://{}/'.format(API_HOST)
WS_BASE_URL = 'wss://{}'.format(API_HOST)
SOCKETIO_GRPC_PATH = '/socket.io/grpc-proxy'
LOGIN_NAMESPACE = '/login_v2'
