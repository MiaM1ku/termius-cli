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

# gRPC login overwrites device.mobile_type with this enum. REST still
# sends the string "Desktop" from DeviceIdentity.to_json().
GRPC_MOBILE_TYPE_DESKTOP = 3
SSO_DESKTOP_URL = 'https://account.termius.com/sso/desktop'
FIREBASE_API_KEY = 'AIzaSyBFnPuANmLK2HzicAwuuDffSjRcW1FGDCU'
FIREBASE_AUTH_REFERER = 'https://account.termius.com/'
FIREBASE_CREATE_AUTH_URI = (
    'https://www.googleapis.com/identitytoolkit/v3/relyingparty/createAuthUri'
)
FIREBASE_SIGN_IN_WITH_IDP = (
    'https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp'
)
