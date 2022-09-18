const HTTP_PORT = 8089
const HTTPS_PORT = 8009
const HTTP_HOST_NAME = "localhost:8089"
const HTTPS_HOST_NAME = "localhost:8009"
const REDIRECT_URL = "http://" & HTTPS_HOST_NAME
const DEBUG_LOG = true

const CERT_PATH = "."
const CERT_FILE = CERT_PATH / "cert.pem"
const PRIVKEY_FILE = CERT_PATH / "privkey.pem"
const CHAIN_FILE = CERT_PATH / "fullchain.pem"
const SSL_AUTO_RELOAD = true
