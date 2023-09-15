# Caprese
A front-end web server specialized for real-time message exchange

### Appetizers
> *Can I write server-side APIs, back-end services, client-side applications, javascript, wasm, even html, in one language and in one code file, and even in one executable binary and process? 〜a certain geek〜*

*Yes, you can do it with the Caprese. It is free and flexible. Actually, though, it's thanks to a great Nim and libraries.*

> *Is web3 a web? Are there any web server that can be called web3? 〜a certain tweet〜*

*Caprese will be the base of that system. It would be a decentralized web server with server-to-server connections that could verify the reliability of contents and applications.*

### Quick Trial
#### Install Nim
I heard you like Ubuntu, so I will explain for it. The following are required to install [Nim](https://nim-lang.org/).

    sudo apt install build-essential curl

Installation using [choosenim](https://github.com/dom96/choosenim#choosenim).

    curl https://nim-lang.org/choosenim/init.sh -sSf | sh
    echo 'export PATH='$HOME'/.nimble/bin:$PATH' >> ~/.bashrc
    . ~/.bashrc

See [Nim](https://nim-lang.org/) for installation details.

#### Build Caprese and Launch
you also require the following installation to build the SSL libraries, *golang* is required to build *BoringSSL*. The version of *golang* installed by the Ubuntu package tool might be old, so you might want to download and install the latest version from [The Go Programming Language](https://go.dev/), you can choose either.

    sudo apt install autoconf libtool cmake pkg-config golang

Do you have git installed?

    sudo apt install git

Now let's build the Caprese.

    git clone https://github.com/zenywallet/caprese
    cd caprese
    nimble install -d
    nimble deps
    nim c -r -d:release --threads:on --mm:orc src/caprese.nim

Open [https://localhost:8009/](https://localhost:8009/) in your browser. You'll probably get a SSL certificate warning, but make sure it's a local server and proceed.

#### Build Your Custom Web Server
Install Caprese package.

    nimble install https://github.com/zenywallet/caprese

It will take quite a while, so make some coffee. The Caprese body is located *~/.nimble/pkgs/caprese-0.1.0/* when installed. The version number may change, though. If you can't find it, try looking for *~/.nimble/pkgs2*.

In some directory, create *server.nim* file with the following code.

```nim
import caprese

server(ssl = true, ip = "0.0.0.0", port = 8009):
  routes:
    get "/":
      return send("Hello!".addHeader())

    return send("Not found".addHeader(Status404))

serverStart()
```

Build and launch.

    nim c -r --threads:on server.nim

Open [https://localhost:8009/](https://localhost:8009/) in your browser. You'll get a SSL certificate warning again, but do something.

### Features
- Multi-threaded server processing
- [WebSocket](https://datatracker.ietf.org/doc/html/rfc6455) support
- [TLS/SSL](https://en.wikipedia.org/wiki/Transport_Layer_Security) support. [BearSSL](https://bearssl.org/), [OpenSSL](https://www.openssl.org/), [LibreSSL](https://www.libressl.org/), or [BoringSSL](https://boringssl.googlesource.com/boringssl/) can be selected depending on the performance and the future security situation
- [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication) support for TLS/SSL. Servers can use multiple certificates of different hostnames with the same IP address
- Support for automatic renewal of [Let's Encrypt](https://letsencrypt.org/) SSL certificates without application restart
- Web pages are in-memory static files at compile time, dynamic file loading is also available for development
- Web proxy for backend and internal services
- Messaging functionality to send data from the server to clients individually or in groups
- Dependency-free executables for easy server deployment
- Languages - Nim 100.0%

### Requirements
- Linux, recommended Debian or Ubuntu  
  BSD, Windows will be supported

### Closure Compiler Setup
The closure-compiler is needed to minify javascript. It thoroughly optimizes even somewhat verbose and human understandable javascript generated by nim into short code.

    sudo apt install openjdk-19-jre maven

Maven is used to download the closure-compiler. Caprese automatically downloads and runs the closure-compiler internally. To download manually,

    mvn dependency:get -Ddest=./ -Dartifact=com.google.javascript:closure-compiler:LATEST

You can find closure-compiler-vyyyyMMdd.jar in the current path. Copy the file to the *src* path or *~/.nimble/pkgs/caprese-0.1.0/* of the caprese repository, *~/.nimble/pkgs* could be *~/.nimble/pkgs2*. If several versions of a closure-compiler are found in the path, the latest version is used.

Use *scriptMinifier* to make minified javascript.
```nim
import caprese

const HelloJs = staticScript:
  import jsffi
  var console {.importc, nodecl.}: JsObject
  console.log("hello")

const HelloMinJs = scriptMinifier(code = HelloJs, extern = "")

const HelloHtml = staticHtmlDocument:
  buildHtml(html):
    head:
      meta(charset="utf-8")
    body:
      tdiv: text "hello"
      script: verbatim HelloMinJs
```

It's amazing. Nothing could be more wonderful. [Karax](https://github.com/karaxnim/karax) is used to generate HTML.

Register in `extern` the names of some variables and functions that should not be changed by the closure-compiler. If a string is specified for `extern`, it will be read directly into `--externs` option of the closure-compiler via a file. You can also pass `extern` a list of keywords you want to prevent the closure-compiler from replacing strings in `seq[string]`. The list of keywords will be converted to a readable format by `--externs` and passed to the closure-compiler. In addition to them, when the Nim generates javascript, some keywords that should not be changed are automatically added internally to `extern`.

### Server Configuration
The server configuration is written in the `config:` block. The `config:` block should be set before the `server:` block. Below are the default settings. You only need to set the items you want to change or explain explicitly.

```nim
config:
  sslLib = BearSSL
  debugLog = false
  sigTermQuit = true
  sigPipeIgnore = true
  limitOpenFiles = -1
  serverWorkerNum = -1
  epollEventsSize = 10
  soKeepalive = false
  tcpNodelay = true
  clientMax = 32000
  connectionTimeout = 120
  recvBufExpandBreakSize = 131072 * 5
  maxFrameSize = 131072 * 5
  certsPath = "./certs"
  privKeyFile = "privkey.pem"
  fullChainFile = "fullchain.pem"
```

* **sslLib:** *None*, *BearSSL*(default), *OpenSSL*, *LibreSSL*, *BoringSSL*  
Somewhat surprisingly, Caprese supports 4 different SSL libraries. I would like to keep it a secret that *BearSSL* is the most extreme, with the smallest binary size and the fastest SSL processing speed. Enjoy the differences.  
If SSL is not required, it is recommended set to *None*. This will enable the experimental implementation of fast dispatch processing based on number of client connections and requests. At this time, it is only available for *None*.
* **debugLog:** *true* or *false*(default). If *true*, debug messages are output to the console.
* **sigTermQuit:** *true*(default) or *false*. If *true*, handling SIGTERM at the end of the process. The code in the `onQuit:` block is called before the process is terminated.
* **sigPipeIgnore:** Whether to ignore SIGPIPE. Caprese requires SIGPIPE to be ignored, but can be set to *false* if duplicated in other libraries.
* **limitOpenFiles:** *[Number of open files]*, *-1*(default, automatically set the maximum number of open files)
* **serverWorkerNum:** *[Number of processing threads]*, *-1*(default, automatically set the number of CPUs in the system)
* **connectionTimeout:** *[Client connection timeout in seconds]*, *-1*(disabled). The time to disconnect is not exact. Disconnection occurs between a specified second and twice the time.

### Server Routes
#### Example of a simple `server:` block

```nim
server(ip = "0.0.0.0", port = 8089):
  routes:
    get "/":
      return send(IndexHtml.addHeader())

serverStart()
```

#### Multiple URL paths

```nim
    get "/home":
      return send(HomeHtml.addHeader())

    get "/about":
      return send(AboutHtml.addHeader())
```

```nim
    get "/home", "/about":
      return send(MainHtml.addHeader())
```

#### URL path handling using Regular expression

```nim
    get re"/([a-z]+)(\d+)":
      return send(sanitizeHtml(matches[0] & "|" & matches[1]).addHeader())
```

#### 404 Not Found
```nim
  routes:
    get "/":
      ...

    let urlText = sanitizeHtml(reqUrl)
    return send(fmt"Not found: {urlText}".addDocType().addHeader(Status404))
```

#### Multiple ports for SSL website and no SSL website

```nim
server(ssl = true, ip = "0.0.0.0", port = 8009):
  routes(host = "website1"):
    certificates(path = "./certs/website1"):
      privKey: "privkey.pem"
      fullChain: "fullchain.pem"

    get "/":
      return send(WebSite1Html.addHeader())

server(ip = "0.0.0.0", port = 8089):
  routes(host = "website1"):
    get "/":
      return send(WebSite1Html.addHeader())

serverStart()
```

The `host` value of the `routes:` block is actually set to your domain name.

#### Set the certificate path for each

```nim
    certificates:
      privKey: "./certs/priv/privkey.pem"
      fullChain: "./certs/chain/fullchain.pem"
```
#### Specify default certificate file names and omit them

```nim
config:
  ...
  privKeyFile = "privkey.pem"
  fullChainFile = "fullchain.pem"

server(ssl = true, ip = "0.0.0.0", port = 8009):
  routes(host = "website1"):
    certificates(path = "./certs/website1")

    get "/":
      return send(WebSite1Html.addHeader())
```

#### Specify default certificate path and omit `certificates:` block

```nim
config:
  ...
  certsPath = "./certs"
  privKeyFile = "privkey.pem"
  fullChainFile = "fullchain.pem"

server(ssl = true, ip = "0.0.0.0", port = 8009):
  routes(host = "website1"):
    get "/":
      return send(WebSite1Html.addHeader())
```

In the above example, the following two files are loaded.

    ./certs/website1/privkey.pem
    ./certs/website1/fullchain.pem

The `host` value of the `routes:` block is used for the file location.

    <certsPath>/<routes host>/{<privKeyFile>,<fullChainFile>}

#### Multi-website configuration on the same port with SSL

```nim
server(ssl = true, ip = "0.0.0.0", port = 8089):
  routes(host = "website1"):
    certificates(path = "./certs/website1"):
      privKey: "privkey.pem"
      fullChain: "fullchain.pem"

    get "/":
      return send(WebSite1Html.addHeader())

  routes(host = "website2"):
    certificates(path = "./certs/website2"):
      privKey: "privkey.pem"
      fullChain: "fullchain.pem"

    get "/":
      return send(WebSite2Html.addHeader())

serverStart()
```

#### Pending and worker
The runnable level inside the `server:` block is called the server dispatch-level. Inside the block is called from multiple threads, it must not call functions that generate waits and must return results immediately. If the response cannot be returned immediately, return pending first and then process it in another worker thread. Feel free to use async/await in another thread.

```nim
type
  PendingData = object
    url: string

var reqs = newPending[PendingData](100)

onQuit:
  reqs.drop()

worker(num = 2):
  while true:
    let req = reqs.getPending()
    let urlText = sanitizeHtml(req.data.url)
    let clientId = req.cid
    clientId.send(fmt("worker {urlText}").addHeader())

server(ip = "0.0.0.0", port = 8089):
  routes(host = "website1"):
    get "/test":
      return reqs.pending(PendingData(url: reqUrl))

    let urlText = sanitizeHtml(reqUrl)
    return send(fmt"Not found: {urlText}".addDocType().addHeader(Status404))

serverStart()
```

The send commands executed by another worker thread invoke a server dispatch-level thread to execute the sending process. The number of threads in the `server:` block is the number of *serverWorkerNum* in the `config:` block. The same worker threads are used even in a multi-port configuration with multiple `server:` blocks, and the number of threads remains the same.

One of the reasons for creating Caprese is stream encryption. The common method of stream encryption using a web proxy server in a separate process seems inefficient. To reduce context switches, it would be better to handle stream encryption in the same thread context as the SSL process, like the `server:` block in the Caprese.

#### Thread context variables
Put before the `routes:` block in the `server:` block. Um, how do I access it?

```nim
server(ip = "0.0.0.0", port = 8089):
  var localThreadBuffer = newSeq[byte](1024)

  routes:
    ...
```

#### Web pages and WebSocket use the same port
To use WebSocket, add a `stream:` block in the `routes:` block. When a WebSocket connection is established, the `onOpen:` block is called. When a message is received, the `onMessage:` block is called. When the connection is closed, the `onClose:` block is called.
Although a bit tricky to use, WebSockets and web pages can also use the same url path like `/`. In that case, the `get:` path to the web page should be after the `stream:`.

```nim
server(ssl = true, ip = "0.0.0.0", port = 8009):
  routes(host = "website1"):
    certificates(path = "./certs/website1"):
      privKey: "privkey.pem"
      fullChain: "fullchain.pem"

    get "/wstest":
      return send(WsTestHtml.addHeader())

    stream(path = "/ws", protocol = "caprese-0.1"):
      onOpen:
        # client: Client
        echo "onOpen"

      onMessage:
        # client: Client
        # opcode: WebSocketOpCode
        # data: ptr UncheckedArray[byte]
        # size: int
        echo "onMessage"
        return wsSend(data.toString(size), WebSocketOpcode.Binary)

      onClose:
        # client: Client
        echo "onClose"

    get "/ws":
      return send("WebSocket Protocol: caprese-0.1".addHeader())
```

#### Custom WebSocket handling such as ping and pong

```nim
    stream(path = "/ws", protocol = "caprese-0.1"):
      # client: Client
      onOpen:
        echo "onOpen"

      # client: Client
      # opcode: WebSocketOpCode
      # data: ptr UncheckedArray[byte]
      # size: int
      case opcode
      of WebSocketOpcode.Binary, WebSocketOpcode.Text, WebSocketOpcode.Continue:
        echo "onMessage"
        return wsSend(data.toString(size), WebSocketOpcode.Binary)
      of WebSocketOpcode.Ping:
        return wsSend(data.toString(size), WebSocketOpcode.Pong)
      of WebSocketOpcode.Pong:
        debug "pong ", data.toString(size)
        return SendResult.Success
      else: # WebSocketOpcode.Close
        echo "onClose"
        return SendResult.None
```

#### WebSocket without protocol check

```nim
  routes:
    get "/wstest":
      ...

    stream "/ws":
      ...
```

#### Check multiple protocols of the WebSocket
Use `onProtocol:` block.

```nim
  routes:
    ...

    stream "/ws":
      onProtocol:
        let prot = reqProtocol()
        if prot == "caprese-0.2":
          return (true, "caprese-0.2")
        elif prot == "caprese-0.1":
          return (true, "caprese-0.1")
        else:
          return (false, "")

      onOpen:
        ...
```

#### Routes helper APIs
* **reqUrl:** URL requested from client, always starts `/`. Caprese will reject requests that do not begin with `/`. This means that when concatenating URL strings in a request, it is guaranteed that there will always be a `/` between the strings.
* **reqHost:** Hostname requested in the header from client. It may be different from the hostname negotiated by SSL. Incorrect hostnames should be rejected. If the `host` of `routes:` is specified, unmatched hosts will be ignored and will not be processed within that `routes:` block. You may use `reqHost` for custom handling without `host` of `routes:`.
* **reqProtocol:** WebSocket protocol requested by the client. See [Check multiple protocols of the WebSocket](#check-multiple-protocols-of-the-websocket) for details.
* **reqHeader(HeaderID):** Get the specific header parameter of the client request by *HeaderID*. See [Http Headers](#http-headers) for details.
* **reqClient:** Pointer to the client object currently being processed in the thread context, the same as `client`. Normally, `client` should be used.

### Http Headers
There are various efficient ways to parse http headers, though, Caprese uses the approach of predefining only the headers to be used and reading only those headers that are needed. I could not find any servers implementing this approach, so it may be very novel approach. Compared to a fast header parsing algorithm, this approach had an advantage over it.

Enumerate any header IDs you have determined and target strings of headers to be retrieved in the `httpHeader:` block. The `httpHeader:` block must be in the `config:` block.

```nim
config:
  sslLib = BearSSL
  ...

  httpHeader:
    HeaderHost: "Host"
    HeaderUserAgent: "User-Agent"
    ...
```

Get the header string by specifying the header ID with the `reqHeader()` in the `routes:` block.

```nim
  routes:
    let userAgent = reqHeader(HeaderUserAgent)
    echo userAgent
```

The `reqHeader:` can only be called within the `routes:` block contexts, because the headers only manage the read position of the receive buffer, which may be in the server thread context.

### Publishing Static Files
Use `public:` block. All files in `importPath` are statically imported into the code at compile time. Specify the `importPath` as relative path like Nim `import`, however, double quotes are necessary. The `importPath` is added internally `getProjectPath()`.

```nim
  routes:
    public(importPath = "../public")
```

 Inside the `public:` block, `responce()` is used, which sends compressed files if the client allows to receive *Brotli* or *Deflate*. It also checks the *If-None-Match* header and return *304 Not Modified* if the file has not been changed.

Custom handling such as changing the base URL.

```nim
  routes:
    public(importPath = "../public"):
      let retFile = getFile("/webroot" & reqUrl)
      if retFile.err == FileContentSuccess:
        return response(retFile.data)
```

You can also create static content objects from static strings with `content()`. The second argument of `content()` does not have to be a formal MIME type, but can be an extension such as *html* or *js*. The content object has uncompressed, Deflate compressed, Brotli compressed, MIME type, SHA256 hash, and MD5 hash.

```nim
const IndexHtml = staticHtmlDocument:
  buildHtml(html):
    ...

const AppJs = staticScript:
    ...

const AppMinJs = scriptMinifier(code = AppJs, extern = "")

server(ssl = true, ip = "0.0.0.0", port = 8009):
  routes(host = "website1"):
    get "/":
      return response(content(IndexHtml, "text/html"))

    get "/js/app.js":
      return response(content(AppMinJs, "application/javascript"))
```

### Web Proxy
The Caprese's proxy is different from a typical proxy server and is more simplified. It may be faster than a typical proxy server due to the following specifications. It would be more useful in simple configurations.

- The request URL and http headers are not changed. Since data is sent and received without changing the data to the proxy destination, it would work fine with WebSockets and such.
- When a client makes a request to a proxy path, all subsequent communication is connected to the proxy destination until disconnected. The proxy path is simply compared to the URL, and if the first string matches, proxy forwarding starts. It may be better to add a `/` at the end of the proxy path to make it strict.
- External connections are made with SSL, but no SSL inside the proxy. It could be used for internal connections or to connect to back-end services.

#### `proxy:` block
```nim
import caprese

server(ssl = true, ip = "0.0.0.0", port = 8009):
  routes(host = "localhost"):
    proxy(path = "/", host = "localhost", port = 8089)

server(ip = "127.0.0.1", port = 8089):
  routes(host = "localhost:8009"):
    get "/":
      return response(content("Hello!", "text/html"))

    return send("Not found".addHeader(Status404))

serverStart()
```

It might be better not to check the hostname and port.
```nim
server(ip = "127.0.0.1", port = 8089):
  routes: # no hostname and port check
    get "/":
```

#### Debug or custom handling
```nim
server(ssl = true, ip = "0.0.0.0", port = 8009):
  routes(host = "localhost"):
    proxy(path = "/", host = "localhost", port = 8089):
      debug "url=", reqUrl
      # custom handling here
```

#### UNIX domain socket
You can also use UNIX domain sockets. It will provide a fast internal connection.

```nim
import caprese

server(ssl = true, ip = "0.0.0.0", port = 8009):
  routes(host = "localhost"):
    proxy(path = "/", unix = "/tmp/caprese1.sock")

server(unix = "/tmp/caprese1.sock"):
  routes(host = "localhost:8009"):
    get "/":
      return response(content("Hello!", "text/html"))

    return send("Not found".addHeader(Status404))

serverStart()
```

### Tag-based Message Exchange
Let me explain one of the unique features of the Caprese that is not implemented in common web servers. Tags can be attached to client connections. It is possible to send some data to the tag. That data will be sent to all tagged clients. The tag value must be a number or at least 8 bytes of data. It could be a string or something else, but it is better to use hashed data. It is assumed that the data is hashed originally, and no internal hashing of tags is performed. Hashing would be easy with Nim's `converter`. To control the tags, you need the *ClientId*, which you can get with `markPending()`.

#### The tag control functions
```nim
proc markPending(client: Client): ClientId
proc unmarkPending(clientId: ClientId)
proc unmarkPending(client: Client)
proc setTag(clientId: ClientId, tag: Tag)
proc delTag(clientId: ClientId, tag: Tag)
proc delTags(clientId: ClientId)
proc delTags(tag: Tag)
proc getClientIds(tag: Tag): Array[ClientId]
proc getTags(clientId: ClientId): Array[Tag]
iterator getClientIds(tag: Tag): ClientId
iterator getTags(clientId: ClientId): Tag
```

#### Send to tag, WebSocket only
```nim
proc wsSend(tag: Tag, data: seq[byte] | string | Array[byte],
            opcode: WebSocketOpCode = WebSocketOpCode.Binary): int
```

This is a feature that was originally used in the server of the block explorer. What this is used for is that if the HASH160 of addresses in the user wallets are registered as tags, when a new block is found, in the process of parsing the block and transactions, address-related information can be sent to the tags of the found addresses, and the user wallets will be notified in real time.

### Release Build
Non-root users cannot use privileged ports such as 80 or 443 by default, so capabilities must be added after each build.

    sudo setcap cap_net_bind_service=+ep ./caprese

**Note:** The target file name should actually be your executable file name.

If the above command is not executed, the following bind error will occur.

    error: bind ret=-1 errno=13

### Let’s Encrypt
At least http port 80 needs to be open for ACME HTTP-01 challenge. One method is to reply ACME tokens on http port 80, another is to redirect http port 80 to https port 443 and reply ACME tokens on the https connection. ACME does not verify certificates, Caprese has self-certificates and can connect with SSL by simply enabling SSL, so SSL connections for ACME are available on https even without certificate files yet. Try redirecting http to https and handling ACME.

```nim
import caprese

server(ssl = true, ip = "0.0.0.0", port = 443):
  routes(host = "YOUR_DOMAIN"):
    certificates(path = "./certs/YOUR_DOMAIN"):
      privKey: "privkey.pem"
      fullChain: "fullchain.pem"

    get "/":
      return send("Hello!".addHeader())

    acme(path = "./www/YOUR_DOMAIN"):
      echo "acme ", reqUrl, " ", mime
      echo content

    return send("Not Found".addHeader())

server(ip = "0.0.0.0", port = 80):
  routes(host = "YOUR_DOMAIN"):
    return send(redirect301("https://YOUR_DOMAIN" & reqUrl))

serverStart()
```

Create a *server.nim* file with the above code and launch *server* as a non-root user. Open ports 80 and 443 to allow connections from external clients.

    nim c -d:release --threads:on --mm:orc server.nim
    sudo setcap cap_net_bind_service=+ep ./server
    ./server

With *server* running, execute the following *certbot* command as root user. Specify the web root folder where *certbot* will place the ACME HTTP-01 challenge token.

    certbot certonly --webroot -w /path/to/www/YOUR_DOMAIN -d YOUR_DOMAIN

ECDSA or something if you like.

    certbot certonly --key-type ecdsa --elliptic-curve secp384r1 --webroot -w /path/to/www/YOUR_DOMAIN -d YOUR_DOMAIN

Or write it in */etc/letsencrypt/cli.ini* file.

    key-type = ecdsa
    elliptic-curve = secp384r1

If successful, the certificate files will be created in the following path.

    /etc/letsencrypt/live/YOUR_DOMAIN/{privkey.pem,fullchain.pem}

These files should be copied to the *certs* folder. Caprese monitors the files in the *certs* folder and automatically loads the new certificates if any files are changed. However, it is necessary to change the permissions on the certificate files so that user running Caprese can access it.

Create *caprese_certs_update.sh*, in the following, user and group is assumed to be *caprese*.

```bash
#!/bin/bash
mkdir -p /path/to/certs/YOUR_DOMAIN
cp /etc/letsencrypt/live/YOUR_DOMAIN/{privkey.pem,fullchain.pem} /path/to/certs/YOUR_DOMAIN
chown -R caprese:caprese /path/to/certs
```

Copy *caprese_certs_update.sh* to letsencrypt post hook.

    cp caprese_certs_update.sh /etc/letsencrypt/renewal-hooks/post

First copy of certificate files, also for testing.

    certbot renew --dry-run

Now open [http://YOUR_DOMAIN/](http://YOUR_DOMAIN/) in your browser. If the URL http redirects to https and there is no certificate warning, it is successful.

If you have just created the directory */path/to/certs/YOUR_DOMAIN*, wait about 30 seconds before opening the URL. This is because if the directory does not exist yet, real-time file monitoring to update the certificates is deactivated. Once the Caprese has detected the directory, monitoring is activated, the certificates will be updated instantly after the certificate files have been changed.

### Leftover Desserts
- POST
- IPv6
- QUIC
- Cookies

### License
MIT
