var connect = require('connect')
  , static_pages = require('serve-static')
  , fs = require('fs')
  , md5 = require('md5')
  , app = connect()
;

/* ****************************************************************************
**
** Configure routes
**
** ***************************************************************************/

/*
** resources with content-type not matching file extension
*/
app.use('/file1.html', function(request,response,next) {
  send_fake(response,'htdocs/hello.jpeg','image/jpeg');
});
app.use('/file2.html', function(request,response,next) {
  send_fake(response,'htdocs/hello.gif','image/gif');
});
app.use('/file3.html', function(request,response,next) {
  send_fake(response,'htdocs/hello.pdf','application/pdf');
});

/*
** redirecting resources
*/
app.use('/redirect', function(request,response,next) {
  response.writeHead(301, { 'Location': 'http://www.ec-lyon.fr' });
  response.end();
});

/*
** password protected resources
*/
app.use('/user.html', function(request,response,next) {
  var auth = request.headers.authorization;
  if ( auth && auth.indexOf('Basic') === 0 ) {
    var encoded = auth.split(' ')[1].trim()
      , decoded = new Buffer(encoded,'base64').toString('ascii')
    ;
    if ( decoded == 'be-http:cool!' ) next();
    else send_401_basic(response);
  }
  else send_401_basic(response);
});
app.use('/401/basic', function(request,response,next) {
  send_401_basic(response);
});
app.use('/digest.html', function(request,response,next) {
  var auth = request.headers.authorization;
  if ( auth ) {
    let info = auth_info(auth)
      , A1 = md5(info.username+':'+info.realm+':'+'cool!')
      , A2 = md5(request.method+':'+info.uri)
      , expected = md5(A1+':'+info.nonce+':'+A2)
    ;
    if ( info.response == expected ) next();
  }
  else send_401_digest(response);
});
app.use('/401/digest', function(request,response,next) {
  send_401_digest(response);
});

/*
** base64 encode
*/
app.use('/encode', function(request,response,next) {
  var url = request.url.substring(1)
    , encoded = Buffer.from(url).toString('base64')
  ;
  // console.log(url,encoded);
  response.writeHead(200, {
    'Content-Type': 'text/plain; charset=utf-8'
    });
  response.end(encoded);
});

/*
** static pages
*/
app.use(static_pages('htdocs'));

/*
** 404 Not Found
*/
app.use(function(request,response) {
  send_404(response);
});


/* ****************************************************************************
**
** Misc functions
**
** ***************************************************************************/

function send_401_basic(response) {
  response.writeHead(401, {
    'WWW-Authenticate': 'Basic realm="BE-HTTP"',
    'Content-Type': 'text/plain; charset=utf-8'
  });
  response.end('Désolé, ce document est protégé par mot de passe...');
}
function send_401_digest(response) {
  response.writeHead(401, {
    'WWW-Authenticate': 'Digest realm="BE-HTTP", nonce="abc"',
    'Content-Type': 'text/plain; charset=utf-8'
  });
  response.end('Désolé, ce document est protégé par mot de passe...');
}
function send_404(response) {
  response.writeHead(404, {
    'Content-Type': 'text/plain; charset=utf-8'
    });
  response.end('Désolé, le document demandé est introuvable...');
}
function send_fake(response,file,type) {
  var sent_header = false
    , stream = fs.createReadStream(file)
  ;
  stream.on('error', function(e) {
    // console.log(e);
    send_404(response);
  });
  stream.on('data', function(data) {
    if ( ! sent_header ) {
      response.writeHead(200, { 'Content-Type': type });
      sent_header = true;
    }
    response.write(data);
  });
  stream.on('end', function(data) { response.end(); });
}

// get info from auth string
function auth_info(auth) {
  return auth.split(/,? /).reduce( function(o,s) {
    let [k,v] = s.split('=');
    if ( v ) {
      v = v.trim();
      o[k] = v.substr(1,v.length-2);
    }
    return o;
  },{});
}


/* ****************************************************************************
**
** Main program
**
** ***************************************************************************/

let port = process.env.PORT || 8088;
app.listen(port);
console.log("listening on port "+port);
