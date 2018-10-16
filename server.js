var express = require('express')
  , static_pages = require('serve-static')
  , body_parser = require('body-parser')
  , mustache = require('mustache-express')
  , fs = require('fs')
  , md5 = require('md5')
;
var urlencoded_parser = body_parser.urlencoded({extended: false})
  , app = express()
;

/* ****************************************************************************
**
** Configure template engine
**
** ***************************************************************************/
let VIEWS_PATH =  __dirname + '/views';
app.engine('html', mustache(VIEWS_PATH,'.html'));
app.set('view engine', 'mustache');
app.set('views', VIEWS_PATH);


/* ****************************************************************************
**
** Configure routes
**
** ***************************************************************************/

/*
** resources with content-type not matching file extension
*/
app.get('/file1.html', function(request,response,next) {
  request.params = { file: 'htdocs/hello.jpeg', type:'image/jpeg' };
  send_fake(request,response);
});
app.get('/file2.html', function(request,response,next) {
  request.params = { file: 'htdocs/hello.gif', type:'image/gif' };
  send_fake(request,response);
});
app.get('/file3.html', function(request,response,next) {
  request.params = { file: 'htdocs/hello.pdf', type:'application/pdf' };
  send_fake(request,response);
});

/*
** redirecting resources
*/
app.get('/redirect', function(request,response,next) {
  response.writeHead(301, { 'Location': 'http://www.ec-lyon.fr' });
  response.end();
});

/*
** HTTP Basic protected resource
*/
app.get('/user.html', function(request,response,next) {
  var auth = request.headers.authorization;
  if ( auth && auth.indexOf('Basic') === 0 ) {
    var encoded = auth.split(' ')[1].trim()
      , decoded = new Buffer(encoded,'base64').toString('ascii')
    ;
    if ( decoded == 'be-http:cool!' ) next();
    else send_401_basic(request,response);
  }
  else send_401_basic(request,response);
});
app.get('/401/basic', send_401_basic);

// encode
app.get('/encode/*', function(request,response,next) {
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
** HTTP Digest protected resource
*/
app.get('/digest.html', function(request,response,next) {
  var auth = request.headers.authorization;
  if ( auth ) {
    let info = auth_info(auth)
      , A1 = md5(info.username+':'+info.realm+':'+'cool!')
      , A2 = md5(request.method+':'+info.uri)
      , expected = md5(A1+':'+info.nonce+':'+A2)
    ;
    if ( info.response == expected ) next();
    else send_401_digest(request,response);
  }
  else send_401_digest(request,response);
});
app.get('/401/digest/*', send_401_digest);

// MD5
app.get('/md5', function(request, response, next) {
  var url = request.url.substring(1);
  response.writeHead(200, {
    'Content-Type': 'text/plain; charset=utf-8'
  });
  response.end(md5(url));
});


/* ****************************************************************************
**
** List service
**
** ***************************************************************************/
var lists = {};

/*
** POST /list  - create a list
**   params : name
**   returns : empty list
*/

// GET list/$listid
// PUT /list/$listid update
// DELETE /list/$listid


/*
** 405 Method Not Allowed
*/
app.delete('*',function(request,response) {
  send_405(request, response);
});
app.patch('*',function(request,response) {
  send_405(request, response);
});
app.post('*',function(request,response) {
  send_405(request, response);
});
app.put('*',function(request,response) {
  send_405(request, response);
});

/*
** static pages
*/
app.use(static_pages('htdocs'));

/*
** 404 Not Found
*/
app.use(function(request,response) {
  send_404(request, response);
});



/* ****************************************************************************
**
** Local middleware
**
** ***************************************************************************/

function send_401_basic(request,response) {
  response.status(401).set({
    'WWW-Authenticate': 'Basic realm="BE-HTTP"',
  }).render( 'error.html', {
    bgcolor: "#066",
    code: "401 : Authorization Required",
    msg:"Ce document est protégé par mot de passe"
  });
}
function send_401_digest(request,response) {
  response.status(401).set({
    'WWW-Authenticate': 'Digest realm="BE-HTTP", nonce="abc"'
  }).render( 'error.html', {
    bgcolor: "#060",
    code: "401 : Authorization Required",
    msg:"Ce document est protégé par mot de passe"
  });
}
function send_404(request,response) {
  response.status(404).render( 'error.html', {
    bgcolor: "#006",
    code: "404 : Not Found",
    msg:"Désolé le document demandé est introuvable"
  });
}
function send_405(request,response) {
  response.status(404).render( 'error.html', {
    bgcolor: "#600",
    code: "405 : Method Not Allowed",
    msg:"La méthode "+request.method+" n'est pas autorisée pour cette ressource"
  });
}

function send_fake(request, response) {
  var file = request.params.file
    , type = request.params.type
  ;
  fs.stat(file, function(err, stats) {
    if ( err ) {
	console.log(err);
        send_404(response);
        return;
    }
    response.writeHead(200, {
      'Content-Type': type,
      'Content-Length': stats.size,
      'Last-Modified': stats.mtime.toUTCString()
    });
    let stream = fs.createReadStream(file);
    stream.on('error', function(e) { send_404(response); });
    stream.on('data', function(data) { response.write(data); });
    stream.on('end', function(data) { response.end(); });
  });
}

function send_json(request, response) {
  response.writeHead(200, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(response.data || null));
}


/* ****************************************************************************
**
** Other functions
**
** ***************************************************************************/

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
