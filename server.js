var express = require('express')
  , static_pages = require('serve-static')
  , body_parser = require('body-parser')
  , mustache = require('mustache-express')
  , fs = require('fs')
  , md5 = require('md5')
;
var urlencoded_parser = body_parser.urlencoded({extended: false})
  , json_parser = body_parser.json({strict: false})
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
let send_401_basic = send_401('Basic','BE-HTTP');
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
let send_401_digest = send_401('Digest','BE-HTTP','abc');
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
let lists = {}
  , list_name = () => 'list-'+(new Date()).getTime()
  , list_data = (value) => Array.isArray(value) ? value : [value]
  , new_list = (value) => {
      let name = list_name();
      if ( lists[name] ) return new_list();
      lists[name] = { name, data:  list_data(value) };
      return lists[name];
    }
;

/*
** POST /todolist  - create a todolist
**   param : value = String | [String]
**   returns : new todolist
*/
app.post('/todolist', check_content_types([
    'application/x-www-form-urlencoded',
    'application/json'
  ]),
  json_parser,
  urlencoded_parser,
  check_params('body',['value']),
  function(request,response,next) {
    response.data = new_list(request.body.value);
    send_json(request,response);
  }
);

/*
** PUT /todolist/:id - change given todolist
**   param : value = String | [String]
**   returns : modified todolist
*/
app.put('/todolist/:id', check_content_types([
    'application/x-www-form-urlencoded',
    'application/json'
  ]),
  json_parser,
  urlencoded_parser,
  check_params('body',['value']),
  check_list,
  function(request,response,next) {
    lists[request.params.id].data = list_data(request.body.value);
    response.data = lists[request.params.id];
    send_json(request,response);
  }
);

/*
** PATCH /todolist/:id - patch given todolist
**   does a splice
**   param : index = integer
**   param : delete = integer
**   param : value = String | [String]
**   returns : patched todolist
*/
app.patch('/todolist/:id', check_content_types([
    'application/x-www-form-urlencoded',
    'application/json'
  ]),
  json_parser,
  urlencoded_parser,
  check_params('body',['index','delete','value']),
  check_list,
  function(request,response,next) {
    lists[request.params.id].data.splice(
      request.body.index, request.body.delete, ...list_data(request.body.value));
    response.data = lists[request.params.id];
    send_json(request,response);
  }
);

/*
** GET /todolist/:id - return given todolist
*/
app.get('/todolist/:id',
  check_list,
  function(request,response,next) {
    response.data = lists[request.params.id];
    send_json(request,response);
  }
);

/*
** DELETE /todolist/:id - delete given todolist
*/
app.delete('/todolist/:id',
  check_list,
  function(request,response,next) {
    delete lists[request.params.id];
    response.status(204).end();
  }
);


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

function check_list(request,response,next) {
  var name = request.params.id;
  if ( !lists[name] ) {
    response.status(404).render( 'error.html', {
      bgcolor: "#006",
      code: "404 : Not Found",
      msg:"La liste demandée n'existe pas"
    });
  }
  else next();
}
function check_content_types(media_types) {
  return function(request,response,next) {
    var ct = request.get('Content-Type');
    // 415 - Unsupported Media type
    if ( media_types.indexOf(ct) == -1 ) {
      response.detail = media_types;
      send_415(request,response);
    }
    else next();
  }
}
function check_params(ctx,params) {
  return function(request,response,next) {
    console.log('context',request[ctx]);
    var missing = params.reduce((a,p) => request[ctx] && typeof request[ctx][p] != 'undefined' ? a : a.concat([p]),[]);
    // 422 - Unprocessable entity
    if ( missing.length ) {
      response.detail = missing;
      send_422(request,response);
    }
    else next();
  }
}
function send_401(auth_method, realm, nonce='') {
  var supported = ['Basic','Digest']
    , method = (supported.indexOf(auth_method) > -1) ? auth_method : 'Basic'
    , info = {
        Basic: { color:'#066', auth: method+' realm="'+realm+'"' },
        Digest: { color:'#060', auth: method+' realm="'+realm+'", nonce="'+nonce+'"' }
      }
  ;
  return function(request,response) {
    response.status(401).set({
      'WWW-Authenticate': info[method].auth,
    }).render( 'error.html', {
      bgcolor: info[method].color,
      code: "401 : Authorization Required",
      msg:"Ce document est protégé par mot de passe"
    });
  };
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
function send_415(request,response) {
  response.status(422).render( 'error.html', {
    bgcolor: '#fa4',
    code: "415 : Unsupported Media Type",
    msg:"Type de contenu non supporté"+(response.detail ? " ('"+
      response.detail.join("' ou '")+"' attendu)" : '')
  });
}
function send_422(request,response) {
  response.status(422).render( 'error.html', {
    bgcolor: "#ec0",
    code: "422 : Unprocessable Entity",
    msg: "Impossible de traiter la requête"+(response.detail ?
      ", paramètre"+(response.detail.length > 1 ? 's':'') +
      " manquant"+(response.detail.length > 1 ? 's':'') + ' : ' +
      response.detail.join(', ') : '')
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
