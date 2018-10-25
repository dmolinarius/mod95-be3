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
app.get('/moved', function(request,response,next) {
  response.writeHead(301, { 'Location': 'http://www.ec-lyon.fr' });
  response.end();
});
app.get('/found', function(request,response,next) {
  response.writeHead(302, { 'Location': 'http://www.ec-lyon.fr' });
  response.end();
});
app.get('/temp', function(request,response,next) {
  response.writeHead(307, { 'Location': 'http://www.ec-lyon.fr' });
  response.end();
});
app.get('/perm', function(request,response,next) {
  response.writeHead(308, { 'Location': 'http://www.ec-lyon.fr' });
  response.end();
});

/*
** HTTP Basic protected resources
*/
function check_basic_user(user,password) {
  return (user == 'be-http' && password == 'cool!') ? {user, password} : null;
};

realm = 'BE-HTTP';
app.get('/user.html', basic_auth(realm, check_basic_user));
app.get('/401/basic', err(401).basic(realm));
app.use(render_401_basic);

// encode
app.get('/encode/*', (req,res,next) => {
    res.body = Buffer.from(req.params[0]).toString('base64');
    next();
  },
  send_text
);

/*
** HTTP Digest protected resources
*/
function check_digest_user(user,realm) {
  var users = { 'be-http': { 'BE-HTTP': md5('be-http:BE-HTTP:cool!') } };
  return users[user] ? users[user][realm] : null;
};

realm = 'BE-HTTP';
app.get('/digest.html', digest_auth(realm, check_digest_user));
app.get('/401/digest', err(401).digest(realm,create_nonce));

realm = 'Digest 2';
app.get('/digest2.html', digest_auth(realm, check_digest_user));
app.get('/401/digest2', err(401).digest(realm,create_nonce));

app.use(render_unknown_user, render_unallowed_realm, render_wrong_password, render_401_digest);

// MD5
app.get('/md5/*', (req,res,next) => {
    res.body = md5(req.params[0]);
    next();
  },
  send_text
);


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
    // TODO check index and delete to be integers in a reasonable range
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
** List management middleware
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
    var missing = params.reduce((a,p) => request[ctx] && typeof request[ctx][p] != 'undefined' ? a : a.concat([p]),[]);
    // 422 - Unprocessable entity
    if ( missing.length ) {
      response.detail = missing;
      send_422(request,response);
    }
    else next();
  }
}

/* ****************************************************************************
**
** Basic authentication middleware
**
** ***************************************************************************/

function basic_auth(realm,check_user) {
  return function (request,response,next) {
    var auth = request.headers.authorization
      , err_401 = err(401).basic(realm)
    ;
    if ( auth && auth.indexOf('Basic') === 0 ) {
      var encoded = auth.split(' ')[1].trim()
        , decoded = Buffer.from(encoded,'base64').toString('ascii')
        , [username,password] = decoded.split(':')
      ;
      request.user = check_user(username,password);
      if ( request.user ) next();
      else err_401(request,response,next);
    }
    else err_401(request,response,next);
  };
}


/* ****************************************************************************
**
** Digest authentication middleware
**
** ***************************************************************************/

nonces = [];
function create_nonce(request) {
  var ip = get_client_ip(request)
    , time = (new Date()).getTime()
    , method = request.method
    , nonce = md5(method+':'+time+':'+ip)
  ;
  nonces[nonce] = {ip, time, method};
  setTimeout(() => {
    delete nonces[nonce];
  },3600000); // 1 hour
  return nonce;
}
function check_nonce(request,response,next) {
  var info = request.auth_info
    , ip = get_client_ip(request)
    , method = request.method
    , time = (new Date()).getTime()
    , nonce = info.nonce
  ;
  if ( ! nonce ) {
    err(401).digest(info.realm,create_nonce)(request,response,next);
  }
  else if ( !nonces[nonce] ) {
    err(401,'Illegal nonce').digest(info.realm,create_nonce)(request,response,next);
  }
  else {
    nonce_info = nonces[nonce];
    if ( nonce_info.ip != ip ) {
      err(401,'IP not allowed '+nonce_info.ip+', '+ip).digest(info.realm,create_nonce)(request,response,next);
    }
    else if ( nonce_info.method != method ) {
      err(401,'Method not allowed').digest(info.realm,create_nonce)(request,response,next);
    }
    // nonce duration is 30s - too short for a static server, more than enough for an API
    else if ( time - nonce_info.time > 30000 ) {
      err(401,'Stale nonce').digest(info.realm,create_nonce)(request,response,next);
    }
    else next();
  }
}

function digest_auth_parser(request,response,next) {
  var auth = request.headers.authorization
    , err_401 = err(401) // no message
  ;
  if ( auth && auth.indexOf('Digest') === 0 ) {
    request.auth_info =  auth.split(/,? /).reduce( function(o,s) {
      let [k,v] = s.split('=');
      if ( v ) {
        v = v.trim();
        o[k] = v.substr(1,v.length-2);
      }
      return o;
    },{});
    next();
  }
  else next(err_401); // no Digest Authorization header
}

function digest_auth(realm, check_user) {
  return function(request, response, next) {
    digest_auth_parser(request, response, function(error) {
      if (error) error.digest(realm,create_nonce)(request, response, next);
      else check_nonce(request, response, function(error) {
        if (error) next(error);
        else {
          let info = request.auth_info
            , A1 = check_user(info.username, realm)
          ;
          if ( A1 === null ) {
            err(401,'unknown user').digest(realm,create_nonce)(request, response, next);
          }
          else if ( A1 === undefined ) {
            err(401,'realm not allowed').digest(realm,create_nonce)(request, response, next);
          }
          else {
            let A2 = md5(request.method+':'+info.uri)
              , expected = md5(A1+':'+info.nonce+':'+A2)
            ;
            if ( info.response == expected ) next(); // user is authenticated
            else err(401,'wrong password').digest(realm,create_nonce)(request, response, next);
          }
        }
      });
    });
  };
}

/*
** cf. https://stackoverflow.com/questions/18264304/get-clients-real-ip-address-on-heroku
*/
function get_client_ip(request) {
  var xff = request.headers['x-forwarded-for'];
  return (xff && xff.split(',').pop().trim()) || request.ip;
}

/* ****************************************************************************
**
** Middleware to send default status messages
**
** ***************************************************************************/
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


/* ****************************************************************************
**
** Middleware to send body with various content-types
**
** ***************************************************************************/
function send_fake(request, response) {
  var file = request.params.file
    , type = request.params.type
  ;
  fs.stat(file, function(error, stats) {
    if ( error ) {
	console.log(error);
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

function send_text(request, response) {
  response.writeHead(200, {
    'Content-Type': 'text/plain; charset=utf-8'
  });
  response.end(response.body);
}


/* ****************************************************************************
**
** Status generator middleware
**
** Usage (examples all return a middleware calling next with an error object) :
**
**  - err(401,message).basic(realm)
**      calls next with {code, message, realm}
**
**  - err(401,message).digest(realm, nonce_generator=null)
**      calls next with {code, message, realm, nonce}
**
**  - err(other_status,message)
**      calls next with {code, message}
**
** Helper functions signature :
**  - nonce_generator(request) returns nonce
**
** ***************************************************************************/

function err(code, message=null) {
  var error = { code, message };

  // 401 needs authentication header
  if ( code == 401 ) {
    return {

      // basic authentication
      basic: function(realm) {
        return function(request, response, next) {
          response.status(code).set({
            'WWW-Authenticate': 'Basic realm="'+realm+'"'
          });
          next({...error, realm});
        };
      },

      // digest authentication
      digest: function(realm, nonce_gen=null) {
        nonce_gen = nonce_gen || (() => md5((new Date()).getTime()));
        return function(request, response, next) {
          var nonce = nonce_gen(request);
          response.status(code).set({
            'WWW-Authenticate': 'Digest realm="'+realm+'", nonce="'+nonce+'"'
          });
          next({...error, realm, nonce});
        };
      }
    }
  }
  else {
    return function(request, response, next) {
      response.status(code);
      next(error);
    }
  }
}

/* ****************************************************************************
**
** Error rendering middleware
**
** ***************************************************************************/

function render_401_basic(error, request ,response, next) {
  if ( error && error.code == 401 && !error.nonce ) {
    response.render( 'error.html', {
      bgcolor: '#066',
      code: "401 : Authorization Required",
      msg:"Ce document est protégé par mot de passe"
    });
  }
  else next(error);
};
function render_401_digest(error, request, response, next) {
  // console.log('hello from render_401_digest',error);
  if ( error && error.code == 401 && error.nonce ) {
    response.render( 'error.html', {
      bgcolor: '#060',
      code: "401 : Authorization Required",
      msg: error.message || "Ce document est protégé par mot de passe"
    });
  }
  else next(error);
}
function render_unknown_user(error, request, response, next) {
  // console.log('hello from render_unknown_user',error);
  if ( error && error.code == 401 && error.message == 'unknown user') {
    response.render( 'error.html', {
      bgcolor: '#060',
      code: "401 : Authorization Required",
      msg: "L'utilisateur "+request.auth_info.username+" est inconnu de nos services"
    });
  }
  else next(error);
}
function render_wrong_password(error, request, response, next) {
  // console.log('hello from render_wrong_password',error);
  if ( error && error.code == 401 && error.message == 'wrong password' ) {
    response.render( 'error.html', {
      bgcolor: '#060',
      code: "401 : Authorization Required",
      msg: "Mot de passe erroné"
    });
  }
  else next(error);
}
function render_unallowed_realm(error, request, response, next) {
  // console.log('hello from render_unallowed_realm',error);
  if ( error && error.code == 401 && error.message == 'realm not allowed' ) {
    response.render( 'error.html', {
      bgcolor: '#060',
      code: "401 : Authorization Required",
      msg: "Zone interdite"
    });
  }
  else next(error);
}


/* ****************************************************************************
**
** Main program
**
** ***************************************************************************/

let port = process.env.PORT || 8088;
app.listen(port);
console.log("listening on port "+port);
