/**
 * JavaScript functions for providing OpenID Connect with NGINX Plus
 * 
 * Copyright (C) 2021 Nginx, Inc.
 */

// Constants for common error message.
var isSignedIn       = false;
var TITLE_SIGNIN     = 'Sign in';
var TITLE_SIGNOUT    = 'Sign out';
var MSG_SIGNINIG_IN  = 'Signinig in';
var MSG_SIGNED_IN    = 'Signed in';
var MSG_SIGNED_OUT   = 'Signed out';
var MSG_EMPTY_JSON   = '{"message": "N/A"}';
var btnSignin        = document.getElementById('signin');
var btnIdToken       = document.getElementById('id-token');
var btnAcToken       = document.getElementById('ac-token');
var btnCookie        = document.getElementById('cookie');
var btnAPIWithCookie = document.getElementById('api-with-cookie');
var btnAPIWithBearer = document.getElementById('api-with-bearer');
var btnUserInfo      = document.getElementById('user-info');
var jsonViewer       = new JSONViewer();
var viewerJSON       = document.querySelector("#json").appendChild(jsonViewer.getContainer());
var accessToken      = '';
var userName         = ''
btnSignin.disabled   = true

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *                1. Event Handler for testing NGINX Plus OIDC                 *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// [WIP] Event Handler: for when clicking a 'Sign in' button.
var eventHandlerSignIn = function (evt) {
  if (evt && evt.type === 'keypress' && evt.keyCode !== 13) {
    return;
  }
  if (!isSignedIn) {
    doSignIn(evt)
  } else {
    showSignInBtn()
  }
};

// Event Handler: for when clicking a button 'Get ID Token'.
var eventHandlerIdToken = function (evt) {
  var headers = {};
  doAPIRequest(
    evt,
    '/id_token', 
    'getting ID token from K/V store...',
    'ID token: received',
    headers
  )
};

// Event Handler: for when clicking a 'Get Access Token' button.
var eventHandlerAccessToken = function (evt) {
  var headers = {};
  doAPIRequest(
    evt,
    '/access_token',
    'getting access token from K/V store...',
    'access token: received',
    headers
  );
};

// Event Handler: for when clicking a 'Get Cookie' button.
var eventHandlerCookie = function (evt) {
  var headers = {};
  doAPIRequest(
    evt,
    '/cookie', 
    'getting cookie...',
    'cookie: acquired',
    headers
  )
};

// Event Handler: for when clicking a 'Backend API w/ Cookie + Bearer' button.
// - /v1/api/2: cookie is used. The bearer access token is also passed to the 
//              backend API via `proxy_set_header Authorization` directive.
var eventHandlerProxiedAPIWithCookie = function (evt) {
  var headers = {};
  doAPIRequest(
    evt,
    '/v1/api/2', 
    'calling a proxied API w/ cookie + bearer...',
    'passed bearer to proxied API w/ cookie',
    headers
  )
};

// Event Handler: for when clicking a 'Backend API w/ Bearer w/o Cookie' button.
// - /v1/api/3: cookie isn't used. The bearer token is only used.
var eventHandlerProxiedAPIWithBearer = function (evt) {
  if (!accessToken) {
    showMessage('Get access token first!');
    clearMessage();
    return;
  }
  var headers = {
    'Accept'       : 'application/json',
    'Content-Type' : 'application/json',
    'Authorization': 'Bearer ' + accessToken
  }
  doAPIRequest(
    evt,
    '/v1/api/3', 
    'calling a proxied API w/ bearer...',
    'passed bearer to proxied API w/o cookie',
    headers
  );
};

// Event Handler: for when clicking a 'Get User Info' button.
var eventHandlerUserInfo = function (evt) {
  showUserInfo(evt)
};


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *         2. Common Functions for testing OIDC Workflows via Sample UI        *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// [WIP] Sign in by clicking 'Sign In' button of the UI via the endpoint of /login
var doSignIn = function(evt) {
  var headers = {};
  const url = window.location.origin + '/login';

  showMessage('Start signing in...');
  fetch(url, {
      method : 'GET',
      mode   : 'cors',
      headers: headers
  })
  .then((response) => {
      if (!response.ok) {
        throw new Error(response.error)
      }
      showUserInfo(evt);
      showSignOutBtn();
  })
  .catch(function(error) {
    showSignInBtn();
    showMessage(error);
  });
}

// Request an API with application/json type response.
var doAPIRequest = function(evt, uri, msgBefore, msgAfter, headers) {
  if (evt && evt.type === 'keypress' && evt.keyCode !== 13) {
    return false;
  }
  showMessage(msgBefore)
  const url = window.location.origin + uri;
  fetch(url, {
      method : 'GET',
      mode   : 'cors',
      headers: headers
  })
  .then((response) => {
    showResponseStatus(response.status, response.statusText, url)
    showMessageDetail(MSG_EMPTY_JSON)
    if (!response.ok) {
      throw new Error(response.error)
    }
    return response.json();
  })
  .then((data) => {
    showMessage(msgAfter)
    showMessageDetail(JSON.stringify(data))
    if (data.username) {
      userName = data.username;
      showMessage(userName)
    } else if (data.name) {
      userName = data.name;
      showMessage(userName)
    } else if (data.email) {
      userName = data.email;
      showMessage(userName)
    } else if (data.token && uri == '/access_token') {
      accessToken = data.token;
    }
  })
  .catch(function(error) {
    showMessage(error);
    showMessageDetail(MSG_EMPTY_JSON)
  });
  return true;
}

// Show user information in the UI via the endpoint of /userinfo
var showUserInfo = function(evt) {
  var headers = {};
  doAPIRequest(
    evt,
    '/userinfo', 
    'getting user info from IdP...',
    'user info: received from IdP',
    headers
  );
}

// Display summarized message for each testing.
var showMessage = function (msg) {
  document.getElementById('message').value = msg;
};

// Display response status & message for each testing.
var showResponseStatus = function (status, msg, uri) {
  document.querySelector('pre').textContent = uri + ', ' + status + ', ' + msg;
};

// Clear message window
var clearMessage = function() {
  document.querySelector('pre').textContent = '';
  showMessageDetail(MSG_EMPTY_JSON);
};

// Display detail message for each testing.
var showMessageDetail = function (msg) {
  var setJSON = function() {
    try {
      jsonObj = JSON.parse(msg);
    }
    catch (err) {
      alert(err);
    }
  };
  setJSON();
  jsonViewer.showJSON(jsonObj);
  var res = jsonObj;
  return res
}

// Display a button title for toggling between 'Sign in' and 'Sign out'.
var showLoginBtnTitle = function (msg) {
  btnSignin.innerText = msg
};

// Display 'Sign In' button when signed-out or occurs error during signing-in.
var showSignInBtn = function () {
  isSignedIn = false;
  showLoginBtnTitle(TITLE_SIGNIN);
  showMessage(MSG_SIGNED_OUT);
};

// Display 'Sign Out' button when signed-in.
var showSignOutBtn = function () {
  isSignedIn = true;
  showLoginBtnTitle(TITLE_SIGNOUT);
  showMessage(MSG_SIGNED_IN);
};

// Add event lister of each button for testing NGINX Plus OIDC integration.
btnSignin       .addEventListener('click', eventHandlerSignIn);
btnIdToken      .addEventListener('click', eventHandlerIdToken);
btnAcToken      .addEventListener('click', eventHandlerAccessToken);
btnCookie       .addEventListener('click', eventHandlerCookie);
btnAPIWithCookie.addEventListener('click', eventHandlerProxiedAPIWithCookie);
btnAPIWithBearer.addEventListener('click', eventHandlerProxiedAPIWithBearer);
btnUserInfo     .addEventListener('click', eventHandlerUserInfo);