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
var jsonViewer       = new JSONViewer();
var viewerJSON       = document.querySelector("#json").appendChild(jsonViewer.getContainer());
var accessToken      = '';
var userName         = ''
var isSignedIn       = false;
btnSignin.disabled = false

// Initialize button status
var initButtons = function() {
  btnSignin.disabled = false
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *                1. Event Handler for testing NGINX Plus OIDC                 *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Event Handler: for when clicking a 'Sign in' button.
var eventHandlerSignIn = function (evt) {
  if (evt && evt.type === 'keypress' && evt.keyCode !== 13) {
    return;
  }
  location.href = window.location.origin + '/signin';
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *         2. Common Functions for testing OIDC Workflows via Sample UI        *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// [WIP] Sign in by clicking 'Sign In' button of the UI via the endpoint of /login
var doLogin = function(evt) {
  var headers = {'Access-Control-Allow-Origin': '*'};
  const url = window.location.origin + '/signin';

  showMessage('Start signing in...');
  fetch(url, {
      method : 'GET',
      mode   : 'no-cors',
      headers: headers
  })
  .then((response) => {
    showMessage('Response from signin: ' + response.status)
    showMessageDetail('{ "message": "' + response.status + ',' + response.ok + ',' + response.statusText + '"}');
    if (!response.ok) {
      showMessageDetail('{ "message-error": "' + response.status + ',' + response.ok + ',' + response.statusText + '"}');
      //throw new Error(response.error)
      return;
    }
    showUserInfo(evt);
    enableButtonsBySigningIn()
    // showSignOutBtn();
  })
  .catch(function(error) {
    // disableButtonsBySigningOut()
    // showSignInBtn();
    // showMessage(error);
  });
}

var doSignIn = function(evt) {
  // var headers = {'Access-Control-Allow-Origin': '*'};
  const url = window.location.origin + '/signin';
  location.href = url;
  // location.replace(window.location.origin + '/signin');


  // fetch(url, {
  //   method : 'GET',
  //   mode   : 'no-cors',
  //   headers: headers
  // })
  // .then(function(response) {
  //     // When the page is loaded convert it to text
  //     // msg = 'url: ' + response.url + " text: " + response.text() +
  //     //       'status: ' + response.statusText + ' code: ' + response.status;
  //     // showMessage(msg)
  //     return response.text()
  // })
  // .then(function(html) {
  //     // Initialize the DOM parser
  //     var parser = new DOMParser();

  //     // Parse the text
  //     var doc = parser.parseFromString(html, "text/html");
  //     var e=document.getElementById("wrap");
      
  //     var msg = 'doc: ' + doc + ' wrap: ' + e;
  //     showMessage(msg)

  //     // You can now even select part of that html as you would in the regular DOM 
  //     // Example:
  //     // var docArticle = doc.querySelector('article').innerHTML;
  //     // showMessage(doc)
  //     console.log(doc);
  // })
  // .catch(function(err) {  
  //     console.log('Failed to fetch page: ', err);  
  // });
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

// Enable buttons after signing in
var enableButtonsBySigningIn = function() {
  showSignOutBtn()
};

// Disable buttons after signing out
var disableButtonsBySigningOut = function() {
  showSignInBtn()
  initButtons()
};

// Add event lister of each button for testing NGINX Plus OIDC integration.
btnSignin       .addEventListener('click', eventHandlerSignIn);
