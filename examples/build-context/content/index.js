/**
 * JavaScript functions for providing OpenID Connect with NGINX Plus
 * 
 * Copyright (C) 2021 Nginx, Inc.
 */

// Constants for common error message.
var btnLogin = document.getElementById('login');


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *               1. Event Handler for testing NGINX Plus OIDC                  *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Event Handler: for when clicking a 'Login' button.
var eventHandlerLogIn = function (evt) {
  if (evt && evt.type === 'keypress' && evt.keyCode !== 13) {
    return;
  }
  location.href = window.location.origin + '/login';
};


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *         2. Common Functions for testing OIDC Workflows via Sample UI        *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Add event lister of each button for testing NGINX Plus OIDC integration.
btnLogin.addEventListener('click', eventHandlerLogIn);

