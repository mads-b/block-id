var uri = window.location.href.split('/');
var redirectUri = window.location.href.split('?')[0];
var baseUri = uri[0] + '//' + uri[2];
var clientId = "184a9125-951b-4160-a81d-cfba7390ae5c";
var clientSecret = "ad7b77f9-1d7a-4687-9cb8-0b514f0d3671";
var state = Math.random().toString(36);
var authorizeUri = "https://dev01.signicat.com/oidc/authorize";
var tokenUri = "https://dev01.signicat.com/oidc/token";
var userinfoUri = "https://dev01.signicat.com/oidc/userinfo";

// Fetches a query parameter given its name
function getParameterByName(name, url) {
  if (!url) {
    url = window.location.href;
  }
  name = name.replace(/[\[\]]/g, "\\$&");
  var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)"),
      results = regex.exec(url);
  if (!results) return null;
  if (!results[2]) return '';
  return decodeURIComponent(results[2].replace(/\+/g, " "));
}

function hiddenInput(key, value) {
  return "<input type='hidden' name='" + key + "' value='" + value + "'>";
}

// Redirects the browser to the Signicat-proxied ID method of choice
function doAuth(scope, method, t, mt) {
    var acr = "urn:signicat:oidc:method:" + method;
    var params = {
      "response_type": "code",
      "redirect_uri": redirectUri,
      "client_id": clientId,
      "scope": scope,
      "state": state,
      "acr_values": acr};

    if (t) {
      params["claims"] = JSON.stringify({
        "userinfo": {
            "t": {"value": t},
            "mt": {"value": mt}
            }
        });
    }
    window.sessionStorage.setItem('state', state);
    var form = "<form action='" + authorizeUri + "' method='POST'>";
    for (key in params) {
      form += hiddenInput(key, params[key]);
    }
    form += '</form>';
    console.log(form);
    $(form).appendTo($(document.body)).submit();
}

function getToken(code, callback) {
  var authorizationString = "Basic " + btoa(clientId + ":" + clientSecret);
  var tokenParams = {
    "grant_type": "authorization_code",
    "code": code,
    "redirect_uri": redirectUri};
  $.ajax({
    type: "POST",
    url: tokenUri,
    headers: { "Authorization": authorizationString},
    data: tokenParams,
    accept: 'application/json',
    async: true,
    success: callback,
    error: function(jqXHR, textStatus, errorThrown) {
        alert("Whoops! " + textStatus + ": " +  errorThrown);
    }
  });
};

function getUserInfo(accessToken, callback) {
  $.ajax({
    type: "GET",
    url: userinfoUri,
    headers: { "Authorization": "Bearer " + accessToken},
    dataType: 'text',
    async: true,
    success: callback,
    error: function(jqXHR, textStatus, errorThrown) {
        alert("Whoops! " + textStatus + ": " +  errorThrown);
    }
  });
}