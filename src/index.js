import request from 'request';
import { inspect } from 'util';
import vm from 'vm';
import fs from 'fs';
import path from 'path';

module.exports = {
  login, logout, getRole, getBmcFwInfo, getBiosFwInfo, getSslCert,
  uploadSslCert, uploadSslKey, validateSsl, restartHttps,
};

function login(protocol, ip, account, password) {
  return new Promise((resolve, reject) => {
    const url     = protocol + '://' + ip + "/rpc/WEBSES/create.asp";
    const body    = 'WEBVAR_USERNAME=' + account + "&WEBVAR_PASSWORD=" + password;
    const options = {
      url,
      rejectUnauthorized: false,
      requestCert: true,
      agent: false,
      method: 'POST',
      port: 443,
      body
    };

    request(options, (err, res, body) => {

      body = vm.runInThisContext(body);
      if (err || res.statusCode != 200) {
        reject(err);
        return;
      }

      let sessionCookie = 'SessionCookie=' + body.WEBVAR_STRUCTNAME_WEB_SESSION[0].SESSION_COOKIE;
      let csrfToken = body.WEBVAR_STRUCTNAME_WEB_SESSION[0].CSRFTOKEN;
      resolve({
        cc: body.HAPI_STATUS,
        cookie: sessionCookie,
        token: csrfToken
      });
    });
  });
}

function logout(protocol, ip, cookie, token) {
  return new Promise((resolve, reject) => {
    const url     = protocol + '://' + ip + "/rpc/WEBSES/logout.asp";
    const options = {
      url,
      rejectUnauthorized: false,
      requestCert: true,
      agent: false,
      method: 'GET',
      port: 443,
      headers: {
        CSRFTOKEN: token,
        Cookie: cookie
      }
    };

    request(options, (err, res, body) => {

      body = vm.runInThisContext(body);
      if (err || res.statusCode != 200) {
        reject(err);
        return;
      }

      resolve(body.HAPI_STATUS);
    });
  });
}

function getRole(protocol, ip, cookie, token) {
  return new Promise((resolve, reject) => {
    const url     = protocol + '://' + ip + "/rpc/getrole.asp";
    const options = {
      url,
      rejectUnauthorized: false,
      requestCert: true,
      agent: false,
      method: 'GET',
      port: 443,
      headers: {
        CSRFTOKEN: token,
        Cookie: cookie
      }
    };

    request(options, (err, res, body) => {

      body = vm.runInThisContext(body);
      if (err || res.statusCode != 200) {
        reject(err);
        return;
      }

      let userName = body.WEBVAR_STRUCTNAME_GET_ROLE[0].CURUSERNAME;
      let userPriv = body.WEBVAR_STRUCTNAME_GET_ROLE[0].CURPRIV; // callback: 1, user: 2, oper: 3, admin: 4, oem: 5

      resolve({
        cc: body.HAPI_STATUS,
        userName,
        userPriv
      });
    });
  });
}

function getBmcFwInfo(protocol, ip, cookie, token) {
  return new Promise((resolve, reject) => {
    const url     = protocol + '://' + ip + "/rpc/getfwinfo.asp";
    const options = {
      url,
      rejectUnauthorized: false,
      requestCert: true,
      agent: false,
      method: 'GET',
      port: 443,
      headers: {
        CSRFTOKEN: token,
        Cookie: cookie
      }
    };

    request(options, (err, res, body) => {

      body = vm.runInThisContext(body);
      if (err || res.statusCode != 200) {
        reject(err);
        return;
      }

      let majorVer = body.WEBVAR_STRUCTNAME_GETFWINFO[0].FirmwareRevision1;
      let minorVer = (body.WEBVAR_STRUCTNAME_GETFWINFO[0].FirmwareRevision2 < 0x10) ?
        (0 + body.WEBVAR_STRUCTNAME_GETFWINFO[0].FirmwareRevision2.toString(16)) :
        (body.WEBVAR_STRUCTNAME_GETFWINFO[0].FirmwareRevision2.toString(16));
      let version  = majorVer + '.' + minorVer;

      let buildTime = body.WEBVAR_STRUCTNAME_GETFWINFO[0].FirmwareBuildDate +
        ' ' + body.WEBVAR_STRUCTNAME_GETFWINFO[0].FirmwareBuildTime;

      resolve({
        cc: body.HAPI_STATUS,
        version,
        buildTime
      });
    });
  });
}

function getBiosFwInfo(protocol, ip, cookie, token) {
  return new Promise((resolve, reject) => {
    const url     = protocol + '://' + ip + "/rpc/getbiosver.asp";
    const options = {
      url,
      rejectUnauthorized: false,
      requestCert: true,
      agent: false,
      method: 'GET',
      port: 443,
      headers: {
        CSRFTOKEN: token,
        Cookie: cookie
      }
    };

    request(options, (err, res, body) => {

      body = vm.runInThisContext(body);
      if (err || res.statusCode != 200) {
        reject(err);
        return;
      }

      let version = body.WEBVAR_STRUCTNAME_GETBIOSVER[0].Version;

      resolve({
        cc: body.HAPI_STATUS,
        version
      });
    });
  });
}

function getSslCert(protocol, ip, cookie, token) {
  return new Promise((resolve, reject) => {
    const url     = protocol + '://' + ip + "/rpc/viewssl.asp";
    const options = {
      url,
      rejectUnauthorized: false,
      requestCert: true,
      agent: false,
      method: 'GET',
      port: 443,
      headers: {
        CSRFTOKEN: token,
        Cookie: cookie
      }
    };

    request(options, (err, res, body) => {

      body = vm.runInThisContext(body);
      if (err || res.statusCode != 200) {
        reject(err);
        return;
      }

      resolve({
        cc: body.HAPI_STATUS,
        certInfo: body.WEBVAR_STRUCTNAME_VIEWSSLCERT[0]
      });
    });
  });
}

function uploadSslCert(protocol, ip, cookie, token, newCert) {
  return new Promise((resolve, reject) => {
    const url = protocol + '://' + ip + "/page/file_upload.html?SOURCE=SSL_CertFile";
    const options = {
      url,
      rejectUnauthorized: false,
      requestCert: true,
      agent: false,
      method: 'POST',
      port: 443,
      formData: {
        '/tmp/actualcert.pem': fs.createReadStream(newCert),
      },
      headers: {
        CSRFTOKEN: token,
        Cookie: cookie
      }
    };

    request(options, (err, res, body) => {

      if (err || res.statusCode != 200) {
        reject(err);
        return;
      }

      resolve(res.statusCode);
    });
  });
}

function uploadSslKey(protocol, ip, cookie, token, newKey) {
  return new Promise((resolve, reject) => {
    const url  = protocol + '://' + ip + "/page/file_upload.html?SOURCE=SSL_PrivKey";
    const options = {
      url,
      rejectUnauthorized: false,
      requestCert: true,
      agent: false,
      method: 'POST',
      port: 443,
      formData: {
        '/tmp/actualprivkey.pem': fs.createReadStream(newKey),
      },
      headers: {
        CSRFTOKEN: token,
        Cookie: cookie
      }
    };

    request(options, (err, res, body) => {

      if (err || res.statusCode != 200) {
        reject(err);
        return;
      }

      resolve(res.statusCode);
    });
  });
}

function validateSsl(protocol, ip, cookie, token) {
  return new Promise((resolve, reject) => {
    const url     = protocol + '://' + ip + "/rpc/validatesslcert.asp";
    const options = {
      url,
      rejectUnauthorized: false,
      requestCert: true,
      agent: false,
      method: 'GET',
      port: 443,
      headers: {
        CSRFTOKEN: token,
        Cookie: cookie
      }
    };

    request(options, (err, res, body) => {

      if (err || res.statusCode != 200) {
        reject(err);
        return;
      }

      resolve(res.statusCode);
    });
  });
}

function restartHttps(protocol, ip, cookie, token) {
  return new Promise((resolve, reject) => {
    const url     = protocol + '://' + ip + "/rpc/restarthttps.asp";
    const options = {
      url,
      rejectUnauthorized: false,
      requestCert: true,
      agent: false,
      method: 'GET',
      port: 443,
      headers: {
        CSRFTOKEN: token,
        Cookie: cookie
      }
    };

    request(options, (err, res, body) => {

      if (err || res.statusCode != 200) {
        reject(err);
        return;
      }

      resolve(res.statusCode);
    });
  });
}
