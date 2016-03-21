require('babel-register');

const fs       = require('fs');
const path     = require('path');
const bmcHapi  = require('../lib');
const protocol = 'https';

const conf = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../conf.json'), 'utf-8'));

// Login
bmcHapi.login(conf.protocol, conf.ip, conf.account, conf.password, (err, cc, cookie, token) => {

  console.log('Login: ' + cc + ', ' + cookie + ', ' + token);

  // Get role
  bmcHapi.getRole(conf.protocol, conf.ip, cookie, token, (err, cc, userName, userPriv) => {
    console.log('Get Role: ' + cc + ', ' + userName + ', ' + userPriv);
  });

  // Get BMC FW Information
  bmcHapi.getBmcFwInfo(conf.protocol, conf.ip, cookie, token, (err, cc, version, buildTime) => {
    console.log('Get BMC FW Info: ' + cc + ', ' + version + ', ' + buildTime);
  });

  // Get BIOS FW Information
  bmcHapi.getBiosFwInfo(conf.protocol, conf.ip, cookie, token, (err, cc, version) => {
    console.log('Get BIOS FW Info: ' + cc + ', ' + version);
  });

  // Logout
  bmcHapi.logout(conf.protocol, conf.ip, cookie, token, (err, cc) => {
    console.log('Logout: ' + cc);
  });
});

