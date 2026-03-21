// Deliberately vulnerable JavaScript code for testing the scanner

// SQL Injection
app.get('/user', (req, res) => {
    db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
});

// Command Injection
const { exec } = require('child_process');
exec(`ls ${userInput}`);

// XSS
document.getElementById('output').innerHTML = userInput;
document.write(unsafeData);

// Eval
eval(userInput);
new Function(userInput);
setTimeout("alert('xss')", 100);

// Hardcoded Credentials
const password = "SuperSecret123!";
const apiKey = "sk-1234567890abcdefghijklmnop";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

// JWT
jwt.sign(payload, "my-secret-key-hardcoded");

// TLS Disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// Weak Crypto
const hash = crypto.createHash('md5').update(data).digest('hex');

// CORS Wildcard
res.setHeader('Access-Control-Allow-Origin', '*');

// Prototype Pollution
const merged = Object.assign({}, userInput);

// Path Traversal
fs.readFile(req.params.filename, callback);

// React XSS
<div dangerouslySetInnerHTML={{__html: userInput}} />

// Debugger
debugger;

// Console
console.log("debug info: " + password);

// Math.random for security
const token = Math.random().toString(36);

// Private Key
const key = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn
-----END RSA PRIVATE KEY-----`;
