<?php
// Deliberately vulnerable PHP code for testing

// SQL Injection
$name = $_GET['name'];
mysql_query("SELECT * FROM users WHERE name = '$name'");
$result = $conn->query("SELECT * FROM users WHERE id = $id");

// Command Injection
$cmd = $_POST['cmd'];
system($cmd);
exec($cmd);
passthru($cmd);
$output = shell_exec($cmd);

// Code Injection
eval($code);

// XSS
echo $_GET['input'];
print $_POST['data'];

// File Inclusion (LFI)
$page = $_GET['page'];
include($page);
require($page);

// Deserialization
unserialize($data);

// Weak Hash
$hash = md5($password);
$hash2 = sha1($data);

// Hardcoded Credentials
$password = "SuperSecret123";
$db_pass = "admin123";

// File Upload
move_uploaded_file($_FILES['file']['tmp_name'], $target);

// SSRF
$content = file_get_contents($url);

// Display Errors
ini_set('display_errors', 1);

// Weak Random
$token = rand(0, 999999);
$code = mt_rand(100000, 999999);
?>
