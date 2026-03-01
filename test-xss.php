<?php
// Test XSS vulnerability
$html = '<pre>Hello ' . $_GET['name'] . '</pre>';
echo $html;
?>
